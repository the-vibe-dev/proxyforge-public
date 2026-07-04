// SOCKS5 inbound proxy server — RFC 1928 / RFC 1929
// Handles greeting, auth negotiation, and CONNECT command, then forwards
// the established tunnel through the provided forwardFn.

import net from 'node:net';
import { EventEmitter } from 'node:events';

export interface SocksInboundConfig {
  port: number;
  host?: string;
  requireAuth?: boolean;
  username?: string;
  password?: string;
}

export type ForwardFn = (
  clientSocket: net.Socket,
  targetHost: string,
  targetPort: number,
) => void;

// Auth method constants (RFC 1928 §3)
const METHOD_NO_AUTH = 0x00;
const METHOD_USER_PASS = 0x02;
const METHOD_NO_ACCEPTABLE = 0xff;

// Reply codes (RFC 1928 §6)
const SOCKS5_VERSION = 0x05;
const CMD_CONNECT = 0x01;
const ATYP_IPV4 = 0x01;
const ATYP_DOMAIN = 0x03;
const ATYP_IPV6 = 0x04;
const REP_SUCCESS = 0x00;
const REP_COMMAND_NOT_SUPPORTED = 0x07;
const REP_ADDRESS_TYPE_NOT_SUPPORTED = 0x08;
const REP_HOST_UNREACHABLE = 0x04;
const REP_GENERAL_FAILURE = 0x01;

// User/password auth sub-negotiation version (RFC 1929)
const AUTH_VERSION = 0x01;
const AUTH_SUCCESS = 0x00;
const AUTH_FAILURE = 0x01;

export interface SocksConnectionInfo {
  clientIp: string;
  clientPort: number;
  targetHost: string;
  targetPort: number;
  authenticated: boolean;
}

export class SocksServer extends EventEmitter {
  private server: net.Server | null = null;
  private config: SocksInboundConfig | null = null;
  private forwardFn: ForwardFn | null = null;

  onConnection: ((info: SocksConnectionInfo) => void) | null = null;

  start(config: SocksInboundConfig, forwardFn?: ForwardFn): Promise<void> {
    this.config = config;
    this.forwardFn = forwardFn ?? this._defaultForward.bind(this);

    return new Promise((resolve, reject) => {
      this.server = net.createServer((socket) => {
        this._handleClient(socket);
      });

      this.server.once('error', reject);
      this.server.listen(config.port, config.host ?? '127.0.0.1', () => {
        this.server!.removeListener('error', reject);
        resolve();
      });
    });
  }

  stop(): Promise<void> {
    return new Promise((resolve) => {
      if (!this.server) { resolve(); return; }
      this.server.close(() => resolve());
      this.server = null;
    });
  }

  address(): net.AddressInfo | null {
    return this.server ? (this.server.address() as net.AddressInfo) : null;
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Internal: per-client state machine
  // ──────────────────────────────────────────────────────────────────────────

  private _handleClient(socket: net.Socket): void {
    const cfg = this.config!;
    let state: 'greeting' | 'auth' | 'request' | 'forwarding' = 'greeting';
    const chunks: Buffer[] = [];

    socket.on('error', () => { socket.destroy(); });

    socket.on('data', (chunk: Buffer) => {
      chunks.push(chunk);
      const buf = Buffer.concat(chunks);

      if (state === 'greeting') {
        // Need at least: VER(1) + NMETHODS(1) + METHODS(NMETHODS)
        if (buf.length < 2) return;
        const nmethods = buf[1];
        if (buf.length < 2 + nmethods) return;

        if (buf[0] !== SOCKS5_VERSION) {
          socket.destroy(); return;
        }

        const methods = Array.from(buf.slice(2, 2 + nmethods));
        chunks.length = 0;
        chunks.push(buf.slice(2 + nmethods)); // leftover

        const useAuth = cfg.requireAuth && cfg.username && cfg.password;
        if (useAuth) {
          if (methods.includes(METHOD_USER_PASS)) {
            socket.write(Buffer.from([SOCKS5_VERSION, METHOD_USER_PASS]));
            state = 'auth';
          } else {
            socket.write(Buffer.from([SOCKS5_VERSION, METHOD_NO_ACCEPTABLE]));
            socket.end();
          }
        } else {
          if (methods.includes(METHOD_NO_AUTH)) {
            socket.write(Buffer.from([SOCKS5_VERSION, METHOD_NO_AUTH]));
            state = 'request';
          } else if (methods.includes(METHOD_USER_PASS)) {
            // Accept user/pass but skip validation if auth not required
            socket.write(Buffer.from([SOCKS5_VERSION, METHOD_USER_PASS]));
            state = 'auth';
          } else {
            socket.write(Buffer.from([SOCKS5_VERSION, METHOD_NO_ACCEPTABLE]));
            socket.end();
          }
        }
        return;
      }

      if (state === 'auth') {
        const combined = Buffer.concat(chunks.slice(0, -1).concat([chunk]));
        // RFC 1929: VER(1) ULEN(1) UNAME(ULEN) PLEN(1) PASSWD(PLEN)
        if (combined.length < 3) return;
        const ulen = combined[1];
        if (combined.length < 3 + ulen) return;
        const plen = combined[2 + ulen];
        if (combined.length < 3 + ulen + plen) return;

        const uname = combined.slice(2, 2 + ulen).toString('utf8');
        const passwd = combined.slice(3 + ulen, 3 + ulen + plen).toString('utf8');
        const leftover = combined.slice(3 + ulen + plen);

        chunks.length = 0;
        chunks.push(leftover);

        const cfg2 = this.config!;
        const valid = !cfg2.requireAuth ||
          (uname === (cfg2.username ?? '') && passwd === (cfg2.password ?? ''));

        if (valid) {
          socket.write(Buffer.from([AUTH_VERSION, AUTH_SUCCESS]));
          state = 'request';
        } else {
          socket.write(Buffer.from([AUTH_VERSION, AUTH_FAILURE]));
          socket.end();
        }
        return;
      }

      if (state === 'request') {
        const combined = Buffer.concat(chunks.slice(0, -1).concat([chunk]));
        // VER(1) CMD(1) RSV(1) ATYP(1) ...
        if (combined.length < 4) return;

        if (combined[0] !== SOCKS5_VERSION) {
          socket.destroy(); return;
        }

        const cmd = combined[1];
        const atyp = combined[3];

        if (cmd !== CMD_CONNECT) {
          this._sendReply(socket, REP_COMMAND_NOT_SUPPORTED, '0.0.0.0', 0);
          socket.end(); return;
        }

        let targetHost: string;
        let targetPort: number;
        let consumed: number;

        if (atyp === ATYP_IPV4) {
          if (combined.length < 10) return;
          targetHost = Array.from(combined.slice(4, 8)).join('.');
          targetPort = combined.readUInt16BE(8);
          consumed = 10;
        } else if (atyp === ATYP_DOMAIN) {
          const domainLen = combined[4];
          if (combined.length < 5 + domainLen + 2) return;
          targetHost = combined.slice(5, 5 + domainLen).toString('utf8');
          targetPort = combined.readUInt16BE(5 + domainLen);
          consumed = 5 + domainLen + 2;
        } else if (atyp === ATYP_IPV6) {
          if (combined.length < 22) return;
          const ipv6Parts: string[] = [];
          for (let i = 0; i < 8; i++) {
            ipv6Parts.push(combined.readUInt16BE(4 + i * 2).toString(16));
          }
          targetHost = ipv6Parts.join(':');
          targetPort = combined.readUInt16BE(20);
          consumed = 22;
        } else {
          this._sendReply(socket, REP_ADDRESS_TYPE_NOT_SUPPORTED, '0.0.0.0', 0);
          socket.end(); return;
        }

        const leftover = combined.slice(consumed);
        chunks.length = 0;
        if (leftover.length > 0) chunks.push(leftover);

        state = 'forwarding';

        const info: SocksConnectionInfo = {
          clientIp: socket.remoteAddress ?? '?',
          clientPort: socket.remotePort ?? 0,
          targetHost,
          targetPort,
          authenticated: cfg.requireAuth ? true : false,
        };

        if (this.onConnection) {
          try { this.onConnection(info); } catch { /* ignore */ }
        }
        this.emit('connection', info);

        // Send success reply and hand off
        this._sendReply(socket, REP_SUCCESS, '0.0.0.0', 0);

        // Pause so forwardFn can attach its own data listeners
        socket.pause();

        try {
          this.forwardFn!(socket, targetHost, targetPort);
          // forwardFn is responsible for piping; resume so data can flow
          if (!socket.destroyed) socket.resume();
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : String(err);
          this.emit('forward-error', { info, error: msg });
          socket.destroy();
        }
      }
    });
  }

  private _sendReply(
    socket: net.Socket,
    rep: number,
    bindAddr: string,
    bindPort: number,
  ): void {
    const parts = bindAddr.split('.').map(Number);
    const addrBuf = parts.length === 4
      ? Buffer.from([ATYP_IPV4, ...parts])
      : Buffer.from([ATYP_IPV4, 0, 0, 0, 0]);
    const portBuf = Buffer.allocUnsafe(2);
    portBuf.writeUInt16BE(bindPort, 0);
    socket.write(Buffer.concat([
      Buffer.from([SOCKS5_VERSION, rep, 0x00]),
      addrBuf,
      portBuf,
    ]));
  }

  private _defaultForward(
    clientSocket: net.Socket,
    targetHost: string,
    targetPort: number,
  ): void {
    const upstream = net.connect(targetPort, targetHost, () => {
      clientSocket.pipe(upstream);
      upstream.pipe(clientSocket);
    });
    upstream.on('error', () => {
      clientSocket.destroy();
    });
    clientSocket.on('close', () => upstream.destroy());
  }
}
