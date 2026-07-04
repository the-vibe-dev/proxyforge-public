// Reverse listener: binds a local port and forwards all incoming HTTP/HTTPS
// traffic to a configured upstream origin, relaying responses back to the client.
// Useful for intercepting traffic destined for a specific host.

import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { EventEmitter } from 'node:events';

export interface ReverseModeConfig {
  listenPort: number;
  listenHost?: string;
  targetHost: string;
  targetPort: number;
  targetScheme?: 'http' | 'https';
  upstreamTlsMode?: 'strict' | 'relaxed';
}

export type PersistFn = (config: ReverseModeConfig) => void | Promise<void>;

export interface ReverseRequestLog {
  id: string;
  method: string;
  path: string;
  statusCode: number;
  targetHost: string;
  targetPort: number;
  durationMs: number;
  timestamp: string;
}

export class ReverseServer extends EventEmitter {
  private server: http.Server | null = null;
  private config: ReverseModeConfig | null = null;
  private persistFn: PersistFn | null = null;

  start(config: ReverseModeConfig, persistFn?: PersistFn): Promise<void> {
    this.config = config;
    this.persistFn = persistFn ?? null;

    if (persistFn) {
      try { void persistFn(config); } catch { /* non-fatal */ }
    }

    return new Promise((resolve, reject) => {
      this.server = http.createServer((req, res) => {
        this._handleRequest(req, res);
      });

      // Forward CONNECT tunnels (pass-through without interpretation)
      this.server.on('connect', (req, clientSocket, head) => {
        this._handleConnect(req, clientSocket as net.Socket, head);
      });

      this.server.once('error', reject);
      this.server.listen(config.listenPort, config.listenHost ?? '0.0.0.0', () => {
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
      this.config = null;
    });
  }

  address(): net.AddressInfo | null {
    return this.server ? (this.server.address() as net.AddressInfo) : null;
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Internal helpers
  // ──────────────────────────────────────────────────────────────────────────

  private _handleRequest(
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ): void {
    const cfg = this.config!;
    const start = Date.now();
    const id = `rev-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

    const isHttps = cfg.targetScheme === 'https';
    const transport = isHttps ? https : http;

    const outHeaders = { ...req.headers };
    // Rewrite the Host header to point at the target
    outHeaders['host'] = cfg.targetPort === (isHttps ? 443 : 80)
      ? cfg.targetHost
      : `${cfg.targetHost}:${cfg.targetPort}`;

    const options: http.RequestOptions = {
      hostname: cfg.targetHost,
      port: cfg.targetPort,
      method: req.method,
      path: req.url ?? '/',
      headers: outHeaders,
      ...(isHttps ? { rejectUnauthorized: cfg.upstreamTlsMode !== 'relaxed' } : {}),
    };

    const proxyReq = transport.request(options, (proxyRes) => {
      res.writeHead(proxyRes.statusCode ?? 502, proxyRes.headers);
      proxyRes.pipe(res, { end: true });

      proxyRes.on('end', () => {
        const log: ReverseRequestLog = {
          id,
          method: req.method ?? 'GET',
          path: req.url ?? '/',
          statusCode: proxyRes.statusCode ?? 0,
          targetHost: cfg.targetHost,
          targetPort: cfg.targetPort,
          durationMs: Date.now() - start,
          timestamp: new Date().toISOString(),
        };
        this.emit('request', log);
      });
    });

    proxyReq.on('error', (err) => {
      this.emit('proxy-error', { id, error: err.message });
      if (!res.headersSent) {
        res.writeHead(502, { 'Content-Type': 'text/plain' });
      }
      res.end(`ProxyForge reverse proxy error: ${err.message}`);
    });

    req.pipe(proxyReq, { end: true });
  }

  private _handleConnect(
    _req: http.IncomingMessage,
    clientSocket: net.Socket,
    head: Buffer,
  ): void {
    const cfg = this.config!;

    const upstream = net.connect(cfg.targetPort, cfg.targetHost, () => {
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head.length > 0) upstream.write(head);
      upstream.pipe(clientSocket);
      clientSocket.pipe(upstream);
    });

    upstream.on('error', (err) => {
      this.emit('proxy-error', { error: err.message });
      clientSocket.end(`HTTP/1.1 502 Bad Gateway\r\n\r\n`);
    });

    clientSocket.on('error', () => upstream.destroy());
    upstream.on('close', () => clientSocket.destroy());
    clientSocket.on('close', () => upstream.destroy());
  }
}
