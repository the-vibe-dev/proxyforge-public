// HTTP/2 transport — server + client session management using node:http2.

import * as http2 from 'node:http2';
import * as tls from 'node:tls';

export interface Http2TransportConfig {
  listenHost: string;
  listenPort: number;
  certPem?: string;
  keyPem?: string;
  alpnProtocols?: string[];
}

export interface Http2Frame {
  streamId: number;
  type:
    | 'HEADERS'
    | 'DATA'
    | 'RST_STREAM'
    | 'SETTINGS'
    | 'PUSH_PROMISE'
    | 'PING'
    | 'GOAWAY'
    | 'WINDOW_UPDATE'
    | 'CONTINUATION';
  flags: number;
  payload: Buffer;
}

/**
 * Strips HTTP/2 pseudo-headers (:method, :path, :scheme, :authority) and
 * normalises the remaining headers into a plain string→string map.
 */
export function parseHttp2Headers(
  headers: http2.IncomingHttpHeaders,
): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (key.startsWith(':')) continue; // drop pseudo-headers
    if (value === undefined) continue;
    if (Array.isArray(value)) {
      result[key] = value.join(', ');
    } else {
      result[key] = String(value);
    }
  }
  return result;
}

/**
 * Builds an OutgoingHttpHeaders object that includes the four required
 * HTTP/2 pseudo-headers plus any caller-supplied regular headers.
 */
export function buildHttp2Headers(
  method: string,
  path: string,
  host: string,
  headers: Record<string, string>,
): http2.OutgoingHttpHeaders {
  const out: http2.OutgoingHttpHeaders = {
    ':method': method.toUpperCase(),
    ':path': path,
    ':scheme': 'https',
    ':authority': host,
  };
  for (const [key, value] of Object.entries(headers)) {
    if (!key.startsWith(':')) {
      out[key] = value;
    }
  }
  return out;
}

/**
 * Thin wrapper around a ClientHttp2Session that exposes a promise-based
 * request/response API.
 */
export class Http2Connection {
  private readonly session: http2.ClientHttp2Session;

  constructor(session: http2.ClientHttp2Session) {
    this.session = session;
  }

  sendRequest(
    headers: http2.OutgoingHttpHeaders,
    body?: Buffer,
  ): Promise<{ status: number; headers: Record<string, string>; body: Buffer }> {
    return new Promise((resolve, reject) => {
      const req = this.session.request(headers);

      req.on('error', reject);

      req.on('response', (responseHeaders) => {
        const status = Number(responseHeaders[':status'] ?? 0);
        const responseHeadersNorm: Record<string, string> = {};
        for (const [key, value] of Object.entries(responseHeaders)) {
          if (key.startsWith(':')) continue;
          if (value === undefined) continue;
          responseHeadersNorm[key] = Array.isArray(value)
            ? value.join(', ')
            : String(value);
        }

        const chunks: Buffer[] = [];
        req.on('data', (chunk: Buffer) => chunks.push(chunk));
        req.on('end', () => {
          resolve({
            status,
            headers: responseHeadersNorm,
            body: Buffer.concat(chunks),
          });
        });
        req.on('error', reject);
      });

      if (body && body.length > 0) {
        req.write(body);
      }
      req.end();
    });
  }

  close(): void {
    this.session.close();
  }
}

/**
 * Opens an HTTP/2 client connection to the given host:port.
 * Pass tls=true for h2 (TLS), tls=false for h2c (cleartext).
 */
export function createHttp2Connection(
  host: string,
  port: number,
  useTls: boolean = true,
  options: { rejectUnauthorized?: boolean } = {},
): Http2Connection {
  const authority = `${useTls ? 'https' : 'http'}://${host}:${port}`;
  const sessionOptions: http2.ClientSessionOptions &
    tls.ConnectionOptions = useTls
    ? { rejectUnauthorized: options.rejectUnauthorized !== false }
    : {};
  const session = http2.connect(authority, sessionOptions);
  return new Http2Connection(session);
}
