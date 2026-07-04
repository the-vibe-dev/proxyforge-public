// Callback provider registry — manages active OAST callback listeners.
// Tracks received interactions and correlates them to OAST tokens.
// No external dependencies beyond Node.js builtins.

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { createSocket, type Socket as UdpSocket } from 'node:dgram';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface OastInteraction {
  id: string;
  token: string;
  projectId?: string;
  type: 'http' | 'dns' | 'smtp';
  sourceIp?: string;
  requestData?: string;
  receivedAt: string;
}

export interface HttpListenerConfig {
  port: number;
  host?: string;
}

export interface DnsListenerConfig {
  port: number;
  host?: string;
}

export interface CallbackListenerState {
  httpRunning: boolean;
  dnsRunning: boolean;
  httpPort?: number;
  dnsPort?: number;
  interactionCount: number;
}

// ---------------------------------------------------------------------------
// In-memory interaction store
// ---------------------------------------------------------------------------

const interactions: OastInteraction[] = [];
let httpServer: ReturnType<typeof createServer> | null = null;
let dnsServer: UdpSocket | null = null;

let interactionCounter = 0;

function generateInteractionId(): string {
  return `oast-${Date.now()}-${++interactionCounter}`;
}

function extractTokenFromPath(path: string): string {
  // Token is the first 32-hex-char segment of the hostname or path
  const match = path.match(/([0-9a-f]{32})/);
  return match?.[1] ?? '';
}

// ---------------------------------------------------------------------------
// HTTP callback listener
// ---------------------------------------------------------------------------

export function startHttpCallbackListener(config: HttpListenerConfig): Promise<void> {
  if (httpServer) return Promise.resolve();

  return new Promise((resolve, reject) => {
    httpServer = createServer((req: IncomingMessage, res: ServerResponse) => {
      const token = extractTokenFromPath(req.headers.host ?? req.url ?? '');
      const interaction: OastInteraction = {
        id: generateInteractionId(),
        token,
        type: 'http',
        sourceIp: req.socket?.remoteAddress,
        requestData: `${req.method} ${req.url}`,
        receivedAt: new Date().toISOString(),
      };
      interactions.push(interaction);
      res.writeHead(200);
      res.end();
    });

    httpServer.listen(config.port, config.host ?? '0.0.0.0', () => resolve());
    httpServer.on('error', reject);
  });
}

export function stopHttpCallbackListener(): Promise<void> {
  return new Promise((resolve) => {
    if (!httpServer) { resolve(); return; }
    httpServer.close(() => { httpServer = null; resolve(); });
  });
}

// ---------------------------------------------------------------------------
// DNS callback listener (UDP)
// ---------------------------------------------------------------------------

export function startDnsCallbackListener(config: DnsListenerConfig): Promise<void> {
  if (dnsServer) return Promise.resolve();

  return new Promise((resolve, reject) => {
    dnsServer = createSocket('udp4');
    dnsServer.on('message', (msg: Buffer, rinfo) => {
      const token = extractTokenFromPath(msg.toString('hex'));
      const interaction: OastInteraction = {
        id: generateInteractionId(),
        token,
        type: 'dns',
        sourceIp: rinfo.address,
        requestData: msg.toString('hex').slice(0, 128),
        receivedAt: new Date().toISOString(),
      };
      interactions.push(interaction);
    });
    dnsServer.bind(config.port, config.host ?? '0.0.0.0', () => resolve());
    dnsServer.on('error', reject);
  });
}

export function stopDnsCallbackListener(): void {
  if (dnsServer) { dnsServer.close(); dnsServer = null; }
}

// ---------------------------------------------------------------------------
// Interaction retrieval
// ---------------------------------------------------------------------------

export function getInteractionsForToken(token: string): OastInteraction[] {
  return interactions.filter((i) => i.token === token);
}

export function getAllInteractions(): OastInteraction[] {
  return [...interactions];
}

export function clearInteractions(): void {
  interactions.length = 0;
}

export function getListenerState(): CallbackListenerState {
  return {
    httpRunning: httpServer !== null,
    dnsRunning: dnsServer !== null,
    interactionCount: interactions.length,
  };
}
