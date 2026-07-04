import dgram from 'node:dgram';
import http from 'node:http';
import net from 'node:net';

export type CallbackProtocol = 'dns' | 'http' | 'smtp';
export type CallbackListenerMode = 'browser-preview' | 'local-http' | 'local-dns' | 'local-smtp' | 'hybrid-local';
export type CallbackListenerStatus = 'planned' | 'running' | 'stopped' | 'blocked';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface CallbackPayload {
  id: string;
  token: string;
  label: string;
  protocol: CallbackProtocol;
  endpoint: string;
  createdAt: string;
  status: 'waiting' | 'observed' | 'archived';
  sourceExchangeId?: string;
  sourceHost?: string;
  sourcePath?: string;
  lastInteractionAt?: string;
  notes: string;
}

export interface CallbackInteraction {
  id: string;
  payloadId: string;
  protocol: CallbackProtocol;
  observedAt: string;
  sourceIp: string;
  sourceHost: string;
  requestLine: string;
  userAgent: string;
  raw: string;
  severity: Severity;
  tags: string[];
}

export interface CallbackListenerProfile {
  id: string;
  name: string;
  createdAt: string;
  mode: CallbackListenerMode;
  status: CallbackListenerStatus;
  host: string;
  publicBaseUrl: string;
  protocols: CallbackProtocol[];
  httpPort: number;
  dnsPort: number;
  smtpPort: number;
  pollIntervalSeconds: number;
  retentionHours: number;
  signingKeyId: string;
  ciCommand: string;
  healthChecks: string[];
  summary: string;
  content: string;
}

export interface CallbackListenerRuntimeStatus {
  profileId: string;
  running: boolean;
  mode: CallbackListenerMode;
  host: string;
  protocols: CallbackProtocol[];
  ports: Partial<Record<CallbackProtocol, number>>;
  interactionCount: number;
  retentionHours?: number;
  retentionPrunedCount?: number;
  startedAt?: string;
  stoppedAt?: string;
  healthChecks: string[];
  message: string;
}

export interface CallbackListenerPollResult {
  status: CallbackListenerRuntimeStatus;
  interactions: CallbackInteraction[];
  newInteractionIds: string[];
}

interface CallbackListenerRuntime {
  profile: CallbackListenerProfile;
  payloads: CallbackPayload[];
  interactions: CallbackInteraction[];
  lastPollIndex: number;
  startedAt: string;
  ports: Partial<Record<CallbackProtocol, number>>;
  healthChecks: string[];
  retentionPrunedCount: number;
  httpServer?: http.Server;
  dnsSocket?: dgram.Socket;
  smtpServer?: net.Server;
}

const MAX_HTTP_CAPTURE_BYTES = 1024 * 1024;
const MAX_SMTP_TRANSCRIPT_BYTES = 1024 * 1024;
const MAX_DNS_NAME_BYTES = 253;

export interface CallbackInteractionSink {
  payloads?: (profile: CallbackListenerProfile, payloads: CallbackPayload[]) => void;
  interaction?: (profile: CallbackListenerProfile, interaction: CallbackInteraction) => void;
}

export class CallbackListenerService {
  private readonly runtimes = new Map<string, CallbackListenerRuntime>();

  constructor(private readonly sink?: CallbackInteractionSink) {}

  async start(profile: CallbackListenerProfile, payloads: CallbackPayload[] = []): Promise<CallbackListenerRuntimeStatus> {
    await this.stop(profile.id);
    if (!isLoopbackBindHost(profile.host)) {
      throw new Error('Callback listener host must be loopback. External binding requires a future explicit approval workflow.');
    }
    const protocols = protocolsForMode(profile);
    if (profile.mode === 'browser-preview') {
      return stoppedStatus(profile, 'Browser-preview callback polling stays in the renderer simulator.');
    }

    const runtime: CallbackListenerRuntime = {
      profile: { ...profile, protocols },
      payloads,
      interactions: [],
      lastPollIndex: 0,
      startedAt: new Date().toISOString(),
      ports: {},
      healthChecks: [],
      retentionPrunedCount: 0,
    };

    try {
      if (protocols.includes('http')) await this.startHttp(runtime);
      if (protocols.includes('dns')) await this.startDns(runtime);
      if (protocols.includes('smtp')) await this.startSmtp(runtime);
    } catch (error) {
      await closeRuntime(runtime);
      throw error;
    }

    this.runtimes.set(profile.id, runtime);
    this.sink?.payloads?.(runtime.profile, payloads);
    return this.statusFor(runtime, `${profile.name} is listening for ${protocols.join(', ')} callback interactions.`);
  }

  async stop(profileId: string): Promise<CallbackListenerRuntimeStatus> {
    const runtime = this.runtimes.get(profileId);
    if (!runtime) {
      return {
        profileId,
        running: false,
        mode: 'browser-preview',
        host: '127.0.0.1',
        protocols: [],
        ports: {},
        interactionCount: 0,
        stoppedAt: new Date().toISOString(),
        healthChecks: [],
        message: 'Callback listener is not running.',
      };
    }

    await closeRuntime(runtime);
    this.runtimes.delete(profileId);
    return {
      ...this.statusFor(runtime, `${runtime.profile.name} stopped.`),
      running: false,
      stoppedAt: new Date().toISOString(),
    };
  }

  async stopAll(): Promise<void> {
    await Promise.all(Array.from(this.runtimes.keys()).map((profileId) => this.stop(profileId)));
  }

  status(profileId: string): CallbackListenerRuntimeStatus {
    const runtime = this.runtimes.get(profileId);
    return runtime ? this.statusFor(runtime, `${runtime.profile.name} is running.`) : stoppedStatus({ id: profileId } as CallbackListenerProfile, 'Callback listener is not running.');
  }

  poll(profileId: string, payloads?: CallbackPayload[]): CallbackListenerPollResult {
    const runtime = this.runtimes.get(profileId);
    if (!runtime) {
      const status = stoppedStatus({ id: profileId } as CallbackListenerProfile, 'Callback listener is not running.');
      return { status, interactions: [], newInteractionIds: [] };
    }

    if (payloads) runtime.payloads = payloads;
    pruneExpiredInteractions(runtime);
    const newInteractions = runtime.interactions.slice(runtime.lastPollIndex);
    runtime.lastPollIndex = runtime.interactions.length;

    return {
      status: this.statusFor(runtime, newInteractions.length
        ? `Collected ${newInteractions.length} new callback interaction(s).`
        : 'No new callback interactions since the last poll.'),
      interactions: runtime.interactions,
      newInteractionIds: newInteractions.map((interaction) => interaction.id),
    };
  }

  private async startHttp(runtime: CallbackListenerRuntime): Promise<void> {
    const server = http.createServer((request, response) => {
      const chunks: Buffer[] = [];
      let totalBytes = 0;
      let truncated = false;
      request.on('data', (chunk: Buffer) => {
        totalBytes += chunk.byteLength;
        if (totalBytes <= MAX_HTTP_CAPTURE_BYTES) {
          chunks.push(chunk);
          return;
        }
        truncated = true;
        const remaining = Math.max(0, MAX_HTTP_CAPTURE_BYTES - (totalBytes - chunk.byteLength));
        if (remaining > 0) chunks.push(chunk.subarray(0, remaining));
      });
      request.on('end', () => {
        const body = Buffer.concat(chunks).toString('utf8');
        const raw = [
          `${request.method ?? 'GET'} ${request.url ?? '/'} HTTP/${request.httpVersion}`,
          ...Object.entries(request.headers).map(([name, value]) => `${name}: ${Array.isArray(value) ? value.join(', ') : value ?? ''}`),
          '',
          truncated ? `${body}\n[ProxyForge callback listener truncated body at ${MAX_HTTP_CAPTURE_BYTES} bytes]` : body,
        ].join('\n');
        this.recordInteraction(runtime, 'http', raw, `${request.method ?? 'GET'} ${request.url ?? '/'} HTTP/${request.httpVersion}`, request.headers['user-agent']?.toString() ?? 'http-client', request.socket.remoteAddress ?? '127.0.0.1');
        response.writeHead(204, {
          'Access-Control-Allow-Origin': '*',
          'ProxyForge-Callback-Listener': runtime.profile.id,
        });
        response.end();
      });
    });
    await listenTcp(server, runtime.profile.host, runtime.profile.httpPort);
    runtime.httpServer = server;
    runtime.ports.http = addressPort(server.address(), runtime.profile.httpPort);
    runtime.healthChecks.push(`HTTP listener running on ${runtime.profile.host}:${runtime.ports.http}`);
  }

  private async startDns(runtime: CallbackListenerRuntime): Promise<void> {
    const socket = dgram.createSocket('udp4');
    socket.on('error', (error) => {
      runtime.healthChecks.push(`DNS listener socket error: ${error.message}`);
    });
    socket.on('message', (message, remote) => {
      try {
        const query = parseDnsQuery(message);
        if (!query) return;
        const raw = `${query.name} ${query.typeName}`;
        this.recordInteraction(runtime, 'dns', raw, `${query.name} ${query.typeName}`, 'udp-dns-client', remote.address);
        const response = buildDnsResponse(message, query);
        socket.send(response, remote.port, remote.address);
      } catch (error) {
        runtime.healthChecks.push(`Dropped malformed DNS callback datagram from ${remote.address}: ${error instanceof Error ? error.message : 'parse failure'}`);
      }
    });
    await bindUdp(socket, runtime.profile.host, runtime.profile.dnsPort);
    runtime.dnsSocket = socket;
    runtime.ports.dns = addressPort(socket.address(), runtime.profile.dnsPort);
    runtime.healthChecks.push(`DNS listener running on ${runtime.profile.host}:${runtime.ports.dns}`);
  }

  private async startSmtp(runtime: CallbackListenerRuntime): Promise<void> {
    const server = net.createServer((socket) => {
      let transcript = '';
      let captured = false;
      socket.write('220 ProxyForge OAST SMTP listener ready\r\n');
      socket.on('data', (chunk) => {
        if (Buffer.byteLength(transcript, 'utf8') < MAX_SMTP_TRANSCRIPT_BYTES) {
          const remaining = MAX_SMTP_TRANSCRIPT_BYTES - Buffer.byteLength(transcript, 'utf8');
          transcript += chunk.subarray(0, remaining).toString('utf8');
          if (chunk.byteLength > remaining) transcript += '\n[ProxyForge callback listener truncated SMTP transcript]';
        }
        if (!captured && findPayload(runtime.payloads, transcript)) {
          captured = true;
          const line = transcript.split(/\r?\n/).find((item) => /RCPT TO|MAIL FROM|HELO|EHLO/i.test(item)) ?? 'SMTP callback';
          this.recordInteraction(runtime, 'smtp', transcript.trim(), line, 'smtp-client', socket.remoteAddress ?? '127.0.0.1');
        }
        if (/EHLO|HELO/i.test(transcript)) socket.write('250-proxyforge.local\r\n250 OK\r\n');
        if (/MAIL FROM:/i.test(transcript)) socket.write('250 OK\r\n');
        if (/RCPT TO:/i.test(transcript)) socket.write('250 Accepted\r\n');
        if (/DATA/i.test(transcript)) socket.write('354 End data with <CR><LF>.<CR><LF>\r\n');
        if (/\r?\n\.\r?\n/.test(transcript)) socket.write('250 Queued\r\n');
        if (/QUIT/i.test(transcript)) {
          socket.write('221 Bye\r\n');
          socket.end();
        }
      });
    });
    await listenTcp(server, runtime.profile.host, runtime.profile.smtpPort);
    runtime.smtpServer = server;
    runtime.ports.smtp = addressPort(server.address(), runtime.profile.smtpPort);
    runtime.healthChecks.push(`SMTP listener running on ${runtime.profile.host}:${runtime.ports.smtp}`);
  }

  private recordInteraction(runtime: CallbackListenerRuntime, protocol: CallbackProtocol, raw: string, requestLine: string, userAgent: string, sourceIp: string): void {
    const payload = findPayload(runtime.payloads, raw);
    const observedAt = new Date().toISOString();
    const idSeed = `${runtime.profile.id}|${protocol}|${observedAt}|${raw}|${runtime.interactions.length}`;
    const interaction = {
      id: `cb-live-${protocol}-${simpleDigest(idSeed).slice(0, 12)}`,
      payloadId: payload?.id ?? 'unmatched',
      protocol,
      observedAt,
      sourceIp,
      sourceHost: sourceIp,
      requestLine,
      userAgent,
      raw,
      severity: protocol === 'dns' ? 'medium' : 'high',
      tags: ['oast', protocol, 'local-listener', payload ? 'matched-payload' : 'unmatched'],
    } satisfies CallbackInteraction;
    runtime.interactions.push(interaction);
    this.sink?.interaction?.(runtime.profile, interaction);
    pruneExpiredInteractions(runtime);
  }

  private statusFor(runtime: CallbackListenerRuntime, message: string): CallbackListenerRuntimeStatus {
    return {
      profileId: runtime.profile.id,
      running: true,
      mode: runtime.profile.mode,
      host: runtime.profile.host,
      protocols: runtime.profile.protocols,
      ports: runtime.ports,
      interactionCount: runtime.interactions.length,
      retentionHours: runtime.profile.retentionHours,
      retentionPrunedCount: runtime.retentionPrunedCount,
      startedAt: runtime.startedAt,
      healthChecks: runtime.healthChecks,
      message,
    };
  }
}

function protocolsForMode(profile: CallbackListenerProfile): CallbackProtocol[] {
  if (profile.mode === 'local-http') return ['http'];
  if (profile.mode === 'local-dns') return ['dns'];
  if (profile.mode === 'local-smtp') return ['smtp'];
  if (profile.mode === 'hybrid-local') return ['dns', 'http', 'smtp'];
  return profile.protocols?.length ? profile.protocols : ['dns', 'http'];
}

function isLoopbackBindHost(host: string) {
  return /^(localhost|127(?:\.\d{1,3}){3}|::1|\[::1\])$/i.test(host.trim());
}

function stoppedStatus(profile: CallbackListenerProfile, message: string): CallbackListenerRuntimeStatus {
  return {
    profileId: profile.id,
    running: false,
    mode: profile.mode ?? 'browser-preview',
    host: profile.host ?? '127.0.0.1',
    protocols: profile.protocols ?? [],
    ports: {},
    interactionCount: 0,
    retentionHours: profile.retentionHours,
    retentionPrunedCount: 0,
    stoppedAt: new Date().toISOString(),
    healthChecks: [],
    message,
  };
}

function pruneExpiredInteractions(runtime: CallbackListenerRuntime): void {
  const retentionHours = Math.max(1, Math.floor(runtime.profile.retentionHours || 24));
  const cutoff = Date.now() - retentionHours * 60 * 60 * 1000;
  const before = runtime.interactions.length;
  runtime.interactions = runtime.interactions.filter((interaction) => {
    const observedAt = Date.parse(interaction.observedAt);
    return Number.isNaN(observedAt) || observedAt >= cutoff;
  });
  const pruned = before - runtime.interactions.length;
  if (pruned > 0) {
    runtime.retentionPrunedCount += pruned;
    runtime.lastPollIndex = Math.min(runtime.lastPollIndex, runtime.interactions.length);
  }
}

function listenTcp(server: net.Server | http.Server, host: string, port: number): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      server.off('error', reject);
      resolve();
    });
  });
}

function bindUdp(socket: dgram.Socket, host: string, port: number): Promise<void> {
  return new Promise((resolve, reject) => {
    socket.once('error', reject);
    socket.bind(port, host, () => {
      socket.off('error', reject);
      resolve();
    });
  });
}

async function closeRuntime(runtime: CallbackListenerRuntime): Promise<void> {
  await Promise.all([
    closeServer(runtime.httpServer),
    closeServer(runtime.smtpServer),
    closeSocket(runtime.dnsSocket),
  ]);
}

function closeServer(server?: net.Server | http.Server): Promise<void> {
  return new Promise((resolve) => {
    if (!server?.listening) {
      resolve();
      return;
    }
    server.close(() => resolve());
  });
}

function closeSocket(socket?: dgram.Socket): Promise<void> {
  return new Promise((resolve) => {
    if (!socket) {
      resolve();
      return;
    }
    socket.close(() => resolve());
  });
}

function addressPort(address: string | net.AddressInfo | null, fallback: number): number {
  return typeof address === 'object' && address ? address.port : fallback;
}

function findPayload(payloads: CallbackPayload[], raw: string): CallbackPayload | undefined {
  return payloads.find((payload) => raw.includes(payload.token) || raw.includes(payload.endpoint) || raw.includes(payload.id));
}

function parseDnsQuery(message: Buffer): { name: string; type: number; typeName: string; questionEnd: number } | null {
  if (message.length < 12) return null;
  const questionCount = message.readUInt16BE(4);
  if (questionCount < 1) return null;
  const parsedName = readDnsName(message, 12);
  if (!parsedName || parsedName.name.length > MAX_DNS_NAME_BYTES) return null;
  if (parsedName.nextOffset + 4 > message.length) return null;
  const type = message.readUInt16BE(parsedName.nextOffset);
  const questionEnd = parsedName.nextOffset + 4;
  const typeName = type === 1 ? 'A' : type === 28 ? 'AAAA' : type === 16 ? 'TXT' : `TYPE${type}`;
  return { name: parsedName.name || '.', type, typeName, questionEnd };
}

function readDnsName(message: Buffer, startOffset: number): { name: string; nextOffset: number } | null {
  const labels: string[] = [];
  const visitedPointers = new Set<number>();
  let offset = startOffset;
  let nextOffset = startOffset;
  let jumped = false;
  let labelBytes = 0;

  for (let labelCount = 0; labelCount < 128; labelCount += 1) {
    if (offset >= message.length) return null;
    const length = message[offset];
    if ((length & 0xc0) === 0xc0) {
      if (offset + 1 >= message.length) return null;
      const pointer = ((length & 0x3f) << 8) | message[offset + 1];
      if (pointer >= message.length || visitedPointers.has(pointer)) return null;
      visitedPointers.add(pointer);
      if (!jumped) nextOffset = offset + 2;
      offset = pointer;
      jumped = true;
      continue;
    }
    if ((length & 0xc0) !== 0) return null;
    offset += 1;
    if (length === 0) {
      if (!jumped) nextOffset = offset;
      return { name: labels.join('.'), nextOffset };
    }
    if (length > 63 || offset + length > message.length) return null;
    labelBytes += length + (labels.length ? 1 : 0);
    if (labelBytes > MAX_DNS_NAME_BYTES) return null;
    labels.push(message.subarray(offset, offset + length).toString('ascii'));
    offset += length;
    if (!jumped) nextOffset = offset;
  }
  return null;
}

function buildDnsResponse(message: Buffer, query: { type: number; questionEnd: number }): Buffer {
  const response = Buffer.alloc(query.questionEnd + 16);
  message.copy(response, 0, 0, query.questionEnd);
  response.writeUInt16BE(0x8180, 2);
  response.writeUInt16BE(1, 4);
  response.writeUInt16BE(1, 6);
  response.writeUInt16BE(0, 8);
  response.writeUInt16BE(0, 10);
  let offset = query.questionEnd;
  response.writeUInt16BE(0xc00c, offset);
  offset += 2;
  response.writeUInt16BE(query.type === 28 ? 1 : query.type, offset);
  offset += 2;
  response.writeUInt16BE(1, offset);
  offset += 2;
  response.writeUInt32BE(30, offset);
  offset += 4;
  response.writeUInt16BE(4, offset);
  offset += 2;
  response.set([127, 0, 0, 1], offset);
  return response;
}

function simpleDigest(value: string) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `${hash.toString(16).padStart(8, '0')}${value.length.toString(16).padStart(8, '0')}`;
}
