// DNS proxy: UDP listener that forwards DNS queries, applies block/map rules,
// and maintains a query log.  Raw DNS wire-format parsing for query name
// extraction; upstream forwarding via node:dgram.

import dgram from 'node:dgram';
import { randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { applyDnsRules } from './dnsRecordRules';
import type { DnsRecordRule } from './dnsRecordRules';

export interface DnsProxyConfig {
  port?: number;
  host?: string;
  upstreamDns?: string;
  upstreamPort?: number;
  blockList?: string[];
  mapRules?: Array<{ pattern: string; resolvedIp: string }>;
}

export interface DnsQueryLog {
  id: string;
  timestamp: string;
  name: string;
  type: string;
  clientIp: string;
  resolved?: string;
  blocked?: boolean;
  mapped?: boolean;
}

// DNS record type numbers → names
const DNS_TYPES: Record<number, string> = {
  1: 'A',
  2: 'NS',
  5: 'CNAME',
  6: 'SOA',
  12: 'PTR',
  15: 'MX',
  16: 'TXT',
  28: 'AAAA',
  33: 'SRV',
  255: 'ANY',
};

// ─── Wire-format DNS parsing ─────────────────────────────────────────────────

/**
 * Parse the first question's QNAME from a raw DNS message buffer.
 * Returns { name, type } or null if parsing fails.
 */
export function parseDnsQuery(buf: Buffer): { name: string; type: number } | null {
  try {
    // DNS header is 12 bytes; question section starts at offset 12
    if (buf.length < 13) return null;

    let offset = 12;
    const labels: string[] = [];

    // Read QNAME (series of length-prefixed labels, ending with 0x00)
    while (offset < buf.length) {
      const len = buf[offset];
      if (len === 0) { offset++; break; }
      // Compression pointer (top 2 bits set) — not expected in queries but handle gracefully
      if ((len & 0xc0) === 0xc0) { offset += 2; break; }
      offset++;
      if (offset + len > buf.length) return null;
      labels.push(buf.slice(offset, offset + len).toString('ascii'));
      offset += len;
    }

    if (offset + 2 > buf.length) return null;
    const qtype = buf.readUInt16BE(offset);

    return { name: labels.join('.'), type: qtype };
  } catch {
    return null;
  }
}

/**
 * Build a minimal NXDOMAIN response for the given query buffer.
 * Reuses the query ID and question section; sets QR=1, RCODE=3.
 */
function buildNxdomainResponse(query: Buffer): Buffer {
  const response = Buffer.alloc(query.length);
  query.copy(response);

  // Flags: QR=1, opcode=0, AA=0, TC=0, RD=1, RA=1, RCODE=3 (NXDOMAIN)
  // Original flags are at bytes 2-3
  const origFlags = query.readUInt16BE(2);
  const newFlags =
    (origFlags & 0x7800) | // preserve opcode
    0x8183; // QR=1, RD=1, RA=1, RCODE=3
  response.writeUInt16BE(newFlags, 2);
  // ANCOUNT, NSCOUNT, ARCOUNT = 0 (already zero from copy if QDCOUNT was the only section)
  response.writeUInt16BE(0, 6);  // ANCOUNT
  response.writeUInt16BE(0, 8);  // NSCOUNT
  response.writeUInt16BE(0, 10); // ARCOUNT

  return response;
}

/**
 * Build a spoofed A-record response resolving QNAME → resolvedIp.
 */
function buildSpoofedAResponse(query: Buffer, resolvedIp: string): Buffer {
  // Parse offset of end of question section
  let offset = 12;
  // Skip QNAME
  while (offset < query.length) {
    const len = query[offset];
    if (len === 0) { offset++; break; }
    if ((len & 0xc0) === 0xc0) { offset += 2; break; }
    offset += 1 + len;
  }
  offset += 4; // QTYPE + QCLASS

  const questionSection = query.slice(12, offset);

  // Answer: pointer to name (0xc00c = pointer to offset 12), TYPE A, CLASS IN,
  //         TTL 60, RDLENGTH 4, RDATA (4 bytes IP)
  const ipParts = resolvedIp.split('.').map(Number);
  if (ipParts.length !== 4 || ipParts.some(isNaN)) {
    return buildNxdomainResponse(query);
  }

  const answer = Buffer.alloc(16);
  answer.writeUInt16BE(0xc00c, 0);  // name pointer
  answer.writeUInt16BE(1, 2);        // TYPE A
  answer.writeUInt16BE(1, 4);        // CLASS IN
  answer.writeUInt32BE(60, 6);       // TTL
  answer.writeUInt16BE(4, 10);       // RDLENGTH
  answer[12] = ipParts[0];
  answer[13] = ipParts[1];
  answer[14] = ipParts[2];
  answer[15] = ipParts[3];

  const header = Buffer.alloc(12);
  query.copy(header, 0, 0, 12);
  const flags = (query.readUInt16BE(2) & 0x7800) | 0x8180; // QR=1, RA=1, RCODE=0
  header.writeUInt16BE(flags, 2);
  header.writeUInt16BE(1, 4);  // QDCOUNT
  header.writeUInt16BE(1, 6);  // ANCOUNT
  header.writeUInt16BE(0, 8);  // NSCOUNT
  header.writeUInt16BE(0, 10); // ARCOUNT

  return Buffer.concat([header, questionSection, answer]);
}

// ─── DnsProxy class ──────────────────────────────────────────────────────────

export class DnsProxy extends EventEmitter {
  private socket: dgram.Socket | null = null;
  private config: DnsProxyConfig | null = null;
  private queryLog: DnsQueryLog[] = [];

  start(config: DnsProxyConfig): Promise<void> {
    this.config = config;
    this.queryLog = [];

    const upstreamDns = config.upstreamDns ?? '1.1.1.1';
    const upstreamPort = config.upstreamPort ?? 53;

    // Build DnsRecordRule list from blockList + mapRules
    const blockRules: DnsRecordRule[] = (config.blockList ?? []).map((pattern, i) => ({
      id: `block-${i}`,
      name: `block:${pattern}`,
      enabled: true,
      matchPattern: pattern,
      action: 'block' as const,
    }));

    const mapRules: DnsRecordRule[] = (config.mapRules ?? []).map((rule, i) => ({
      id: `map-${i}`,
      name: `map:${rule.pattern}`,
      enabled: true,
      matchPattern: rule.pattern,
      action: 'map' as const,
      resolvedIp: rule.resolvedIp,
    }));

    const allRules: DnsRecordRule[] = [...blockRules, ...mapRules];

    return new Promise((resolve, reject) => {
      this.socket = dgram.createSocket('udp4');

      this.socket.on('error', (err) => {
        this.emit('error', err);
      });

      this.socket.on('message', (msg: Buffer, rinfo: dgram.RemoteInfo) => {
        this._handleQuery(msg, rinfo, upstreamDns, upstreamPort, allRules);
      });

      this.socket.once('error', reject);
      this.socket.bind(config.port ?? 5353, config.host ?? '127.0.0.1', () => {
        this.socket!.removeListener('error', reject);
        resolve();
      });
    });
  }

  stop(): Promise<void> {
    return new Promise((resolve) => {
      if (!this.socket) { resolve(); return; }
      this.socket.close(() => resolve());
      this.socket = null;
    });
  }

  getQueryLog(): DnsQueryLog[] {
    return [...this.queryLog];
  }

  address(): { address: string; family: string; port: number } | null {
    if (!this.socket) return null;
    return this.socket.address();
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Internal
  // ──────────────────────────────────────────────────────────────────────────

  private _handleQuery(
    msg: Buffer,
    rinfo: dgram.RemoteInfo,
    upstreamDns: string,
    upstreamPort: number,
    rules: DnsRecordRule[],
  ): void {
    const parsed = parseDnsQuery(msg);
    const name = parsed?.name ?? '<unparsed>';
    const typeNum = parsed?.type ?? 0;
    const typeName = DNS_TYPES[typeNum] ?? `TYPE${typeNum}`;

    const logEntry: DnsQueryLog = {
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      name,
      type: typeName,
      clientIp: rinfo.address,
    };

    const ruleResult = applyDnsRules(name, rules);

    if (ruleResult.action === 'block') {
      logEntry.blocked = true;
      this.queryLog.push(logEntry);
      this.emit('query', logEntry);
      const nxResp = buildNxdomainResponse(msg);
      this.socket?.send(nxResp, rinfo.port, rinfo.address);
      return;
    }

    if (ruleResult.action === 'map' && ruleResult.resolvedIp) {
      logEntry.mapped = true;
      logEntry.resolved = ruleResult.resolvedIp;
      this.queryLog.push(logEntry);
      this.emit('query', logEntry);
      const spoofed = buildSpoofedAResponse(msg, ruleResult.resolvedIp);
      this.socket?.send(spoofed, rinfo.port, rinfo.address);
      return;
    }

    // Forward to upstream
    this.queryLog.push(logEntry);
    this.emit('query', logEntry);

    const upstreamSocket = dgram.createSocket('udp4');

    const timeout = setTimeout(() => {
      upstreamSocket.close();
    }, 5000);

    upstreamSocket.once('message', (response: Buffer) => {
      clearTimeout(timeout);
      logEntry.resolved = `upstream:${upstreamDns}`;
      this.socket?.send(response, rinfo.port, rinfo.address);
      upstreamSocket.close();
    });

    upstreamSocket.on('error', () => {
      clearTimeout(timeout);
      try { upstreamSocket.close(); } catch { /* ignore */ }
    });

    upstreamSocket.send(msg, upstreamPort, upstreamDns);
  }
}
