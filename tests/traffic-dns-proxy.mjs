// Tests: DnsProxy — UDP listener, query logging, block rules, map rules
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import dgram from 'node:dgram';

const require = createRequire(import.meta.url);
const { DnsProxy, parseDnsQuery } = require('../dist-electron/traffic/dnsProxy.js');

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Build a minimal DNS A-query for the given name.
 * Returns the wire-format Buffer.
 */
function buildDnsQuery(name, txid = 0x1234) {
  // Header: ID(2) FLAGS(2) QDCOUNT(2) ANCOUNT(2) NSCOUNT(2) ARCOUNT(2)
  const header = Buffer.alloc(12);
  header.writeUInt16BE(txid, 0);
  header.writeUInt16BE(0x0100, 2); // standard query, RD=1
  header.writeUInt16BE(1, 4);      // QDCOUNT=1

  // QNAME
  const labels = name.split('.').filter(Boolean);
  const qnameParts = [];
  for (const label of labels) {
    const lbuf = Buffer.from(label, 'ascii');
    qnameParts.push(Buffer.from([lbuf.length]), lbuf);
  }
  qnameParts.push(Buffer.from([0x00])); // root label
  const qname = Buffer.concat(qnameParts);

  // QTYPE=A(1) QCLASS=IN(1)
  const qtype = Buffer.from([0x00, 0x01, 0x00, 0x01]);

  return Buffer.concat([header, qname, qtype]);
}

/**
 * Send a UDP datagram and wait for a response, timing out after ms milliseconds.
 */
function sendAndReceive(serverPort, msg, ms = 2000) {
  return new Promise((resolve, reject) => {
    const client = dgram.createSocket('udp4');
    const timer = setTimeout(() => {
      client.close();
      reject(new Error('DNS response timed out'));
    }, ms);

    client.once('message', (response) => {
      clearTimeout(timer);
      client.close(() => resolve(response));
    });

    client.once('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });

    client.bind(0, '127.0.0.1', () => {
      client.send(msg, serverPort, '127.0.0.1', (err) => {
        if (err) { clearTimeout(timer); client.close(); reject(err); }
      });
    });
  });
}

function waitFor(predicate, ms = 2000) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + ms;
    const check = () => {
      if (predicate()) { resolve(); return; }
      if (Date.now() >= deadline) { reject(new Error('waitFor timed out')); return; }
      setTimeout(check, 20);
    };
    check();
  });
}

// ─── Tests ───────────────────────────────────────────────────────────────────

let proxy;

try {
  // ── Test 1: parseDnsQuery extracts name and type ───────────────────────────
  {
    const query = buildDnsQuery('example.com');
    const result = parseDnsQuery(query);
    assert(result, 'parseDnsQuery should return a result');
    assert.equal(result.name, 'example.com', 'Parsed name should match');
    assert.equal(result.type, 1, 'Parsed type should be 1 (A)');
  }

  {
    const query = buildDnsQuery('a.b.c.example.org');
    const result = parseDnsQuery(query);
    assert(result);
    assert.equal(result.name, 'a.b.c.example.org');
  }

  // ── Test 2: DnsProxy starts and logs queries ───────────────────────────────
  proxy = new DnsProxy();
  const queryEvents = [];
  proxy.on('query', (entry) => queryEvents.push(entry));

  // Point upstream at a port that won't answer — we only care that the query
  // is logged before the forward attempt times out silently.
  await proxy.start({
    port: 0,
    host: '127.0.0.1',
    upstreamDns: '127.0.0.1',
    upstreamPort: 1,   // closed port — forward will fail silently
    blockList: [],
    mapRules: [],
  });

  const { port: dnsPort } = proxy.address();

  const query1 = buildDnsQuery('test.example.com', 0xaaaa);

  // Send query — it will be logged immediately, then forward attempt fails
  await sendAndReceive(dnsPort, query1, 500).catch(() => { /* forward timeout expected */ });
  await waitFor(() => proxy.getQueryLog().some((e) => e.name === 'test.example.com'), 1000);

  const log = proxy.getQueryLog();
  const entry = log.find((e) => e.name === 'test.example.com');
  assert(entry, 'Query should be logged');
  assert.equal(entry.type, 'A');
  assert(entry.clientIp === '127.0.0.1');
  assert(entry.id.length > 0);
  assert(entry.timestamp.match(/^\d{4}-/));
  assert(!entry.blocked);
  assert(!entry.mapped);

  await proxy.stop();

  // ── Test 3: Block rule — response is NXDOMAIN ─────────────────────────────
  proxy = new DnsProxy();
  await proxy.start({
    port: 0,
    host: '127.0.0.1',
    upstreamDns: '127.0.0.1',
    upstreamPort: 1,
    blockList: ['ads.tracker.io', '*.malware.net'],
    mapRules: [],
  });

  const { port: blockPort } = proxy.address();

  // Query for a blocked domain
  const blockedQuery = buildDnsQuery('ads.tracker.io', 0xbbbb);
  const blockedResponse = await sendAndReceive(blockPort, blockedQuery, 2000);

  // Verify NXDOMAIN: QR=1, RCODE=3
  const flags = blockedResponse.readUInt16BE(2);
  assert(flags & 0x8000, 'QR bit should be set (response)');
  assert.equal(flags & 0x000f, 3, 'RCODE should be 3 (NXDOMAIN) for blocked domain');

  // Verify the log entry is marked blocked
  await waitFor(() => proxy.getQueryLog().some((e) => e.name === 'ads.tracker.io' && e.blocked));
  const blockedEntry = proxy.getQueryLog().find((e) => e.name === 'ads.tracker.io');
  assert(blockedEntry.blocked, 'Log entry should be marked blocked');
  assert(!blockedEntry.mapped);

  // Wildcard block: *.malware.net
  const wildcardQuery = buildDnsQuery('download.malware.net', 0xcccc);
  const wildcardResponse = await sendAndReceive(blockPort, wildcardQuery, 2000);
  const wildcardFlags = wildcardResponse.readUInt16BE(2);
  assert.equal(wildcardFlags & 0x000f, 3, 'Wildcard block should also return NXDOMAIN');

  await proxy.stop();

  // ── Test 4: Map rule — response is spoofed A record ───────────────────────
  proxy = new DnsProxy();
  await proxy.start({
    port: 0,
    host: '127.0.0.1',
    upstreamDns: '127.0.0.1',
    upstreamPort: 1,
    blockList: [],
    mapRules: [{ pattern: 'internal.corp', resolvedIp: '10.0.0.1' }],
  });

  const { port: mapPort } = proxy.address();

  const mapQuery = buildDnsQuery('internal.corp', 0xdddd);
  const mapResponse = await sendAndReceive(mapPort, mapQuery, 2000);

  // QR=1, RCODE=0
  const mapFlags = mapResponse.readUInt16BE(2);
  assert(mapFlags & 0x8000, 'QR bit should be set');
  assert.equal(mapFlags & 0x000f, 0, 'RCODE should be 0 (NOERROR) for mapped domain');
  // ANCOUNT >= 1
  const ancount = mapResponse.readUInt16BE(6);
  assert(ancount >= 1, 'Mapped response should have at least one answer');

  // Verify log entry
  await waitFor(() => proxy.getQueryLog().some((e) => e.name === 'internal.corp' && e.mapped));
  const mapEntry = proxy.getQueryLog().find((e) => e.name === 'internal.corp');
  assert(mapEntry.mapped, 'Log entry should be marked mapped');
  assert.equal(mapEntry.resolved, '10.0.0.1');

  await proxy.stop();
  proxy = null;

  // ── Test 5: getQueryLog returns a snapshot copy ────────────────────────────
  {
    const p = new DnsProxy();
    await p.start({ port: 0, host: '127.0.0.1', upstreamPort: 1 });
    const log1 = p.getQueryLog();
    const log2 = p.getQueryLog();
    assert(log1 !== log2, 'getQueryLog should return a new array each time');
    await p.stop();
  }

  console.log('PASS traffic-dns-proxy');
} catch (err) {
  if (proxy) await proxy.stop().catch(() => undefined);
  console.error('FAIL traffic-dns-proxy:', err.message);
  console.error(err.stack);
  process.exit(1);
}
