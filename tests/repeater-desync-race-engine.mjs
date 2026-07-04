import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import http from 'node:http';
import path from 'node:path';

const require = createRequire(import.meta.url);
const {
  RepeaterDesyncRaceEngine,
  buildRepeaterDesyncParserDifferentialPackage,
  buildRepeaterRaceDesyncProductionPackage,
} = require('../dist-electron/repeaterDesyncRaceEngine.js');

const arrivals = [];
const server = http.createServer((request, response) => {
  const receivedAt = Date.now();
  arrivals.push({
    url: request.url,
    raceId: request.headers['x-proxyforge-race-id'],
    receivedAt,
    socket: `${request.socket.remoteAddress}:${request.socket.remotePort}`,
  });
  const body = JSON.stringify({ ok: true, url: request.url, raceId: request.headers['x-proxyforge-race-id'] ?? null });
  response.writeHead(200, {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(body),
    connection: 'keep-alive',
  });
  response.end(body);
});

try {
  const port = await listen(server);
  const targetUrl = `http://127.0.0.1:${port}/baseline`;
  const engine = new RepeaterDesyncRaceEngine();
  const singleRequests = ['/baseline', '/poison', '/victim'].map((route, index) => ({
    id: `single-${index + 1}`,
    name: `Single connection ${route}`,
    targetUrl: `http://127.0.0.1:${port}${route}`,
    rawRequest: [
      `GET ${route} HTTP/1.1`,
      `Host: 127.0.0.1:${port}`,
      'Authorization: Bearer repeater-desync-secret-token',
      'Cookie: session=repeater-desync-cookie',
      'X-API-Key: repeater-desync-api-key',
      'Connection: keep-alive',
      '',
      '',
    ].join('\r\n'),
    role: index === 0 ? 'baseline' : index === 1 ? 'poison' : 'victim',
  }));

  const single = await engine.runSingleConnectionProbe({
    planId: 'test-single-plan',
    targetUrl,
    scopeAllowlist: ['127.0.0.1'],
    timeoutMs: 2000,
    requests: singleRequests,
  });

  assert.equal(single.status, 'proof');
  assert.equal(single.transport, 'single-connection');
  assert.equal(single.responses.length, 3);
  assert.deepEqual(single.responses.map((response) => response.status), [200, 200, 200]);
  assert(single.rawTranscript.includes('GET /poison HTTP/1.1'));
  assert(single.responseOrder.some((entry) => entry.includes('victim')));

  const differentialRequests = [
    singleRequests[0],
    {
      id: 'parser-poison',
      name: 'Parser differential CL.0 poison',
      targetUrl: targetUrl,
      rawRequest: [
        'POST /poison HTTP/1.1',
        `Host: 127.0.0.1:${port}`,
        'Authorization: Bearer repeater-parser-secret-token',
        'Cookie: session=repeater-parser-cookie',
        'Content-Length: 48',
        'Connection: keep-alive',
        '',
        'GET /__proxyforge-desync-canary HTTP/1.1',
        'X-ProxyForge-Desync: canary',
        '',
      ].join('\r\n'),
      role: 'poison',
    },
    singleRequests[2],
  ];
  const parserDifferential = buildRepeaterDesyncParserDifferentialPackage(differentialRequests);
  assert.equal(parserDifferential.kind, 'proxyforge-repeater-desync-parser-differential-package');
  assert.equal(parserDifferential.parserProfiles.includes('cl0-backend'), true);
  assert.equal(parserDifferential.highRiskCandidateCount >= 1, true);
  assert(
    parserDifferential.candidates.some((candidate) =>
      candidate.role === 'poison'
      && candidate.verdict === 'queued-followup'
      && candidate.outcomes.some((outcome) => outcome.signal === 'queued-followup' && /GET \/poison|GET \/__proxyforge/i.test(outcome.leftoverPreview)),
    ),
    'parser differential package should identify queued follow-up request framing',
  );

  const raceRequests = [1, 2, 3].map((index) => ({
    id: `race-${index}`,
    name: `Race request ${index}`,
    targetUrl: `http://127.0.0.1:${port}/race`,
    rawRequest: [
      'GET /race HTTP/1.1',
      `Host: 127.0.0.1:${port}`,
      `X-ProxyForge-Race-Id: race-${index}`,
      'Authorization: Bearer repeater-race-secret-token',
      'Cookie: session=repeater-race-cookie',
      'Connection: close',
      '',
      '',
    ].join('\r\n'),
    role: index === 1 ? 'baseline' : 'victim',
  }));

  const beforeRaceCount = arrivals.length;
  const race = await engine.runParallelRace({
    planId: 'test-race-plan',
    targetUrl: `http://127.0.0.1:${port}/race`,
    scopeAllowlist: ['127.0.0.1'],
    timeoutMs: 2000,
    syncTechnique: 'last-byte',
    pauseMs: 20,
    requests: raceRequests,
  });

  assert.equal(race.status, 'proof');
  assert.equal(race.transport, 'parallel-last-byte');
  assert.equal(race.responses.length, 3);
  assert.equal(race.responses.every((response) => response.status === 200), true);
  assert.equal(race.releaseSkewMs < 50, true, `release skew was ${race.releaseSkewMs}ms`);
  assert(race.rawTranscript.includes('X-ProxyForge-Race-Id: race-3'));

  const raceArrivals = arrivals.slice(beforeRaceCount).filter((entry) => entry.url === '/race');
  assert.equal(raceArrivals.length, 3);
  const arrivalWindowMs = Math.max(...raceArrivals.map((entry) => entry.receivedAt)) - Math.min(...raceArrivals.map((entry) => entry.receivedAt));
  assert.equal(arrivalWindowMs < 250, true, `arrival window was ${arrivalWindowMs}ms`);

  const soakRequests = Array.from({ length: 16 }, (_value, index) => ({
    id: `race-soak-${index + 1}`,
    name: `Single-packet race soak request ${index + 1}`,
    targetUrl: `http://127.0.0.1:${port}/race-soak`,
    rawRequest: [
      'GET /race-soak HTTP/1.1',
      `Host: 127.0.0.1:${port}`,
      `X-ProxyForge-Race-Id: race-soak-${index + 1}`,
      'Authorization: Bearer repeater-soak-secret-token',
      'Cookie: session=repeater-soak-cookie',
      'Connection: close',
      '',
      '',
    ].join('\r\n'),
    role: index === 0 ? 'baseline' : 'victim',
  }));
  const beforeSoakCount = arrivals.length;
  const singlePacketSoak = await engine.runParallelRace({
    planId: 'test-race-single-packet-soak',
    targetUrl: `http://127.0.0.1:${port}/race-soak`,
    scopeAllowlist: ['127.0.0.1'],
    timeoutMs: 2000,
    syncTechnique: 'single-packet',
    pauseMs: 5,
    requests: soakRequests,
  });

  assert.equal(singlePacketSoak.status, 'proof');
  assert.equal(singlePacketSoak.transport, 'parallel-single-packet');
  assert.equal(singlePacketSoak.responses.length, 16);
  assert.equal(singlePacketSoak.responses.every((response) => response.status === 200), true);
  assert.equal(singlePacketSoak.releaseSkewMs < 100, true, `single-packet release skew was ${singlePacketSoak.releaseSkewMs}ms`);
  assert(singlePacketSoak.rawTranscript.includes('X-ProxyForge-Race-Id: race-soak-16'));

  const raceSoakArrivals = arrivals.slice(beforeSoakCount).filter((entry) => entry.url === '/race-soak');
  assert.equal(raceSoakArrivals.length, 16);
  const soakArrivalWindowMs = Math.max(...raceSoakArrivals.map((entry) => entry.receivedAt)) - Math.min(...raceSoakArrivals.map((entry) => entry.receivedAt));
  assert.equal(soakArrivalWindowMs < 500, true, `single-packet soak arrival window was ${soakArrivalWindowMs}ms`);

  const blocked = await engine.runParallelRace({
    planId: 'blocked-plan',
    targetUrl: `http://127.0.0.1:${port}/race`,
    scopeAllowlist: ['example.test'],
    timeoutMs: 500,
    requests: raceRequests,
  });
  assert.equal(blocked.status, 'blocked');
  assert.match(blocked.summary, /outside the supplied scope/i);

  const productionPackage = buildRepeaterRaceDesyncProductionPackage({
    parserDifferential,
    runtimeResults: [single, race, singlePacketSoak],
    blockedResults: [blocked],
    minSoakRequests: 16,
    maxReleaseSkewMs: 100,
    maxRaceWindowMs: 100,
    generatedAt: '2026-05-26T18:30:00.000Z',
  });
  assert.equal(productionPackage.kind, 'proxyforge-repeater-race-desync-production-package');
  assert.equal(productionPackage.reportReady, true);
  assert.equal(productionPackage.runtimeProfileCount, 3);
  assert.equal(productionPackage.requestCount, 22);
  assert.equal(productionPackage.observedResponseCount, 22);
  assert.equal(productionPackage.highRiskParserCandidateCount >= 1, true);
  assert(productionPackage.transportModes.includes('single-connection'));
  assert(productionPackage.transportModes.includes('parallel-last-byte'));
  assert(productionPackage.transportModes.includes('parallel-single-packet'));
  assert(productionPackage.operationalSecretSignals.includes('authorization-header'));
  assert(productionPackage.operationalSecretSignals.includes('cookie-header'));
  assert(productionPackage.operationalSecretSignals.includes('x-api-key-header'));
  for (const [name, covered] of Object.entries(productionPackage.requirements)) {
    assert.equal(covered, true, `Repeater race/desync production requirement ${name} should be covered`);
  }
  assert.match(productionPackage.content, /Bearer repeater-desync-secret-token|session=repeater-race-cookie|repeater-soak-secret-token/);
  assert.match(productionPackage.content, /redact-only-during-report-export/);
  const artifactDir = path.resolve('.gitignored/test-artifacts/repeater-desync-race-engine');
  await fs.mkdir(artifactDir, { recursive: true });
  await fs.writeFile(
    path.join(artifactDir, 'repeater-race-desync-production-package.json'),
    JSON.stringify(productionPackage, null, 2),
    'utf8',
  );

  console.log('repeater-desync-race-engine: socket-backed single-connection, parser-differential, last-byte race, single-packet race soak, and production package proof passed');
} finally {
  await close(server);
}

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return server.address().port;
}

async function close(server) {
  if (!server.listening) return;
  await new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}
