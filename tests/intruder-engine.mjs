import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';

const require = createRequire(import.meta.url);
const { CertificateAuthorityManager } = require('../dist-electron/certManager.js');
const {
  ProxyEngine,
  buildIntruderAttackModeMatrix,
  buildIntruderCheckpointResumePackage,
  buildIntruderGrepExtractComparisonPackage,
  buildIntruderLiveTargetProfilePackage,
} = require('../dist-electron/proxyEngine.js');

const tempDir = path.join(process.cwd(), '.gitignored', 'test-artifacts', `proxyforge-intruder-${Date.now()}-${process.pid}`);
await fs.mkdir(tempDir, { recursive: true });
const seen = [];
let activeRequests = 0;
let maxActiveRequests = 0;

try {
  const upstream = http.createServer((request, response) => {
    activeRequests += 1;
    maxActiveRequests = Math.max(maxActiveRequests, activeRequests);
    response.once('finish', () => {
      activeRequests = Math.max(0, activeRequests - 1);
    });
    seen.push(request.url);
    if (request.url.startsWith('/burst')) {
      setTimeout(() => {
        const body = JSON.stringify({ path: request.url, burst: true });
        response.writeHead(200, { 'content-type': 'application/json' });
        response.end(body);
      }, 25);
      return;
    }
    const body = JSON.stringify({
      path: request.url,
      forbidden: request.url.toLowerCase().includes('admin'),
    });
    response.writeHead(request.url.toLowerCase().includes('admin') ? 403 : 200, { 'content-type': 'application/json' });
    response.end(body);
  });
  const upstreamPort = await listen(upstream);
  const proxy = new ProxyEngine(
    () => undefined,
    new CertificateAuthorityManager(path.join(tempDir, 'certs')),
  );

  const rawRequest = [
    'GET /probe?role=§role§ HTTP/1.1',
    `Host: 127.0.0.1:${upstreamPort}`,
    'Authorization: Bearer intruder-regression-token',
    'Cookie: session=intruder-regression-session',
    'X-API-Key: intruder-regression-key',
    'Connection: close',
    '',
    '',
  ].join('\r\n');

  const modeMatrixRawRequest = [
    'GET /combo?role=§role§&region=§region§ HTTP/1.1',
    `Host: 127.0.0.1:${upstreamPort}`,
    'Authorization: Bearer intruder-matrix-token',
    'Cookie: session=intruder-matrix-session',
    'Connection: close',
    '',
    '',
  ].join('\r\n');
  const modeMatrix = buildIntruderAttackModeMatrix(modeMatrixRawRequest, {
    payloadSets: [['user', 'admin'], ['us', 'eu', 'ap']],
    attackMode: 'cluster-bomb',
  });
  const modeCounts = Object.fromEntries(modeMatrix.modes.map((entry) => [entry.mode, entry.requestCount]));
  assert.equal(modeMatrix.kind, 'proxyforge-intruder-attack-mode-matrix');
  assert.equal(modeMatrix.payloadPositions, 2);
  assert.deepEqual(modeCounts, {
    sniper: 4,
    'battering-ram': 2,
    pitchfork: 2,
    'cluster-bomb': 6,
  });
  assert(modeMatrix.modes.find((entry) => entry.mode === 'sniper').sampleRequests.some((request) => /role=user&region=region/.test(request)));
  assert(modeMatrix.modes.find((entry) => entry.mode === 'battering-ram').sampleRequests.some((request) => /role=user&region=user/.test(request)));
  assert(modeMatrix.modes.find((entry) => entry.mode === 'pitchfork').sampleRequests.some((request) => /role=admin&region=eu/.test(request)));
  assert(modeMatrix.modes.find((entry) => entry.mode === 'cluster-bomb').sampleRequests.some((request) => /role=user&region=ap|role=admin&region=ap/.test(request)));

  const transformMatrix = buildIntruderAttackModeMatrix(modeMatrixRawRequest, {
    payloadSets: [['/Admin Root'], ['us west']],
    payloadProcessors: ['uppercase'],
    payloadRules: ['case-variants', 'url-recursive', 'path-depth'],
    attackMode: 'pitchfork',
  });
  assert.deepEqual(transformMatrix.payloadTransformations.processors, ['uppercase']);
  assert.deepEqual(transformMatrix.payloadTransformations.rules, ['case-variants', 'url-recursive', 'path-depth']);
  assert.equal(transformMatrix.payloadTransformations.expandedPayloadCounts.every((count) => count > 1), true);
  assert.match(JSON.stringify(transformMatrix.payloadTransformations.sampleExpandedPayloads), new RegExp('%2FADMIN%20ROOT|\\.\\./ADMIN ROOT|US%20WEST'));
  assert.equal(transformMatrix.modes.find((entry) => entry.mode === 'pitchfork').requestCount, Math.min(...transformMatrix.payloadTransformations.expandedPayloadCounts));

  const advancedTransformMatrix = buildIntruderAttackModeMatrix(modeMatrixRawRequest, {
    payloadSets: [['<Admin Root>'], ['/api/v1/users']],
    payloadProcessors: ['html-encode', 'json-escape'],
    payloadRules: ['delimiter-variants', 'extension-bypass', 'null-byte'],
    attackMode: 'cluster-bomb',
  });
  assert.deepEqual(advancedTransformMatrix.payloadTransformations.processors, ['html-encode', 'json-escape']);
  assert.deepEqual(advancedTransformMatrix.payloadTransformations.rules, ['delimiter-variants', 'extension-bypass', 'null-byte']);
  assert.equal(advancedTransformMatrix.payloadTransformations.expandedPayloadCounts.every((count) => count > 4), true);
  assert.match(JSON.stringify(advancedTransformMatrix.payloadTransformations.sampleExpandedPayloads), /&lt;Admin-Root&gt;|&lt;Admin Root&gt;\.json|%00|api-v1-users|api%2fv1%2fusers/i);

  const encodedTransformMatrix = buildIntruderAttackModeMatrix(modeMatrixRawRequest, {
    payloadSets: [['Admin Root']],
    payloadProcessors: ['double-url-encode', 'hex-encode'],
    attackMode: 'sniper',
  });
  assert.deepEqual(encodedTransformMatrix.payloadTransformations.processors, ['double-url-encode', 'hex-encode']);
  assert.match(JSON.stringify(encodedTransformMatrix.payloadTransformations.sampleExpandedPayloads), /41646d696e2532353230526f6f74|41646d696e/i);

  const blocked = await proxy.runIntruderAttack({
    rawRequest,
    targetUrl: `http://127.0.0.1:${upstreamPort}/probe?role=seed`,
    payloads: ['user'],
    scopeAllowlist: ['example.invalid'],
    throttleMs: 0,
    grepTerms: ['forbidden'],
  });
  assert.equal(blocked.blocked, true);
  assert.equal(blocked.totalRequests, 0);

  const summary = await proxy.runIntruderAttack({
    rawRequest,
    targetUrl: `http://127.0.0.1:${upstreamPort}/probe?role=seed`,
    payloads: ['user', 'admin'],
    scopeAllowlist: ['127.0.0.1'],
    throttleMs: 1,
    grepTerms: ['forbidden'],
  });

  assert.equal(summary.blocked, false);
  assert.equal(summary.totalRequests, 2);
  assert.deepEqual(seen.slice(-2), ['/probe?role=user', '/probe?role=admin']);
  assert.equal(summary.results[0].payload, 'user');
  assert.equal(summary.results[0].status, 200);
  assert.equal(summary.results[1].payload, 'admin');
  assert.equal(summary.results[1].status, 403);
  assert(summary.results[1].grepMatches.includes('forbidden'));
  assert.match(summary.results[1].requestRaw, /role=admin/);

  const checkpointSummary = await proxy.runIntruderAttack({
    rawRequest,
    targetUrl: `http://127.0.0.1:${upstreamPort}/probe?role=seed`,
    payloads: ['Admin Root'],
    payloadRules: ['case-variants', 'url-recursive'],
    scopeAllowlist: ['127.0.0.1'],
    throttleMs: 0,
    grepTerms: ['forbidden'],
    maxPayloadRequests: 3,
    resourcePoolName: 'Regression pool',
    resourcePoolMaxConcurrent: 3,
  });

  assert.equal(checkpointSummary.blocked, false);
  assert.equal(checkpointSummary.totalRequests, 3);
  assert.equal(checkpointSummary.startOffset, 0);
  assert.equal(checkpointSummary.nextOffset, 3);
  assert.equal(checkpointSummary.hasMore, true);
  assert(checkpointSummary.payloadPlanCount > checkpointSummary.totalRequests);
  assert.equal(checkpointSummary.payloadRuleCount, 2);
  assert.equal(checkpointSummary.resourcePoolName, 'Regression pool');
  assert.equal(checkpointSummary.resourcePoolMaxConcurrent, 3);
  assert(checkpointSummary.results[0].tags.includes('payload-rule:case-variants'));
  assert(checkpointSummary.results[0].tags.includes('payload-rule:url-recursive'));
  assert(checkpointSummary.results[0].tags.includes('pool:Regression pool'));

  const resumedSummary = await proxy.runIntruderAttack({
    rawRequest,
    targetUrl: `http://127.0.0.1:${upstreamPort}/probe?role=seed`,
    payloads: ['Admin Root'],
    payloadRules: ['case-variants', 'url-recursive'],
    scopeAllowlist: ['127.0.0.1'],
    throttleMs: 0,
    grepTerms: ['forbidden'],
    startOffset: checkpointSummary.nextOffset,
    maxPayloadRequests: 20,
    resourcePoolName: 'Regression pool',
    resourcePoolMaxConcurrent: 3,
  });

  assert.equal(resumedSummary.blocked, false);
  assert.equal(resumedSummary.hasMore, false);
  assert.equal(resumedSummary.startOffset, checkpointSummary.nextOffset);
  assert.equal(resumedSummary.payloadPlanCount, checkpointSummary.payloadPlanCount);
  assert.equal(resumedSummary.nextOffset, resumedSummary.payloadPlanCount);
  assert(seen.some((url) => url.includes('Admin%20Root') || url.includes('Admin%2520Root')));

  const bodyTransformRawRequest = [
    'POST /probe?role=static HTTP/1.1',
    `Host: 127.0.0.1:${upstreamPort}`,
    'Content-Type: application/json',
    'Authorization: Bearer intruder-regression-token',
    'Connection: close',
    '',
    '{"name":"§name§"}',
  ].join('\r\n');
  const bodyTransformSummary = await proxy.runIntruderAttack({
    rawRequest: bodyTransformRawRequest,
    targetUrl: `http://127.0.0.1:${upstreamPort}/probe?role=static`,
    payloads: ['<Admin Root>'],
    payloadProcessors: ['html-encode'],
    payloadRules: ['delimiter-variants', 'extension-bypass', 'null-byte'],
    scopeAllowlist: ['127.0.0.1'],
    throttleMs: 0,
    grepTerms: [],
    maxPayloadRequests: 6,
  });
  assert.equal(bodyTransformSummary.blocked, false);
  assert.equal(bodyTransformSummary.payloadRuleCount, 3);
  assert.equal(bodyTransformSummary.totalRequests, 6);
  assert.match(JSON.stringify(bodyTransformSummary.results.map((result) => result.requestRaw)), /&lt;Admin Root&gt;|&lt;Admin-Root&gt;|%00|\.json/i);

  const checkpointPackage = buildIntruderCheckpointResumePackage({
    summaries: [checkpointSummary, resumedSummary],
    queue: [
      {
        id: 'intruder-queue-checkpoint',
        attackName: 'Regression checkpoint slice',
        targetUrl: checkpointSummary.targetUrl,
        attackMode: checkpointSummary.attackMode,
        status: 'paused',
        totalRequests: checkpointSummary.payloadPlanCount,
        completedRequests: checkpointSummary.nextOffset,
        message: checkpointSummary.message,
        createdAt: checkpointSummary.startedAt,
        updatedAt: checkpointSummary.completedAt,
        latestSummaryId: checkpointSummary.id,
        checkpointOffset: checkpointSummary.nextOffset,
        resourcePoolName: checkpointSummary.resourcePoolName,
        payloadRules: ['case-variants', 'url-recursive'],
      },
      {
        id: 'intruder-queue-resumed',
        attackName: 'Regression checkpoint slice',
        targetUrl: resumedSummary.targetUrl,
        attackMode: resumedSummary.attackMode,
        status: 'complete',
        totalRequests: resumedSummary.payloadPlanCount,
        completedRequests: resumedSummary.nextOffset,
        message: resumedSummary.message,
        createdAt: resumedSummary.startedAt,
        updatedAt: resumedSummary.completedAt,
        latestSummaryId: resumedSummary.id,
        checkpointOffset: resumedSummary.nextOffset,
        resourcePoolName: resumedSummary.resourcePoolName,
        payloadRules: ['case-variants', 'url-recursive'],
      },
    ],
  });
  assert.equal(checkpointPackage.kind, 'proxyforge-intruder-checkpoint-resume-package');
  assert.equal(checkpointPackage.requirements.checkpointPauseCovered, true);
  assert.equal(checkpointPackage.requirements.resumeCovered, true);
  assert.equal(checkpointPackage.requirements.queueStateCovered, true);
  assert.equal(checkpointPackage.requirements.resourcePoolStateCovered, true);
  assert.equal(checkpointPackage.requirements.payloadRuleStateCovered, true);
  assert.equal(checkpointPackage.requirements.rawExecutorMaterialPreserved, true);
  assert(checkpointPackage.operationalSecretSignals.includes('authorization-header'));
  assert(checkpointPackage.operationalSecretSignals.includes('cookie-header'));
  assert.equal(checkpointPackage.reportRedactionBoundary, 'redact-only-during-report-export');
  await fs.writeFile(path.join(tempDir, 'intruder-checkpoint-resume-package.json'), JSON.stringify(checkpointPackage, null, 2), 'utf8');

  const clusterRawRequest = [
    'GET /combo?role=§role§&region=§region§ HTTP/1.1',
    `Host: 127.0.0.1:${upstreamPort}`,
    'Authorization: Bearer intruder-analysis-token',
    'Cookie: session=intruder-analysis-session',
    'Connection: close',
    '',
    '',
  ].join('\r\n');
  const clusterSummary = await proxy.runIntruderAttack({
    rawRequest: clusterRawRequest,
    targetUrl: `http://127.0.0.1:${upstreamPort}/combo?role=seed&region=seed`,
    payloads: ['user', 'admin'],
    payloadSets: [['user', 'admin'], ['us-east', 'eu-west']],
    attackMode: 'cluster-bomb',
    payloadProcessors: ['uppercase'],
    scopeAllowlist: ['127.0.0.1'],
    throttleMs: 0,
    grepTerms: ['forbidden'],
    extractRegexes: ['"path":"([^"]+)"'],
  });

  assert.equal(clusterSummary.blocked, false);
  assert.equal(clusterSummary.attackMode, 'cluster-bomb');
  assert.equal(clusterSummary.payloadPositions, 2);
  assert.equal(clusterSummary.totalRequests, 4);
  assert.deepEqual(seen.slice(-4), [
    '/combo?role=USER&region=US-EAST',
    '/combo?role=USER&region=EU-WEST',
    '/combo?role=ADMIN&region=US-EAST',
    '/combo?role=ADMIN&region=EU-WEST',
  ]);
  assert.equal(clusterSummary.results[2].payload, 'ADMIN | US-EAST');
  assert.equal(clusterSummary.results[2].status, 403);
  assert(clusterSummary.results[2].extractMatches.some((match) => match.includes('/combo?role=ADMIN&region=US-EAST')));

  const analysisPackage = buildIntruderGrepExtractComparisonPackage({
    summary: clusterSummary,
    promotedIssue: {
      id: 'issue-intruder-authz-admin-region',
      title: 'Intruder payload produced privileged authorization boundary response',
      severity: 'medium',
      confidence: 'firm',
      detail: 'Cluster-bomb Intruder retained a 403 differential for ADMIN payloads and extracted the affected route.',
      remediation: 'Review authorization handling for privileged role and region combinations.',
    },
  });
  assert.equal(analysisPackage.kind, 'proxyforge-intruder-grep-extract-comparison-package');
  assert.equal(analysisPackage.requirements.grepMatchCovered, true);
  assert.equal(analysisPackage.requirements.extractRegexCovered, true);
  assert.equal(analysisPackage.requirements.baselineComparisonCovered, true);
  assert.equal(analysisPackage.requirements.clusteringCovered, true);
  assert.equal(analysisPackage.requirements.statisticalRankingCovered, true);
  assert.equal(analysisPackage.requirements.scannerPromotionCovered, true);
  assert.equal(analysisPackage.requirements.rawExecutorMaterialPreserved, true);
  assert(analysisPackage.comparisons.some((comparison) => comparison.verdict === 'interesting'));
  assert(analysisPackage.clusters.some((cluster) => cluster.status === 403));
  assert(analysisPackage.rankings[0].score > 0);
  assert(analysisPackage.operationalSecretSignals.includes('authorization-header'));
  assert.equal(analysisPackage.reportRedactionBoundary, 'redact-only-during-report-export');
  await fs.writeFile(path.join(tempDir, 'intruder-grep-extract-comparison-package.json'), JSON.stringify(analysisPackage, null, 2), 'utf8');

  const largePayloads = Array.from({ length: 260 }, (_unused, index) => `scale-${index}`);
  const seenBeforeLargeRun = seen.length;
  const largeSummary = await proxy.runIntruderAttack({
    rawRequest,
    targetUrl: `http://127.0.0.1:${upstreamPort}/probe?role=seed`,
    payloads: largePayloads,
    scopeAllowlist: ['127.0.0.1'],
    throttleMs: 0,
    grepTerms: ['scale-259'],
    streamChunkSize: 64,
    resultWindowSize: 25,
    memoryBudgetBytes: 1,
  });

  assert.equal(largeSummary.blocked, false);
  assert.equal(largeSummary.totalRequests, 260);
  assert.equal(largeSummary.results.length, 25);
  assert.equal(largeSummary.payloadPlanCount, 260);
  assert.equal(largeSummary.streaming.chunkSize, 64);
  assert.equal(largeSummary.streaming.chunkCount, 5);
  assert.equal(largeSummary.streaming.completedChunks, 5);
  assert.equal(largeSummary.streaming.retainedResultCount, 25);
  assert.equal(largeSummary.streaming.droppedResultCount, 235);
  assert.equal(largeSummary.streaming.firstRetainedOffset, 235);
  assert.equal(largeSummary.streaming.lastRetainedOffset, 259);
  assert.equal(largeSummary.streaming.memoryPressure, 'high');
  assert.equal(seen.length - seenBeforeLargeRun, 260);
  assert.equal(largeSummary.results[0].payload, 'scale-235');
  assert.equal(largeSummary.results.at(-1).payload, 'scale-259');
  assert(largeSummary.results.at(-1).grepMatches.includes('scale-259'));
  assert.match(largeSummary.message, /260 payload requests sent/);

  maxActiveRequests = 0;
  const concurrentPayloads = Array.from({ length: 80 }, (_unused, index) => `burst-${index}`);
  const seenBeforeConcurrentRun = seen.length;
  const concurrentRawRequest = [
    'GET /burst?item=§item§ HTTP/1.1',
    `Host: 127.0.0.1:${upstreamPort}`,
    'Connection: close',
    '',
    '',
  ].join('\r\n');
  const concurrentSummary = await proxy.runIntruderAttack({
    rawRequest: concurrentRawRequest,
    targetUrl: `http://127.0.0.1:${upstreamPort}/burst?item=seed`,
    payloads: concurrentPayloads,
    scopeAllowlist: ['127.0.0.1'],
    throttleMs: 0,
    grepTerms: ['burst-79'],
    streamChunkSize: 20,
    resultWindowSize: 10,
    memoryBudgetBytes: 4096,
    resourcePoolName: 'Concurrent regression pool',
    resourcePoolMaxConcurrent: 5,
  });

  assert.equal(concurrentSummary.blocked, false);
  assert.equal(concurrentSummary.totalRequests, 80);
  assert.equal(seen.length - seenBeforeConcurrentRun, 80);
  assert.equal(concurrentSummary.streaming.maxConcurrency, 5);
  assert.equal(concurrentSummary.streaming.maxInFlight, 5);
  assert.equal(concurrentSummary.streaming.chunkCount, 4);
  assert.equal(concurrentSummary.streaming.retainedResultCount, 10);
  assert.equal(concurrentSummary.streaming.droppedResultCount, 70);
  assert(concurrentSummary.streaming.durationMs > 0);
  assert(concurrentSummary.streaming.requestRatePerSecond > 0);
  assert(maxActiveRequests > 1, `expected concurrent upstream requests, saw ${maxActiveRequests}`);
  assert(maxActiveRequests <= 5, `resource pool should cap concurrency at 5, saw ${maxActiveRequests}`);
  assert.equal(concurrentSummary.results.at(-1).payload, 'burst-79');
  assert(concurrentSummary.results.at(-1).grepMatches.includes('burst-79'));

  const liveTargetProfilePackage = buildIntruderLiveTargetProfilePackage({
    summaries: [
      summary,
      checkpointSummary,
      resumedSummary,
      bodyTransformSummary,
      clusterSummary,
      largeSummary,
      concurrentSummary,
    ],
    attackModeMatrix: advancedTransformMatrix,
    checkpointPackage,
    analysisPackage,
  });
  assert.equal(liveTargetProfilePackage.kind, 'proxyforge-intruder-live-target-profile-package');
  assert.equal(liveTargetProfilePackage.requirements.liveTargetDiversityCovered, true);
  assert.equal(liveTargetProfilePackage.requirements.attackModeDiversityCovered, true);
  assert.equal(liveTargetProfilePackage.requirements.highVolumeStreamingCovered, true);
  assert.equal(liveTargetProfilePackage.requirements.resourcePoolConcurrencyCovered, true);
  assert.equal(liveTargetProfilePackage.requirements.checkpointResumeCovered, true);
  assert.equal(liveTargetProfilePackage.requirements.grepExtractTriageCovered, true);
  assert.equal(liveTargetProfilePackage.requirements.authzDifferentialCovered, true);
  assert.equal(liveTargetProfilePackage.requirements.payloadTransformCoverageCovered, true);
  assert.equal(liveTargetProfilePackage.requirements.packageRefreshCovered, true);
  assert.equal(liveTargetProfilePackage.requirements.rawExecutorMaterialPreserved, true);
  assert.equal(liveTargetProfilePackage.requirements.operationalSecretsPreserved, true);
  assert.equal(liveTargetProfilePackage.reportRedactionBoundary, 'redact-only-during-report-export');
  assert(liveTargetProfilePackage.statusClasses.includes('2xx'));
  assert(liveTargetProfilePackage.statusClasses.includes('4xx'));
  assert(liveTargetProfilePackage.targetUrlCount >= 3);
  assert(liveTargetProfilePackage.totalRequestsSent >= 350);
  assert(liveTargetProfilePackage.maxInFlight >= 5);
  assert(liveTargetProfilePackage.packageRefreshProof.linkedPackageKinds.includes('proxyforge-intruder-attack-mode-matrix'));
  assert(liveTargetProfilePackage.packageRefreshProof.linkedPackageKinds.includes('proxyforge-intruder-checkpoint-resume-package'));
  assert(liveTargetProfilePackage.packageRefreshProof.linkedPackageKinds.includes('proxyforge-intruder-grep-extract-comparison-package'));
  assert(liveTargetProfilePackage.operationalSecretSignals.includes('authorization-header'));
  assert(liveTargetProfilePackage.operationalSecretSignals.includes('cookie-header'));
  assert(liveTargetProfilePackage.operationalSecretSignals.includes('x-api-key-header'));
  assert.match(liveTargetProfilePackage.content, /intruder-regression-token|intruder-analysis-token|redact-only-during-report-export/);
  await fs.writeFile(path.join(tempDir, 'intruder-live-target-profile-package.json'), JSON.stringify(liveTargetProfilePackage, null, 2), 'utf8');

  await close(upstream);
} finally {
  // Keep generated certs under ignored .gitignored/ for post-run inspection.
}

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return server.address().port;
}

async function close(server) {
  await new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}
