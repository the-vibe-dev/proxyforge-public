import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

const enginePath = path.resolve('src/scannerRetestEngine.ts');
const scannerRetestEngine = await loadEngine(enginePath);

assert.equal(typeof scannerRetestEngine.buildScannerRetestWorkflow, 'function');
assert.equal(typeof scannerRetestEngine.buildScannerRetestEvidenceDeltaPackage, 'function');

const issue = {
  id: 'issue-refund-authz',
  title: 'Refund authorization boundary can regress after remediation',
  severity: 'high',
  host: 'app.shop.local',
  path: '/api/refunds',
  confidence: 'firm',
  status: 'fixed',
  detail: 'Support-state replay previously approved refunds with the same customer body.',
  remediation: 'Enforce refund authorization server-side for every authenticated state.',
};

const baselineExchange = exchange({
  id: 'hx-refund-baseline-vulnerable',
  status: 200,
  responseRaw: [
    'HTTP/2 200 OK',
    'Content-Type: application/json',
    '',
    '{"status":"approved","role":"support_admin","refundId":"rf_1001"}',
  ].join('\n'),
  notes: 'Original scanner proof showed support-state refund approval.',
  tags: ['scanner', 'active-scan', 'authz-diff', 'original-proof'],
});
const fixedRetestExchange = exchange({
  id: 'hx-refund-retest-fixed',
  status: 403,
  responseRaw: [
    'HTTP/2 403 Forbidden',
    'Content-Type: application/json',
    '',
    '{"error":"missing_permission","fixed":true,"retest":"remediation validated"}',
  ].join('\n'),
  notes: 'Remediation retest denies the refund path.',
  tags: ['scanner-retest', 'retest:fixed'],
});
const regressedRetestExchange = exchange({
  id: 'hx-refund-retest-regressed',
  status: 200,
  responseRaw: [
    'HTTP/2 200 OK',
    'Content-Type: application/json',
    '',
    '{"status":"approved","role":"support_admin","refundId":"rf_2002","retest":"finding returned"}',
  ].join('\n'),
  notes: 'Previously fixed refund authorization issue reproduced.',
  tags: ['scanner-retest', 'retest:regressed', 'authz-diff'],
});
const inconclusiveRetestExchange = exchange({
  id: 'hx-refund-retest-inconclusive',
  status: 502,
  responseRaw: 'HTTP/2 502 Bad Gateway\nContent-Type: text/plain\n\nupstream error during retest',
  notes: 'Transport failed during retest.',
  tags: ['scanner-retest', 'retest:inconclusive'],
});

const fixedWorkflow = scannerRetestEngine.buildScannerRetestWorkflow({
  issue: { ...issue, status: 'open' },
  baselineExchange,
  retestExchange: fixedRetestExchange,
  checkIds: ['authz-diff'],
  now: '2026-05-25T16:00:00.000Z',
});
const stillVulnerableWorkflow = scannerRetestEngine.buildScannerRetestWorkflow({
  issue: { ...issue, status: 'open' },
  baselineExchange,
  retestExchange: baselineExchange,
  checkIds: ['authz-diff'],
  outcomeOverride: 'still-vulnerable',
  now: '2026-05-25T16:01:00.000Z',
});
const inconclusiveWorkflow = scannerRetestEngine.buildScannerRetestWorkflow({
  issue,
  baselineExchange,
  retestExchange: inconclusiveRetestExchange,
  checkIds: ['authz-diff'],
  now: '2026-05-25T16:02:00.000Z',
});

const packageResult = scannerRetestEngine.buildScannerRetestEvidenceDeltaPackage({
  issue,
  baselineExchange,
  retestExchange: regressedRetestExchange,
  previousRetests: [fixedWorkflow, stillVulnerableWorkflow, inconclusiveWorkflow],
  evidenceDeltas: [
    {
      id: 'scanner-delta-fixed-prior',
      title: 'Prior fixed retest delta',
      fileName: 'prior-fixed.json',
      path: 'reports/prior-fixed.json',
      createdAt: '2026-05-25T16:00:00.000Z',
      issueId: issue.id,
      issueTitle: issue.title,
      host: issue.host,
      issuePath: issue.path,
      outcome: 'fixed',
      baselineStatus: 'open',
      retestStatus: 'fixed',
      severity: 'high',
      confidence: 'firm',
      baselineExchangeId: baselineExchange.id,
      retestExchangeId: fixedRetestExchange.id,
      ruleIds: ['scanner-rule-authz'],
      reportReady: true,
      signature: {
        algorithm: 'HMAC-SHA256',
        signerName: 'ProxyForge scanner verifier',
        keyId: 'scanner-local',
        status: 'signed',
        digestPreview: 'priorfixed',
      },
      summary: 'Prior fixed evidence delta.',
      content: '{}',
    },
  ],
  checkIds: ['authz-diff', 'method-options', 'jwt-claims'],
  checkPackId: 'auth-state',
  scopeAllowlist: ['app.shop.local'],
  throttleMs: 0,
  maxRequests: 12,
  sessionProfileName: 'Support remediation profile',
  operator: 'ProxyForge QA',
  runnerPolicyId: 'scanner-retest-policy',
  requestEdits: [
    {
      field: 'Authorization',
      before: 'Bearer customer-token',
      after: 'Bearer support-token',
      reason: 'Replay the original proof with the authorized remediation verification account.',
    },
  ],
  now: '2026-05-25T16:03:00.000Z',
});

assert.equal(packageResult.kind, 'proxyforge-scanner-retest-evidence-delta-package');
assert.equal(packageResult.workflow.outcome, 'regressed');
assert.equal(packageResult.comparison.evidenceDelta, 'regressed');
assert.equal(packageResult.secretHandling, 'execution-full-fidelity-secrets-preserved');
assert.equal(packageResult.reportRedactionBoundary, 'redact-only-during-report-export');
assert.equal(packageResult.requirements.issueLinked, true);
assert.equal(packageResult.requirements.baselineExchangePreserved, true);
assert.equal(packageResult.requirements.retestExchangePreserved, true);
assert.equal(packageResult.requirements.originalProofReplayed, true);
assert.equal(packageResult.requirements.outcomeClassified, true);
assert.equal(packageResult.requirements.fixedRegressedStillVulnerableInconclusiveCovered, true);
assert.equal(packageResult.requirements.runnerControlsPreserved, true);
assert.equal(packageResult.requirements.requestEditsPreserved, true);
assert.equal(packageResult.requirements.evidenceDeltaComputed, true);
assert.equal(packageResult.requirements.reportAttachmentsLinked, true);
assert.equal(packageResult.requirements.operationalSecretsPreserved, true);
assert.equal(packageResult.requirements.reportPhaseOnlyRedaction, true);
assert.equal(packageResult.outcomeCoverage.fixed, 1);
assert.equal(packageResult.outcomeCoverage.regressed, 1);
assert.equal(packageResult.outcomeCoverage['still-vulnerable'], 1);
assert.equal(packageResult.outcomeCoverage.inconclusive, 1);
assert(packageResult.operationalSecretSignals.includes('authorization-header'));
assert(packageResult.operationalSecretSignals.includes('cookie-header'));
assert(packageResult.operationalSecretSignals.includes('x-api-key-header'));
assert(packageResult.operationalSecretSignals.includes('idempotency-key-header'));
assert.match(
  packageResult.content,
  /Bearer support-token|session=scanner-retest-session|scanner-retest-api-key|Idempotency-Key|reportPhaseOnlyRedaction|priorEvidenceDeltaIds/i,
);

const artifactDir = path.resolve('.gitignored/test-artifacts/scanner-retest-engine');
await fs.mkdir(artifactDir, { recursive: true });
await fs.writeFile(
  path.join(artifactDir, 'scanner-retest-evidence-delta-package.json'),
  JSON.stringify(packageResult, null, 2),
  'utf8',
);

console.log('scanner-retest-engine: built report-ready Scanner retest evidence delta package with fixed/regressed/still-vulnerable/inconclusive coverage');

async function loadEngine(resolvedPath) {
  const source = await fs.readFile(resolvedPath, 'utf8');
  const transpiled = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
      esModuleInterop: true,
    },
    fileName: resolvedPath,
  }).outputText;
  const module = { exports: {} };
  const sandbox = {
    module,
    exports: module.exports,
    TextDecoder,
    TextEncoder,
    URL,
    URLSearchParams,
    Buffer,
    console,
    crypto: globalThis.crypto,
    setTimeout,
    clearTimeout,
    require,
  };
  vm.runInNewContext(transpiled, sandbox, { filename: resolvedPath });
  return module.exports;
}

function exchange(overrides) {
  return {
    id: overrides.id,
    method: 'POST',
    host: 'app.shop.local',
    path: '/api/refunds',
    url: 'https://app.shop.local/api/refunds',
    status: overrides.status,
    length: overrides.responseRaw.length,
    mime: 'application/json',
    risk: 'high',
    timing: 120,
    source: 'scanner',
    time: '16:03:00',
    requestRaw: [
      'POST /api/refunds HTTP/2',
      'Host: app.shop.local',
      'Authorization: Bearer support-token',
      'Cookie: session=scanner-retest-session',
      'X-API-Key: scanner-retest-api-key',
      'Idempotency-Key: scanner-retest-001',
      'Content-Type: application/json',
      '',
      '{"orderId":"ord_90210","amount":7900}',
    ].join('\n'),
    responseRaw: overrides.responseRaw,
    notes: overrides.notes,
    tags: overrides.tags,
  };
}
