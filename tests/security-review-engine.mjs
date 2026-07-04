import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

const expectedExports = [
  'buildReleaseSecurityReviewPackage',
  'evaluateReleaseSecurityReview',
  'redactSecurityReviewText',
];

const enginePath = path.resolve('src/securityReviewEngine.ts');
const securityReviewEngine = normalizeModuleExports(await loadEngine(enginePath));
const missingExports = expectedExports.filter((name) => typeof securityReviewEngine[name] !== 'function');
if (missingExports.length) {
  console.log(`security-review-engine: skipped; missing export(s): ${missingExports.join(', ')}`);
  process.exit(0);
}

const passingReview = securityReviewEngine.buildReleaseSecurityReviewPackage({
  projectName: 'ProxyForge',
  generatedAt: '2026-05-24T23:30:00.000Z',
  safetyPolicy: {
    requireScopeMatch: true,
    auditLogging: true,
    redactAuditSecrets: true,
    minThrottleMs: 100,
    maxRequestsPerRun: 50,
  },
  localListeners: [
    {
      id: 'proxy-listener',
      name: 'Desktop proxy listener',
      mode: 'desktop-proxy',
      host: '127.0.0.1',
      port: 8080,
      protocols: ['http', 'connect', 'websocket'],
      enabled: true,
    },
    {
      id: 'callback-http',
      name: 'Local callback HTTP listener',
      mode: 'local-http',
      host: 'localhost',
      port: 8099,
      protocols: ['http'],
      retentionHours: 24,
      signingKeyId: 'callback-local-signing-key',
      enabled: true,
    },
  ],
  secretSurfaces: [
    {
      id: 'ai-openai',
      name: 'OpenAI-compatible provider',
      source: 'ai-provider',
      valuePreview: 'Authorization: Bearer [redacted]',
      redacted: true,
      persisted: false,
    },
    {
      id: 'report-bundle',
      name: 'Report signing secret',
      source: 'report-signing',
      valuePreview: 'signing_secret=[redacted]',
      redacted: true,
      persisted: false,
    },
  ],
  exploitControls: [
    {
      id: 'exploit-lab-runner',
      name: 'Exploit Lab runner',
      approvalRequired: true,
      scopeGate: true,
      rateLimit: true,
      stopCondition: true,
      nonDestructiveDefault: true,
      operatorRole: 'lead',
    },
  ],
  signedTrustSurfaces: [
    {
      id: 'extensions',
      name: 'Extension package trust',
      signatureStatus: 'verified',
      trustPolicy: 'deny-unsigned',
    },
  ],
  agentControls: [
    {
      id: 'proxyforge-agent',
      name: 'Codex Claude Vantix agent CLI',
      commandCount: 46,
      requiredCommands: ['status', 'search-index', 'proxy-import', 'crawl-run', 'content-discovery-plan', 'content-discovery-run', 'target-access-review', 'target-map-compare', 'mitm-start', 'intruder-run', 'repeater-race-run', 'extension-fixtures', 'callback-relay-soak', 'callback-retention-prune', 'report-export'],
      implementedCommands: ['status', 'search-index', 'proxy-import', 'crawl-run', 'content-discovery-plan', 'content-discovery-run', 'target-access-review', 'target-map-compare', 'mitm-start', 'intruder-run', 'repeater-race-run', 'extension-fixtures', 'callback-relay-soak', 'callback-retention-prune', 'report-export'],
      preservesOperationalSecrets: true,
      reportPhaseRedaction: true,
      scopeGate: true,
      approvalGate: true,
      writesOperationalArtifacts: true,
      packagedEntryPoint: true,
      externalCwdProof: true,
    },
  ],
  platformPins: [
    {
      id: 'windows-trust-runner-browser-trust',
      name: 'Windows trusted CA browser routing',
      platform: 'windows',
      lane: 'browser-trust-store',
      status: 'pinned',
      nonBlocking: true,
      reason: 'windows-trust-runner rejects temporary CurrentUser Root store mutation with ERROR_NOT_SUPPORTED.',
      evidence: ['7 passed checks', '1 blocked trust-store check', '0 failed checks'],
    },
  ],
  productionGates: [
    {
      id: 'release-production-gate',
      name: 'Release readiness CI and operator docs',
      fastSuitePassed: true,
      fullSuitePlanValidated: true,
      nightlyWorkflowScheduled: true,
      artifactUploadPolicy: true,
      coverageOwners: true,
      zeroFlakeBudget: true,
      operatorGuidePackaged: true,
      installGuideLinked: true,
      releaseEvidenceLinked: true,
      securityReviewRequired: true,
      retentionDays: 30,
    },
  ],
  artifactPaths: [
    'test-results/ci-full-suite-summary.json',
    'release/ProxyForge.AppImage',
    '.gitignored/local-scratch',
  ],
});

assert.equal(passingReview.kind, 'proxyforge-release-security-review');
assert.equal(passingReview.status, 'pass');
assert.equal(passingReview.failedCount, 0);
assert.ok(passingReview.findings.length >= 9, 'review should cover policy, listeners, secrets, exploit controls, trust, production gates, and artifacts');
assert.match(passingReview.releaseGate, /passed/i);
assert.match(passingReview.content, /Desktop proxy listener|Exploit Lab runner|Release Security Review/);
assert.match(passingReview.content, /search-index|proxy-import|externalCwdProof=true|platform-pin|agent-control|ERROR_NOT_SUPPORTED/i);
assert.match(passingReview.content, /production-gate|nightlyWorkflowScheduled=true|operatorGuidePackaged=true|retentionDays=30/i);
assert.doesNotMatch(passingReview.content, /sk-live|real-secret|retail-support-preview/);

const failingFindings = securityReviewEngine.evaluateReleaseSecurityReview({
  projectName: 'ProxyForge Unsafe',
  safetyPolicy: {
    requireScopeMatch: false,
    auditLogging: true,
    redactAuditSecrets: false,
    minThrottleMs: 0,
    maxRequestsPerRun: 5000,
  },
  localListeners: [
    {
      id: 'public-callback',
      name: 'Public callback listener',
      mode: 'public-relay',
      host: '0.0.0.0',
      port: 80,
      protocols: ['http'],
      enabled: true,
    },
  ],
  secretSurfaces: [
    {
      id: 'raw-key',
      name: 'Raw provider key',
      source: 'ai-provider',
      valuePreview: 'Authorization: Bearer sk-live-real-secret-token',
      redacted: false,
      persisted: true,
    },
  ],
  exploitControls: [
    {
      id: 'unsafe-exploit',
      name: 'Unsafe exploit runner',
      approvalRequired: false,
      scopeGate: false,
      rateLimit: false,
      stopCondition: false,
      nonDestructiveDefault: false,
    },
  ],
  agentControls: [
    {
      id: 'agent-gap',
      name: 'Agent CLI gap',
      commandCount: 2,
      requiredCommands: ['status', 'search-index', 'exploit-run'],
      implementedCommands: ['status'],
      preservesOperationalSecrets: false,
      reportPhaseRedaction: false,
      scopeGate: false,
      approvalGate: false,
      writesOperationalArtifacts: false,
      packagedEntryPoint: false,
      externalCwdProof: false,
    },
  ],
  platformPins: [
    {
      id: 'windows-trust-untracked',
      name: 'Windows trust lane',
      platform: 'windows',
      lane: 'browser-trust-store',
      status: 'blocked',
      nonBlocking: false,
      reason: '',
      evidence: [],
    },
  ],
  productionGates: [
    {
      id: 'production-gate-gap',
      name: 'Missing production release gate',
      fastSuitePassed: false,
      fullSuitePlanValidated: false,
      nightlyWorkflowScheduled: false,
      artifactUploadPolicy: false,
      coverageOwners: false,
      zeroFlakeBudget: false,
      operatorGuidePackaged: false,
      installGuideLinked: false,
      releaseEvidenceLinked: false,
      securityReviewRequired: false,
      retentionDays: 7,
    },
  ],
});

assert.ok(failingFindings.some((finding) => finding.status === 'fail' && finding.category === 'safety-policy'));
assert.ok(failingFindings.some((finding) => finding.status === 'fail' && finding.category === 'local-listener'));
assert.ok(failingFindings.some((finding) => finding.status === 'fail' && finding.category === 'secret-redaction'));
assert.ok(failingFindings.some((finding) => finding.status === 'fail' && finding.category === 'exploit-control'));
assert.ok(failingFindings.some((finding) => finding.status === 'fail' && finding.category === 'agent-control'));
assert.ok(failingFindings.some((finding) => finding.status === 'fail' && finding.category === 'platform-pin'));
assert.ok(failingFindings.some((finding) => finding.status === 'fail' && finding.category === 'production-gate'));
assert.doesNotMatch(JSON.stringify(failingFindings), /sk-live-real-secret-token/);
assert.match(JSON.stringify(failingFindings), /\[redacted\]/);

const redacted = securityReviewEngine.redactSecurityReviewText('Cookie: session=abc123\napi_key=real-secret');
assert.equal(redacted, 'Cookie: [redacted]\napi_key=[redacted]');

console.log(`security-review-engine: exercised ${passingReview.findingCount} release security review finding(s)`);

async function loadEngine(filePath) {
  const source = await fs.readFile(filePath, 'utf8');
  const transpiled = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
      esModuleInterop: true,
    },
    fileName: filePath,
  }).outputText;
  const module = { exports: {} };
  const sandbox = {
    module,
    exports: module.exports,
    TextDecoder,
    TextEncoder,
    console,
    require,
  };
  vm.runInNewContext(transpiled, sandbox, { filename: filePath });
  return module.exports;
}

function normalizeModuleExports(moduleExports) {
  const hasNamedHelper = expectedExports.some((name) => typeof moduleExports[name] === 'function');
  if (hasNamedHelper) return moduleExports;
  if (moduleExports.default && typeof moduleExports.default === 'object') return moduleExports.default;
  return moduleExports;
}
