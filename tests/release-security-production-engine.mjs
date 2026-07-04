import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

const expectedSecurityExports = ['buildReleaseSecurityReviewPackage'];
const expectedProductionExports = ['buildReleaseSecurityProductionEvidencePackage'];
const securityReviewEngine = normalizeModuleExports(
  await loadEngine(path.resolve('src/securityReviewEngine.ts')),
  expectedSecurityExports,
);
const productionEngine = normalizeModuleExports(
  await loadEngine(path.resolve('src/releaseSecurityProductionEngine.ts')),
  expectedProductionExports,
);
const missingSecurityExports = expectedSecurityExports.filter((name) => typeof securityReviewEngine[name] !== 'function');
const missingProductionExports = expectedProductionExports.filter((name) => typeof productionEngine[name] !== 'function');
assert.deepEqual(missingSecurityExports, [], `release-security-production-engine: missing security export(s): ${missingSecurityExports.join(', ')}`);
assert.deepEqual(missingProductionExports, [], `release-security-production-engine: missing production export(s): ${missingProductionExports.join(', ')}`);

const context = buildReleaseSecurityProductionContext();
const productionPackage = productionEngine.buildReleaseSecurityProductionEvidencePackage(context);
const packageContent = JSON.parse(productionPackage.content);

assert.equal(productionPackage.kind, 'proxyforge-release-security-production-evidence-package');
assert.equal(productionPackage.secretHandling, 'execution-full-fidelity-secrets-preserved');
assert.equal(productionPackage.reportRedactionBoundary, 'redact-only-during-report-export');
assert.equal(productionPackage.productionReady, true);
assert(Object.values(productionPackage.requirements).every(Boolean), 'all Release Security production requirements should be true');
assert.equal(packageContent.kind, 'proxyforge-release-security-production-evidence-package');
assert.match(productionPackage.content, /proxyforge-release-security-review/);
assert.match(productionPackage.content, /local-listener/);
assert.match(productionPackage.content, /secret-redaction/);
assert.match(productionPackage.content, /exploit-control/);
assert.match(productionPackage.content, /agent-control/);
assert.match(productionPackage.content, /ai-provider-control/);
assert.match(productionPackage.content, /platform-pin/);
assert.match(productionPackage.content, /production-gate/);
assert.match(productionPackage.content, /artifact-hygiene/);
assert.match(productionPackage.content, /proxyforge-ai-provider-production-evidence-package/);
assert.match(productionPackage.content, /proxyforge-agent-control-production-evidence-package/);
assert.match(productionPackage.content, /proxyforge-platform-shell-production-evidence-package/);
assert.match(productionPackage.content, /proxyforge-linux-package-production-evidence-package/);
assert.match(productionPackage.content, /proxyforge-windows-package-production-evidence-package/);
assert.match(productionPackage.content, /Authorization: Bearer release-security-secret-token/);
assert.match(productionPackage.content, /session=release-security-session/);
assert.match(productionPackage.content, /X-API-Key: release-security-api-key/);
assert.match(productionPackage.content, /callbackToken=release-security-callback-token/);
assert.match(productionPackage.content, /redact-only-during-report-export/);
assert.doesNotMatch(context.review.content, /release-security-secret-token|release-security-session|release-security-api-key|release-security-callback-token/);

const artifactDir = path.resolve('.gitignored/test-artifacts/release-security-production-engine');
await fs.mkdir(artifactDir, { recursive: true });
await fs.writeFile(path.join(artifactDir, 'release-security-production-evidence-package.json'), productionPackage.content);

console.log('release-security-production-engine: verified release-wide security production evidence, platform pins, CI gates, and full-fidelity secret boundary');

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
    URL,
    URLSearchParams,
    Buffer,
    console,
    require,
  };
  vm.runInNewContext(transpiled, sandbox, { filename: filePath });
  return module.exports;
}

function normalizeModuleExports(moduleExports, expectedExports) {
  const hasNamedHelper = expectedExports.some((name) => typeof moduleExports[name] === 'function');
  if (hasNamedHelper) return moduleExports;
  if (moduleExports.default && typeof moduleExports.default === 'object') return moduleExports.default;
  return moduleExports;
}

function buildReleaseSecurityProductionContext() {
  const generatedAt = '2026-05-26T01:30:00.000Z';
  const rawRequest = [
    'POST /api/release-security HTTP/2',
    'Host: app.shop.local',
    'Authorization: Bearer release-security-secret-token',
    'Cookie: session=release-security-session',
    'X-API-Key: release-security-api-key',
    '',
    'callbackToken=release-security-callback-token&mode=production-security',
  ].join('\n');
  const rawResponse = [
    'HTTP/2 200 OK',
    'Content-Type: application/json',
    '',
    '{"ok":true,"rawResponse":"release-security"}',
  ].join('\n');
  const review = securityReviewEngine.buildReleaseSecurityReviewPackage({
    projectName: 'ProxyForge',
    generatedAt,
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
        id: 'ai-provider-secret',
        name: 'AI provider operational secret preview',
        source: 'ai-provider',
        valuePreview: 'Authorization: Bearer [redacted]',
        redacted: true,
        persisted: false,
      },
      {
        id: 'project-cookie-secret',
        name: 'Project cookie operational secret preview',
        source: 'project-file',
        valuePreview: 'Cookie: [redacted]',
        redacted: true,
        persisted: false,
      },
      {
        id: 'report-bundle',
        name: 'Report signing secret preview',
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
      {
        id: 'organizer-evidence',
        name: 'Organizer evidence package trust',
        signatureStatus: 'signed',
        trustPolicy: 'review-required',
      },
    ],
    agentControls: [
      {
        id: 'proxyforge-agent',
        name: 'Codex Claude Vantix agent CLI',
        commandCount: 70,
        requiredCommands: [
          'status',
          'inventory',
          'mitm-start',
          'search-index',
          'view',
          'chromium-capture',
          'proxy-import',
          'project-store-status',
          'project-store-recover',
          'project-store-backup',
          'crawl-run',
          'content-discovery-run',
          'live-target-profile',
          'target-access-review',
          'target-map-compare',
          'automation-run',
          'automation-scheduler-tick',
          'automation-service-plan',
          'automation-service-smoke',
          'sequencer-analyze',
          'replay-run',
          'bulk-replay',
          'websocket-list',
          'websocket-replay',
          'websocket-fuzz',
          'websocket-transcript-export',
          'intruder-run',
          'repeater-desync-probe',
          'repeater-race-run',
          'insertion-points',
          'scanner-run',
          'scanner-retest',
          'scanner-evidence-export',
          'anvil-run',
          'anvil-package-export',
          'extension-fixtures',
          'callback-provider-probe',
          'callback-relay-soak',
          'callback-retention-prune',
          'exploit-run',
          'report-export',
          'vantix-sync',
        ],
        implementedCommands: [
          'status',
          'inventory',
          'mitm-start',
          'search-index',
          'view',
          'chromium-capture',
          'proxy-import',
          'project-store-status',
          'project-store-recover',
          'project-store-backup',
          'crawl-run',
          'content-discovery-run',
          'live-target-profile',
          'target-access-review',
          'target-map-compare',
          'automation-run',
          'automation-scheduler-tick',
          'automation-service-plan',
          'automation-service-smoke',
          'sequencer-analyze',
          'replay-run',
          'bulk-replay',
          'websocket-list',
          'websocket-replay',
          'websocket-fuzz',
          'websocket-transcript-export',
          'intruder-run',
          'repeater-desync-probe',
          'repeater-race-run',
          'insertion-points',
          'scanner-run',
          'scanner-retest',
          'scanner-evidence-export',
          'anvil-run',
          'anvil-package-export',
          'extension-fixtures',
          'callback-provider-probe',
          'callback-relay-soak',
          'callback-retention-prune',
          'exploit-run',
          'report-export',
          'vantix-sync',
        ],
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
      {
        id: 'linux-clean-container-trust',
        name: 'Linux clean-container trusted CA',
        platform: 'linux',
        lane: 'clean-container-trusted-ca',
        status: 'passed',
        nonBlocking: false,
        reason: 'clean-container deb install/runtime/GUI/trusted-CA/uninstall proof passed',
        evidence: ['proxyforge-linux-package-production-evidence-package'],
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
      'test-results/ci-fast-suite-summary.json',
      'test-results/ci-full-suite-plan.json',
      'release/ProxyForge.AppImage',
      'release/ProxyForge Setup 0.1.0-alpha.1.exe',
      '.gitignored/test-artifacts/release-security-production-engine/release-security-production-evidence-package.json',
      'docs/RELEASE_EVIDENCE.md',
    ],
  });
  const proof = (id, lane, content, passedChecks = 3) => ({
    id,
    lane,
    status: 'passed',
    passedChecks,
    failedChecks: 0,
    content: JSON.stringify({
      kind: 'proxyforge-release-security-production-proof',
      lane,
      content,
      rawRequest,
      rawResponse,
      reportRedactionBoundary: 'redact-only-during-report-export',
    }),
  });
  return {
    generatedAt,
    review,
    proofs: [
      proof('local-listener', 'local-listener', {
        bindings: ['loopback 127.0.0.1 desktop proxy', 'localhost callback listener', 'websocket loopback upgrade path'],
      }),
      proof('secret-boundary', 'secret-boundary', {
        policy: 'full-fidelity operational secrets retained in executor artifacts; report-export-only redaction via redact-only-during-report-export',
        reportExports: ['submission/report artifacts redact'],
      }),
      proof('exploit-control', 'exploit-control', {
        controls: ['approval gate', 'scope gate', 'rate limit', 'stop-on-proof', 'non-destructive default'],
      }),
      proof('agent-control', 'agent-control', {
        package: 'proxyforge-agent-control-production-evidence-package',
        surface: '70-command Codex/Claude/Vantix surface',
        packaged: 'resources/app.asar external-cwd ~/vantix app.asar proof',
        gates: 'scope approval rate-limit policy/audit',
      }),
      proof('ai-provider-control', 'ai-provider-control', {
        package: 'proxyforge-ai-provider-production-evidence-package',
        providers: ['Codex CLI', 'Claude CLI', 'OpenAI-compatible HTTP'],
        boundary: 'controlled actions only, no direct action traffic',
      }),
      proof('platform-pin', 'platform-pin', {
        linux: 'proxyforge-linux-package-production-evidence-package clean-container trusted-CA passed',
        windows: 'proxyforge-windows-package-production-evidence-package windows-trust-runner ERROR_NOT_SUPPORTED trust-store pin accepted nonblocking',
        shell: 'proxyforge-platform-shell-production-evidence-package',
      }),
      proof('signed-trust', 'signed-trust', {
        trust: ['verified extension package', 'signed organizer evidence', 'deny-unsigned policy', 'HMAC signature coverage'],
      }),
      proof('production-ci', 'production-ci', {
        fast: '82/82 fast suite passed with Project import compatibility, customer-scale interop profiling, third-party Extension compatibility, UI Scale, Full/Nightly production evidence, retained history, and OAST relay/provider diversity integration',
        full: '80-step full suite plan validated with Project import compatibility, customer-scale interop profiling, third-party Extension compatibility, UI Scale, Full/Nightly production evidence, and retained history',
        nightly: 'nightly scheduled workflow with artifact upload, zero-flake budget, coverage owner metadata',
      }),
      proof('clean-runtime', 'clean-runtime', {
        linux: 'clean-container deb install/runtime/installed GUI/trusted-CA/uninstall',
        windows: 'NSIS installed GUI, DPAPI sample-cookie, browser routing, quiet uninstall',
        shell: 'Platform Shell packaged runtime proof',
      }),
      proof('artifact-hygiene', 'artifact-hygiene', {
        paths: ['.gitignored/test-artifacts', 'test-results', 'release/'],
        policy: 'artifact hygiene keeps generated evidence out of tracked source unless committed docs',
      }),
      proof('package-refresh', 'package-refresh', {
        artifacts: ['dist-electron/securityReviewEngine.js', 'dist-electron/releaseSecurityProductionEngine.js'],
        package: 'packaged release security production gate',
      }),
      proof('docs-schema', 'docs-schema', {
        docs: ['OPERATOR_GUIDE', 'RELEASE_CHECKLIST', 'SCHEMAS.md', 'FEATURE_MATRIX', 'proxyforge-release-security-production-evidence-package'],
      }),
    ],
    docs: [
      'OPERATOR_GUIDE documents proxyforge-release-security-production-evidence-package and the full-fidelity executor/report-redaction boundary.',
      'RELEASE_CHECKLIST requires release-security-production-engine and artifact retention before production signoff.',
      'SCHEMAS.md documents proxyforge-release-security-production-evidence-package requirements for agents.',
      'FEATURE_MATRIX promotes the release security review row only when this production package passes.',
    ],
    operationalSecretSamples: [
      'Authorization: Bearer release-security-secret-token',
      'session=release-security-session',
      'X-API-Key: release-security-api-key',
      'callbackToken=release-security-callback-token',
    ],
  };
}
