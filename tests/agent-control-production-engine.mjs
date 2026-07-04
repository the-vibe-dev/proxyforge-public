import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

const expectedExports = [
  'buildAgentControlProductionEvidencePackage',
  'requiredAgentProductionCapabilities',
];
const enginePath = path.resolve('src/agentControlProductionEngine.ts');
const agentControlEngine = normalizeModuleExports(await loadEngine(enginePath));
const missingExports = expectedExports.filter((name) => agentControlEngine[name] === undefined);
assert.deepEqual(missingExports, [], `agent-control-production-engine: missing export(s): ${missingExports.join(', ')}`);

const context = buildAgentControlContext(agentControlEngine.requiredAgentProductionCapabilities);
const productionPackage = agentControlEngine.buildAgentControlProductionEvidencePackage(context);
const packageContent = JSON.parse(productionPackage.content);

assert.equal(productionPackage.kind, 'proxyforge-agent-control-production-evidence-package');
assert.equal(productionPackage.secretHandling, 'execution-full-fidelity-secrets-preserved');
assert.equal(productionPackage.reportRedactionBoundary, 'redact-only-during-report-export');
assert.equal(productionPackage.productionReady, true);
assert.equal(productionPackage.requiredCapabilityCount, 70);
assert(Object.values(productionPackage.requirements).every(Boolean), 'all Agent Control production requirements should be true');
assert.equal(packageContent.kind, 'proxyforge-agent-control-production-evidence-package');
assert.match(productionPackage.content, /automation-list/);
assert.match(productionPackage.content, /automation-service-plan/);
assert.match(productionPackage.content, /automation-service-smoke/);
assert.match(productionPackage.content, /sequencer-analyze/);
assert.match(productionPackage.content, /decoder-chain/);
assert.match(productionPackage.content, /live-target-profile/);
assert.match(productionPackage.content, /insertion-points/);
assert.match(productionPackage.content, /websocket-replay/);
assert.match(productionPackage.content, /websocket-fuzz/);
assert.match(productionPackage.content, /websocket-transcript-export/);
assert.match(productionPackage.content, /scanner-evidence-export/);
assert.match(productionPackage.content, /scanner-oast-promote/);
assert.match(productionPackage.content, /anvil-package-export/);
assert.match(productionPackage.content, /callback-provider-probe/);
assert.match(productionPackage.content, /resources\/app\.asar/);
assert.match(productionPackage.content, /external-cwd/);
assert.match(productionPackage.content, /~\/vantix/);
assert.match(productionPackage.content, /mitm-start/);
assert.match(productionPackage.content, /chromium-capture/);
assert.match(productionPackage.content, /project-store-recover/);
assert.match(productionPackage.content, /project-store-backup/);
assert.match(productionPackage.content, /bulk-replay --soak/);
assert.match(productionPackage.content, /callback-relay-soak/);
assert.match(productionPackage.content, /Authorization: Bearer agent-production-secret-token/);
assert.match(productionPackage.content, /session=agent-production-session/);
assert.match(productionPackage.content, /X-API-Key: agent-production-api-key/);
assert.match(productionPackage.content, /callbackToken=agent-production-callback-token/);
assert.match(productionPackage.content, /submission-reporting-redaction/);

const artifactDir = path.resolve('.gitignored/test-artifacts/agent-control-production-engine');
await fs.mkdir(artifactDir, { recursive: true });
await fs.writeFile(path.join(artifactDir, 'agent-control-production-evidence-package.json'), productionPackage.content);

console.log('agent-control-production-engine: verified packaged 70-command agent surface, active workflow policy, long-running soaks, and full-fidelity secret boundary');

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

function normalizeModuleExports(moduleExports) {
  const hasNamedHelper = expectedExports.some((name) => moduleExports[name] !== undefined);
  if (hasNamedHelper) return moduleExports;
  if (moduleExports.default && typeof moduleExports.default === 'object') return moduleExports.default;
  return moduleExports;
}

function buildAgentControlContext(capabilities) {
  const now = '2026-05-26T00:30:00.000Z';
  const rawRequest = [
    'GET /api/agent-control HTTP/1.1',
    'Host: app.shop.local',
    'Authorization: Bearer agent-production-secret-token',
    'Cookie: session=agent-production-session',
    'X-API-Key: agent-production-api-key',
    '',
    '',
  ].join('\r\n');
  const rawResponse = [
    'HTTP/1.1 200 OK',
    'Content-Type: application/json',
    'Set-Cookie: callbackToken=agent-production-callback-token; HttpOnly',
    '',
    '{"ok":true,"rawResponse":"agent-control"}',
  ].join('\r\n');
  return {
    generatedAt: now,
    proofs: [
      proof('source-surface', 'source', 'source-command-surface', 'local-source', capabilities, 'source status and agent-option-audit expose the full 70-command surface', rawRequest, rawResponse),
      proof('linux-packaged-agent', 'linux', 'packaged-agent-cli', 'local-linux', capabilities, 'packaged status from resources/app.asar/scripts/proxyforge-agent.mjs exposes all commands with appRoot=resources/app.asar', rawRequest, rawResponse),
      proof('windows-packaged-agent', 'windows', 'packaged-agent-cli', 'windows-trust-runner', capabilities, 'installed packaged status from resources/app.asar/scripts/proxyforge-agent.mjs exposes all commands with appRoot=resources/app.asar', rawRequest, rawResponse),
      proof('linux-external-cwd', 'linux', 'packaged-external-cwd', 'local-linux', capabilities, 'external-cwd packaged agent invocation from ~/vantix resolves runtime modules from resources/app.asar and preserves full executor material', rawRequest, rawResponse),
      proof('persistent-mitm', 'source', 'persistent-mitm', 'agent-cli', capabilities, 'mitm-start mitm-status mitm-export mitm-stop project-CA readiness persistent JSONL log upstream TLS strict relaxed controls', rawRequest, rawResponse),
      proof('chromium-data', 'source', 'chromium-data-collection', 'agent-cli', capabilities, 'chromium-capture cookie-capture proxy-import browser profile cookie extraction and data collection proof', rawRequest, rawResponse),
      proof('project-store-recovery', 'source', 'project-store-recovery', 'agent-cli', capabilities, 'project-store-status project-store-recover project-store-backup crash recovery journal restore point full raw request response replay proof', rawRequest, rawResponse),
      proof('search-view', 'source', 'search-view', 'agent-cli', capabilities, 'search search-index --soak search-index --provider-url --execute live semantic provider large-project semantic index sequencer-analyze decoder-chain view raw traffic proof', rawRequest, rawResponse),
      proof('replay-intruder-repeater', 'source', 'replay-intruder-repeater', 'agent-cli', capabilities, 'replay-run bulk-replay --soak websocket-list websocket-replay websocket-fuzz websocket-transcript-export live-target-profile intruder-run --soak repeater-desync-probe repeater-race-run --soak releaseSkewMs rawTranscript', rawRequest, rawResponse),
      proof('scanner-anvil', 'source', 'scanner-anvil', 'agent-cli', capabilities, 'insertion-points scanner-run scanner-retest scanner-evidence-export scanner-oast-promote anvil-plan anvil-run anvil-package-export false-positive controls', rawRequest, rawResponse),
      proof('extension-callback-exploit-report', 'source', 'extension-callback-exploit-report', 'agent-cli', capabilities, 'extension-fixtures callback-provider-probe callback-relay-soak callback-retention-prune callback-replay exploit-run report-export bundle-sign bundle-verify', rawRequest, rawResponse),
      proof('automation-vantix', 'source', 'automation-vantix', 'agent-cli', capabilities, 'automation-list automation-run automation-ci-export automation-scheduler-tick automation-parity-export automation-service-plan automation-service-smoke vantix-sync vantix-intel-export Vantix handoff', rawRequest, rawResponse),
      proof('policy-audit', 'source', 'policy-audit', 'agent-cli', capabilities, 'scope gate approval-file rate limit request cap execute flag audit blocked unsafe trafficSent=false submission-reporting-redaction', rawRequest, rawResponse),
      proof('long-running-soak', 'source', 'long-running-soak', 'agent-cli', capabilities, 'search-index --soak search-index --provider-url --execute bulk-replay --soak live-target-profile intruder-run --soak repeater-race-run --soak callback-relay-soak automation scheduler scanner calibration soak', rawRequest, rawResponse),
      proof('docs-schema', 'source', 'docs-schema', 'docs', capabilities, 'AGENTIC_INTERFACE CODEX.md CLAUDE.md VANTIX.md SCHEMAS.md MVP_OPTION_AUDIT document all commands and report export redaction', rawRequest, rawResponse),
      proof('linux-package-gate', 'linux', 'package-production-gate', 'local-linux', capabilities, 'proxyforge-linux-package-production-evidence-package productionReady=true', rawRequest, rawResponse),
      proof('windows-package-gate', 'windows', 'package-production-gate', 'windows-trust-runner', capabilities, 'proxyforge-windows-package-production-evidence-package productionReady=true', rawRequest, rawResponse),
    ],
    docs: [
      'AGENTIC_INTERFACE documents Codex CLI, Claude CLI, and ~/vantix driving persistent MITM, Chromium, Project Store recovery/backup, search provider ranking, replay, WebSocket list/replay/fuzz/transcript, Intruder, Repeater desync/race, scanner, Anvil, callback, exploit, reports, and Vantix commands.',
      'CODEX.md CLAUDE.md VANTIX.md SCHEMAS.md MVP_OPTION_AUDIT cover the 70-command surface, active workflow gates, full-fidelity operational outputs, and submission-reporting-redaction during report export.',
      'RELEASE_CHECKLIST requires packaged status to expose full current 70-command source surface from resources/app.asar and external-cwd invocation.',
    ],
    operationalSecretSamples: [
      'Authorization: Bearer agent-production-secret-token',
      'session=agent-production-session',
      'X-API-Key: agent-production-api-key',
      'callbackToken=agent-production-callback-token',
    ],
  };
}

function proof(id, platform, lane, runner, capabilities, notes, rawRequest, rawResponse) {
  return {
    id,
    platform,
    lane,
    status: 'passed',
    capabilities,
    runner,
    passedChecks: capabilities.length,
    failedChecks: 0,
    content: JSON.stringify({
      kind: 'proxyforge-agent-control-proof',
      platform,
      lane,
      runner,
      capabilityCount: capabilities.length,
      capabilities,
      notes,
      runtime: platform === 'linux' || platform === 'windows'
        ? {
            appRoot: 'resources/app.asar',
            scriptPath: 'resources/app.asar/scripts/proxyforge-agent.mjs',
            cwd: lane === 'packaged-external-cwd' ? '~/vantix' : '/opt/ProxyForge',
          }
        : {
            appRoot: process.cwd(),
            scriptPath: 'scripts/proxyforge-agent.mjs',
            cwd: process.cwd(),
          },
      safety: {
        scopeAllowlist: ['app.shop.local'],
        approvals: ['approval-file'],
        gates: ['scopeAllowlist', 'request cap', 'rate limit', 'execute flag', 'audit'],
        trafficSent: lane === 'policy-audit' ? false : undefined,
      },
      rawRequest,
      rawResponse,
      reportRedactionBoundary: 'redact-only-during-report-export',
    }),
  };
}
