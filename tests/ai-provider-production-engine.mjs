import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

const expectedExports = [
  'buildAiProviderProductionEvidencePackage',
];
const enginePath = path.resolve('src/aiProviderProductionEngine.ts');
const aiProviderEngine = normalizeModuleExports(await loadEngine(enginePath));
const missingExports = expectedExports.filter((name) => typeof aiProviderEngine[name] !== 'function');
assert.deepEqual(missingExports, [], `ai-provider-production-engine: missing export(s): ${missingExports.join(', ')}`);

const context = buildAiProviderContext();
const productionPackage = aiProviderEngine.buildAiProviderProductionEvidencePackage(context);
const packageContent = JSON.parse(productionPackage.content);

assert.equal(productionPackage.kind, 'proxyforge-ai-provider-production-evidence-package');
assert.equal(productionPackage.secretHandling, 'execution-full-fidelity-secrets-preserved');
assert.equal(productionPackage.reportRedactionBoundary, 'redact-only-during-report-export');
assert.equal(productionPackage.productionReady, true);
assert(Object.values(productionPackage.requirements).every(Boolean), 'all AI Provider production requirements should be true');
assert.equal(packageContent.kind, 'proxyforge-ai-provider-production-evidence-package');
assert.match(productionPackage.content, /Codex/);
assert.match(productionPackage.content, /Claude/);
assert.match(productionPackage.content, /OpenAI-compatible/);
assert.match(productionPackage.content, /\/v1\/chat\/completions/);
assert.match(productionPackage.content, /providers\.json/);
assert.match(productionPackage.content, /streamEvents/);
assert.match(productionPackage.content, /estimatedCostUsd/);
assert.match(productionPackage.content, /benchmark replay/);
assert.match(productionPackage.content, /stage-replay-matrix/);
assert.match(productionPackage.content, /queue-active-scan/);
assert.match(productionPackage.content, /scopePassed\\":false/);
assert.match(productionPackage.content, /trafficSent\\":false/);
assert.match(productionPackage.content, /resources\/app\.asar/);
assert.match(productionPackage.content, /Authorization: Bearer ai-provider-secret-token/);
assert.match(productionPackage.content, /session=ai-provider-session/);
assert.match(productionPackage.content, /X-API-Key: ai-provider-api-key/);
assert.match(productionPackage.content, /redact-only-during-report-export/);

const artifactDir = path.resolve('.gitignored/test-artifacts/ai-provider-production-engine');
await fs.mkdir(artifactDir, { recursive: true });
await fs.writeFile(path.join(artifactDir, 'ai-provider-production-evidence-package.json'), productionPackage.content);

console.log('ai-provider-production-engine: verified Codex/Claude/local provider production coverage, prompt benchmarks, action gates, package refresh, and full-fidelity secret boundary');

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
  const hasNamedHelper = expectedExports.some((name) => typeof moduleExports[name] === 'function');
  if (hasNamedHelper) return moduleExports;
  if (moduleExports.default && typeof moduleExports.default === 'object') return moduleExports.default;
  return moduleExports;
}

function buildAiProviderContext() {
  const rawRequest = [
    'POST /api/refunds HTTP/2',
    'Host: app.shop.local',
    'Authorization: Bearer ai-provider-secret-token',
    'Cookie: session=ai-provider-session',
    'X-API-Key: ai-provider-api-key',
    '',
    '{"amount":100,"role":"viewer"}',
  ].join('\n');
  const rawResponse = [
    'HTTP/2 403 Forbidden',
    'Content-Type: application/json',
    '',
    '{"ok":false,"role":"viewer"}',
  ].join('\n');
  const promptContext = [
    'Scope: *.shop.local',
    'requestRaw:',
    rawRequest,
    'responseRaw:',
    rawResponse,
    'Return scoped, non-destructive next steps and keep full-fidelity executor context.',
  ].join('\n');
  const docs = [
    'OPERATOR_GUIDE documents proxyforge-ai-provider-production-evidence-package and AI provider operation.',
    'SCHEMAS.md documents proxyforge-ai-provider-production-evidence-package, provider runs, token/cost accounting, action packages, and report-export-only redaction.',
    'AGENTIC_INTERFACE and RELEASE_CHECKLIST document Codex CLI, Claude CLI, OpenAI-compatible local provider, controlled actions, and full-fidelity prompt context.',
  ];
  const proof = (id, lane, providerId, content, passedChecks = 3) => ({
    id,
    lane,
    providerId,
    status: 'passed',
    passedChecks,
    failedChecks: 0,
    content: JSON.stringify({
      kind: 'proxyforge-ai-provider-production-proof',
      lane,
      providerId,
      content,
      rawRequest,
      rawResponse,
      promptContext,
      reportRedactionBoundary: 'redact-only-during-report-export',
    }),
  });
  return {
    generatedAt: '2026-05-26T00:50:00.000Z',
    proofs: [
      proof('codex-cli', 'codex-cli', 'codex', {
        label: 'Codex',
        command: 'codex exec --skip-git-repo-check --ephemeral --sandbox read-only -',
        mode: 'cli',
        streamEvents: ['prompt', 'stdout', 'complete'],
        promptEvaluation: ['Codex execution shape ready', 'files commands tests verification gates ready'],
        suggestedActions: ['stage-repeater', 'queue-active-scan'],
        usage: { promptTokens: 128, completionTokens: 64, totalTokens: 192, estimatedCostUsd: 0.002, latencyMs: 320 },
      }),
      proof('claude-cli', 'claude-cli', 'claude', {
        label: 'Claude',
        command: 'claude --print --no-session-persistence --permission-mode dontAsk',
        mode: 'cli',
        streamEvents: ['prompt', 'stdout', 'complete'],
        promptEvaluation: ['Claude structure ready', 'sectioned assumptions ready'],
        suggestedActions: ['stage-replay-matrix', 'open-exploit-review'],
        usage: { promptTokens: 130, completionTokens: 70, totalTokens: 200, estimatedCostUsd: 0.003, latencyMs: 340 },
      }),
      proof('local-http', 'openai-compatible-http', 'local', {
        label: 'OpenAI-compatible Local',
        endpoint: 'http://127.0.0.1:11434/v1/chat/completions',
        apiKeyEnv: 'PROXYFORGE_AI_TEST_KEY',
        authorization: 'Bearer local-secret',
        mode: 'http',
        streamEvents: ['prompt', 'http', 'complete'],
        usage: { promptTokens: 100, completionTokens: 20, totalTokens: 120, estimatedCostUsd: 0.001, source: 'provider' },
      }),
      proof('provider-config', 'provider-config', undefined, {
        path: 'providers.json',
        secretPresent: true,
        apiKeyEnv: 'PROXYFORGE_AI_TEST_KEY',
        timeoutMs: 90000,
        model: 'codex-test-model claude-test-model local-security-model',
      }),
      proof('streaming-telemetry', 'streaming-telemetry', undefined, {
        streamEvents: ['prompt', 'stdout', 'http', 'complete'],
        promptTokens: 358,
        completionTokens: 154,
        totalTokens: 512,
        estimatedCostUsd: 0.006,
        inputCostPerMillionTokens: 0.25,
        outputCostPerMillionTokens: 0.5,
      }),
      proof('prompt-library', 'prompt-library', undefined, {
        templates: ['triage prompt template', 'replay-plan prompt template', 'exploit-review prompt template', 'report-draft prompt template'],
      }),
      proof('baseline-benchmark', 'baseline-comparison-benchmark', undefined, {
        baselines: ['Codex scoped triage baseline', 'Claude replay plan baseline'],
        comparison: { scoreDelta: 2, estimatedCostUsd: 0.002 },
        benchmark: { note: 'benchmark replay long-run profile', providerCount: 3, baselineCount: 2, resultCount: 6, averageScore: 96.5, latencyMs: 420 },
      }),
      proof('controlled-action', 'controlled-action', undefined, {
        actions: ['stage-repeater', 'stage-replay-matrix', 'queue-active-scan', 'open-exploit-review', 'record-automation', 'draft-report'],
        execution: { mode: 'UI-controlled', trafficSent: false, maxRequests: 7 },
      }),
      proof('scope-blocking', 'scope-blocking', undefined, {
        action: 'stage-repeater',
        status: 'blocked',
        scopePassed: false,
        reason: 'scope blocked out-of-scope target',
        trafficSent: false,
      }),
      proof('package-refresh', 'package-refresh', undefined, {
        artifact: 'resources/app.asar/dist-electron/aiEngine.js',
        source: 'dist-electron/aiEngine.js',
        package: 'proxyforge-ai-parity-evidence-package',
        packaged: true,
      }),
      proof('local-interop', 'local-provider-interop', 'local', {
        endpoints: ['Ollama http://127.0.0.1:11434/v1/chat/completions', 'LM Studio http://localhost:1234/v1/chat/completions', 'generic OpenAI-compatible /v1/chat/completions'],
      }),
      proof('long-run-profile', 'long-run-profile', undefined, {
        profile: 'long-run provider benchmark replay soak',
        providerCount: 3,
        baselineCount: 2,
        resultCount: 6,
        latencyMs: 420,
      }),
      proof('docs-schema', 'docs-schema', undefined, {
        docs: ['OPERATOR_GUIDE', 'SCHEMAS.md', 'AGENTIC_INTERFACE', 'RELEASE_CHECKLIST', 'proxyforge-ai-provider-production-evidence-package'],
      }),
      proof('security-policy', 'security-policy', undefined, {
        policy: ['scope gates', 'approval gate', 'no direct traffic', 'full-fidelity prompt context', 'report-export-only redaction'],
        actionBoundary: 'AI provider suggestions never send direct action traffic; tools execute later behind their gates.',
      }),
    ],
    docs,
    operationalSecretSamples: [
      'Authorization: Bearer ai-provider-secret-token',
      'session=ai-provider-session',
      'X-API-Key: ai-provider-api-key',
    ],
  };
}
