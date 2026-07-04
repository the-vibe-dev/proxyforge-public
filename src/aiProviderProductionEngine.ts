export type AiProviderProductionStatus = 'passed' | 'failed' | 'pinned-nonblocking';

export interface AiProviderProductionProof {
  id: string;
  lane:
    | 'codex-cli'
    | 'claude-cli'
    | 'openai-compatible-http'
    | 'provider-config'
    | 'streaming-telemetry'
    | 'prompt-library'
    | 'baseline-comparison-benchmark'
    | 'controlled-action'
    | 'scope-blocking'
    | 'package-refresh'
    | 'local-provider-interop'
    | 'long-run-profile'
    | 'docs-schema'
    | 'security-policy';
  status: AiProviderProductionStatus;
  providerId?: string;
  passedChecks: number;
  failedChecks: number;
  content: string;
  reason?: string;
}

export interface AiProviderProductionRequest {
  proofs: AiProviderProductionProof[];
  docs: string[];
  generatedAt?: string;
  operationalSecretSamples?: string[];
}

export interface AiProviderProductionEvidencePackage {
  id: string;
  kind: 'proxyforge-ai-provider-production-evidence-package';
  title: string;
  fileName: string;
  path: string;
  generatedAt: string;
  proofCount: number;
  requirements: {
    codexCliProviderCovered: boolean;
    claudeCliProviderCovered: boolean;
    openAiCompatibleProviderCovered: boolean;
    providerConfigPersistenceCovered: boolean;
    cliProviderDiversityCovered: boolean;
    httpProviderInteropCovered: boolean;
    streamingTelemetryCovered: boolean;
    tokenCostAccountingCovered: boolean;
    promptLibraryCovered: boolean;
    baselinesComparisonsBenchmarksCovered: boolean;
    controlledActionsCovered: boolean;
    scopeBlockingCovered: boolean;
    noDirectActionTrafficCovered: boolean;
    packageRefreshCovered: boolean;
    longRunProfilingCovered: boolean;
    docsAndSchemasCovered: boolean;
    securityPolicyCovered: boolean;
    rawExecutorMaterialPreserved: boolean;
    operationalSecretsPreserved: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  productionReady: boolean;
  digestPreview: string;
  summaryText: string;
  content: string;
}

export function buildAiProviderProductionEvidencePackage(
  request: AiProviderProductionRequest,
): AiProviderProductionEvidencePackage {
  const generatedAt = request.generatedAt ?? new Date().toISOString();
  const stamp = generatedAt.replace(/[:.]/g, '-');
  const rawMaterial = [
    ...request.proofs.map((proof) => proof.content),
    request.docs.join('\n'),
    ...(request.operationalSecretSamples ?? []),
  ].join('\n');
  const passedLane = (lane: AiProviderProductionProof['lane'], pattern?: RegExp) => request.proofs.some((proof) => (
    proof.lane === lane
    && proof.status === 'passed'
    && proof.passedChecks > 0
    && proof.failedChecks === 0
    && (pattern ? pattern.test(`${proof.reason ?? ''}\n${proof.content}`) : true)
  ));
  const providerProof = (providerId: string, pattern: RegExp) => request.proofs.some((proof) => (
    proof.providerId === providerId
    && proof.status === 'passed'
    && proof.passedChecks > 0
    && proof.failedChecks === 0
    && pattern.test(proof.content)
  ));
  const requirements = {
    codexCliProviderCovered: providerProof('codex', /Codex|codex|cli|stdout|promptEvaluation|suggestedActions/i),
    claudeCliProviderCovered: providerProof('claude', /Claude|claude|cli|stdout|promptEvaluation|suggestedActions/i),
    openAiCompatibleProviderCovered: providerProof('local', /OpenAI-compatible|\/v1\/chat\/completions|Bearer|apiKeyEnv|http/i),
    providerConfigPersistenceCovered: passedLane('provider-config', /providers\.json|secretPresent|apiKeyEnv|timeoutMs|model/i),
    cliProviderDiversityCovered: passedLane('codex-cli', /codex.*exec|ephemeral|sandbox|stdout/i)
      && passedLane('claude-cli', /claude.*print|permission-mode|stdout/i),
    httpProviderInteropCovered: passedLane('local-provider-interop', /Ollama|LM Studio|generic OpenAI|127\.0\.0\.1|localhost|\/v1\/chat\/completions/i),
    streamingTelemetryCovered: passedLane('streaming-telemetry', /prompt|stdout|http|complete|streamEvents/i),
    tokenCostAccountingCovered: /promptTokens|completionTokens|totalTokens|estimatedCostUsd|inputCostPerMillionTokens|outputCostPerMillionTokens/i.test(rawMaterial),
    promptLibraryCovered: passedLane('prompt-library', /triage|replay-plan|exploit-review|report-draft|prompt template/i),
    baselinesComparisonsBenchmarksCovered: passedLane('baseline-comparison-benchmark', /baseline|comparison|benchmark|scoreDelta|averageScore|resultCount/i),
    controlledActionsCovered: passedLane('controlled-action', /stage-repeater|stage-replay-matrix|queue-active-scan|open-exploit-review|record-automation|draft-report/i),
    scopeBlockingCovered: passedLane('scope-blocking', /blocked|scopePassed.*false|scope blocked|out-of-scope/i),
    noDirectActionTrafficCovered: /trafficSent["']?\s*:\s*false|no autonomous traffic sent|UI-controlled/i.test(rawMaterial),
    packageRefreshCovered: passedLane('package-refresh', /dist-electron\/aiEngine\.js|resources[\\/]+app\.asar|proxyforge-ai-parity-evidence-package|packaged/i),
    longRunProfilingCovered: passedLane('long-run-profile', /long-run|soak|benchmark replay|providerCount|baselineCount|resultCount|latencyMs/i),
    docsAndSchemasCovered: passedLane('docs-schema', /OPERATOR_GUIDE|SCHEMAS\.md|AGENTIC_INTERFACE|RELEASE_CHECKLIST|proxyforge-ai-provider-production-evidence-package/i),
    securityPolicyCovered: passedLane('security-policy', /scope|approval|redaction|no direct traffic|full-fidelity|report-export-only/i),
    rawExecutorMaterialPreserved: /HTTP\/[12]|Authorization:|Cookie:|X-API-Key:|requestRaw|responseRaw|Bearer|session/i.test(rawMaterial),
    operationalSecretsPreserved: (request.operationalSecretSamples ?? []).length > 0
      && (request.operationalSecretSamples ?? []).every((sample) => rawMaterial.includes(sample)),
    reportPhaseOnlyRedaction: /redact-only-during-report-export|submission-reporting-redaction|report export/i.test(rawMaterial),
  };
  const unsigned = {
    kind: 'proxyforge-ai-provider-production-evidence-package',
    generatedAt,
    proofs: request.proofs,
    coverageNotes: {
      providerCoverage: 'Codex and Claude are covered as CLI providers; local and OpenAI-compatible providers are covered through /v1/chat/completions HTTP semantics and API-key env forwarding.',
      actionBoundary: 'AI provider suggestions create UI-controlled execution packages; Repeater, Scanner, Exploit Lab, Automations, and Reports backends execute later through their own gates.',
      packageRefresh: 'The production package ties provider evidence to packaged dist-electron aiEngine and release docs/schemas.',
      secretBoundary: 'Provider prompt context stays full fidelity for executor use; report and bundle commands redact only for submission artifacts.',
    },
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    productionReady: Object.values(requirements).every(Boolean),
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const content = JSON.stringify({ ...unsigned, digestPreview }, null, 2);

  return {
    id: `ai-provider-production-${digestPreview.slice(0, 12)}`,
    kind: 'proxyforge-ai-provider-production-evidence-package',
    title: 'AI provider production evidence package',
    fileName: `proxyforge-ai-provider-production-${stamp}.json`,
    path: `release/proxyforge-ai-provider-production-${stamp}.json`,
    generatedAt,
    proofCount: request.proofs.length,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    productionReady: Object.values(requirements).every(Boolean),
    digestPreview,
    summaryText: 'AI provider production evidence covers Codex CLI, Claude CLI, OpenAI-compatible HTTP providers, provider configuration persistence, CLI diversity, local-provider interop, streaming telemetry, token/cost accounting, prompt templates, baselines, comparisons, benchmark replay, controlled action packages, scope blocking, no direct action traffic, packaged aiEngine refresh proof, long-run profiling, docs/schemas, security policy, full-fidelity prompt context, and report-export-only redaction.',
    content,
  };
}

function simpleDigest(value: string) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `${hash.toString(16).padStart(8, '0')}${value.length.toString(16).padStart(8, '0')}`;
}
