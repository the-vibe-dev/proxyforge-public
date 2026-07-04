export type AgentControlProofPlatform = 'source' | 'linux' | 'windows';
export type AgentControlProofStatus = 'passed' | 'pinned-nonblocking' | 'failed';

export const requiredAgentProductionCapabilities = [
  'status',
  'inventory',
  'evidence-list',
  'findings-list',
  'mitm-start',
  'mitm-status',
  'mitm-export',
  'mitm-stop',
  'search',
  'search-index',
  'view',
  'chromium-capture',
  'cookie-capture',
  'proxy-import',
  'project-store-status',
  'project-store-recover',
  'project-store-backup',
  'crawl-run',
  'content-discovery-plan',
  'content-discovery-run',
  'live-target-profile',
  'target-access-review',
  'target-map-compare',
  'automation-list',
  'automation-run',
  'automation-ci-export',
  'automation-scheduler-tick',
  'automation-parity-export',
  'automation-service-plan',
  'automation-service-smoke',
  'intel',
  'sequencer-analyze',
  'decoder-chain',
  'replay-run',
  'bulk-replay',
  'replay-matrix',
  'websocket-list',
  'websocket-replay',
  'websocket-fuzz',
  'websocket-transcript-export',
  'intruder-run',
  'repeater-desync-plan',
  'repeater-desync-probe',
  'repeater-race-run',
  'insertion-points',
  'scanner-plan',
  'scanner-run',
  'scanner-retest',
  'scanner-evidence-export',
  'scanner-oast-promote',
  'anvil-plan',
  'anvil-run',
  'anvil-package-export',
  'extension-fixtures',
  'callback-poll',
  'callback-provider-probe',
  'callback-replay',
  'callback-relay-plan',
  'callback-relay-soak',
  'callback-retention-prune',
  'exploit-preview',
  'exploit-run',
  'exploit-package-export',
  'report-preview',
  'report-export',
  'bundle-sign',
  'bundle-verify',
  'vantix-sync',
  'vantix-intel-export',
  'vantix-report-import',
];

export interface AgentControlProof {
  id: string;
  platform: AgentControlProofPlatform;
  lane:
    | 'source-command-surface'
    | 'packaged-agent-cli'
    | 'packaged-external-cwd'
    | 'persistent-mitm'
    | 'chromium-data-collection'
    | 'project-store-recovery'
    | 'search-view'
    | 'replay-intruder-repeater'
    | 'scanner-anvil'
    | 'extension-callback-exploit-report'
    | 'automation-vantix'
    | 'policy-audit'
    | 'long-running-soak'
    | 'docs-schema'
    | 'package-production-gate';
  status: AgentControlProofStatus;
  capabilities?: string[];
  runner: string;
  passedChecks: number;
  failedChecks: number;
  reason?: string;
  content: string;
}

export interface AgentControlProductionRequest {
  proofs: AgentControlProof[];
  docs: string[];
  generatedAt?: string;
  operationalSecretSamples?: string[];
}

export interface AgentControlProductionEvidencePackage {
  id: string;
  kind: 'proxyforge-agent-control-production-evidence-package';
  title: string;
  fileName: string;
  path: string;
  generatedAt: string;
  proofCount: number;
  requiredCapabilityCount: number;
  requirements: {
    sourceCommandSurfaceCovered: boolean;
    packagedLinuxCommandSurfaceCovered: boolean;
    packagedWindowsCommandSurfaceCovered: boolean;
    packagedExternalCwdCovered: boolean;
    persistentMitmCovered: boolean;
    chromiumDataCollectionCovered: boolean;
    projectStoreRecoveryCovered: boolean;
    searchViewingCovered: boolean;
    replayIntruderRepeaterCovered: boolean;
    scannerBcheckCovered: boolean;
    extensionCallbackExploitReportCovered: boolean;
    automationVantixCovered: boolean;
    policyAuditCovered: boolean;
    scopeApprovalRateLimitCovered: boolean;
    longRunningSoakCovered: boolean;
    linuxWindowsPackageInputsCovered: boolean;
    docsAndSchemasCovered: boolean;
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

export function buildAgentControlProductionEvidencePackage(
  request: AgentControlProductionRequest,
): AgentControlProductionEvidencePackage {
  const generatedAt = request.generatedAt ?? new Date().toISOString();
  const stamp = generatedAt.replace(/[:.]/g, '-');
  const rawMaterial = [
    ...request.proofs.map((proof) => proof.content),
    request.docs.join('\n'),
    ...(request.operationalSecretSamples ?? []),
  ].join('\n');
  const passedProof = (
    lane: AgentControlProof['lane'],
    platform?: AgentControlProofPlatform,
  ) => request.proofs.some((proof) => (
    proof.lane === lane
    && (platform ? proof.platform === platform : true)
    && proof.status === 'passed'
    && proof.passedChecks > 0
    && proof.failedChecks === 0
  ));
  const capabilitiesCovered = (platform: AgentControlProofPlatform, lane: AgentControlProof['lane']) => (
    request.proofs.some((proof) => (
      proof.platform === platform
      && proof.lane === lane
      && proof.status === 'passed'
      && proof.failedChecks === 0
      && requiredAgentProductionCapabilities.every((capability) => proof.capabilities?.includes(capability))
    ))
  );
  const requirements = {
    sourceCommandSurfaceCovered: capabilitiesCovered('source', 'source-command-surface'),
    packagedLinuxCommandSurfaceCovered: capabilitiesCovered('linux', 'packaged-agent-cli')
      && /resources[\\/]+app\.asar|appRoot.*app\.asar/i.test(rawMaterial),
    packagedWindowsCommandSurfaceCovered: capabilitiesCovered('windows', 'packaged-agent-cli')
      && /resources[\\/]+app\.asar|appRoot.*app\.asar/i.test(rawMaterial),
    packagedExternalCwdCovered: passedProof('packaged-external-cwd', 'linux')
      && /external-cwd|external cwd|~\/vantix|resources[\\/]+app\.asar/i.test(rawMaterial),
    persistentMitmCovered: passedProof('persistent-mitm')
      && /mitm-start|mitm-status|mitm-export|mitm-stop|project-CA|persistent JSONL|upstream TLS/i.test(rawMaterial),
    chromiumDataCollectionCovered: passedProof('chromium-data-collection')
      && /chromium-capture|cookie-capture|proxy-import|browser profile|cookie/i.test(rawMaterial),
    projectStoreRecoveryCovered: passedProof('project-store-recovery')
      && /project-store-status|project-store-recover|project-store-backup|crash recovery|restore point|recovery journal/i.test(rawMaterial),
    searchViewingCovered: passedProof('search-view')
      && /search-index|provider-url|sequencer-analyze|decoder-chain|view|semantic|large-project/i.test(rawMaterial),
    replayIntruderRepeaterCovered: passedProof('replay-intruder-repeater')
      && /replay-run|bulk-replay|websocket-replay|websocket-fuzz|websocket-transcript-export|live-target-profile|intruder-run|repeater-desync|repeater-race|releaseSkewMs/i.test(rawMaterial),
    scannerBcheckCovered: passedProof('scanner-anvil')
      && /insertion-points|scanner-run|scanner-retest|scanner-evidence-export|anvil-run|anvil-package-export/i.test(rawMaterial),
    extensionCallbackExploitReportCovered: passedProof('extension-callback-exploit-report')
      && /extension-fixtures|callback-provider-probe|callback-relay-soak|callback-retention-prune|exploit-run|report-export|bundle-sign/i.test(rawMaterial),
    automationVantixCovered: passedProof('automation-vantix')
      && /automation-run|automation-scheduler-tick|automation-parity-export|automation-service-plan|automation-service-smoke|vantix-sync|vantix-intel-export/i.test(rawMaterial),
    policyAuditCovered: passedProof('policy-audit')
      && /scope gate|approval|rate limit|request cap|audit|blocked unsafe/i.test(rawMaterial),
    scopeApprovalRateLimitCovered: /scopeAllowlist|approval-file|request cap|rate limit|execute flag|trafficSent/i.test(rawMaterial),
    longRunningSoakCovered: passedProof('long-running-soak')
      && /search-index --soak|provider-url|bulk-replay.*soak|live-target-profile|intruder.*soak|repeater-race.*soak|callback-relay-soak|scheduler/i.test(rawMaterial),
    linuxWindowsPackageInputsCovered: passedProof('package-production-gate', 'linux')
      && passedProof('package-production-gate', 'windows')
      && /proxyforge-linux-package-production-evidence-package|proxyforge-windows-package-production-evidence-package/i.test(rawMaterial),
    docsAndSchemasCovered: passedProof('docs-schema')
      && /CODEX\.md|CLAUDE\.md|VANTIX\.md|SCHEMAS\.md|AGENTIC_INTERFACE|MVP_OPTION_AUDIT/i.test(rawMaterial),
    rawExecutorMaterialPreserved: /HTTP\/[12]|Authorization:|Cookie:|X-API-Key:|rawRequest|rawResponse|callbackToken|session/i.test(rawMaterial),
    operationalSecretsPreserved: (request.operationalSecretSamples ?? []).length > 0
      && (request.operationalSecretSamples ?? []).every((sample) => rawMaterial.includes(sample)),
    reportPhaseOnlyRedaction: /redact-only-during-report-export|submission-reporting-redaction|report export/i.test(rawMaterial),
  };
  const unsigned = {
    kind: 'proxyforge-agent-control-production-evidence-package',
    generatedAt,
    requiredCapabilities: requiredAgentProductionCapabilities,
    proofs: request.proofs,
    coverageNotes: {
      commandSurface: 'Source and packaged status outputs expose the full current 70-command Codex/Claude/Vantix control surface.',
      packagedRuntime: 'Packaged agent CLI resolves runtime modules from resources/app.asar and supports external-cwd invocation for Vantix-style orchestration.',
      activeWorkflowPolicy: 'Active workflows require explicit execute, scope, approval, request-cap, and audit gates; reporting commands redact only at submission/report phase.',
      longRunningEvidence: 'Agent soaks cover search indexing, live semantic provider ranking, bulk replay, Intruder, race timing, callback relay, scheduler queues, and scanner calibration.',
    },
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    productionReady: Object.values(requirements).every(Boolean),
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const content = JSON.stringify({ ...unsigned, digestPreview }, null, 2);

  return {
    id: `agent-control-production-${digestPreview.slice(0, 12)}`,
    kind: 'proxyforge-agent-control-production-evidence-package',
    title: 'Agent control production evidence package',
    fileName: `proxyforge-agent-control-production-${stamp}.json`,
    path: `release/proxyforge-agent-control-production-${stamp}.json`,
    generatedAt,
    proofCount: request.proofs.length,
    requiredCapabilityCount: requiredAgentProductionCapabilities.length,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    productionReady: Object.values(requirements).every(Boolean),
    digestPreview,
    summaryText: 'Agent control production evidence covers the current 70-command source and packaged Codex/Claude/Vantix command surface, packaged app.asar and external-cwd runtime proof, persistent MITM, Chromium/cookie/data collection, Project Store recovery/backup, search/live-provider ranking/view/Sequencer/Decoder, replay/live-target profiling/WebSocket/Intruder/Repeater race/desync, insertion-point extraction, Scanner/Anvil/OAST promotion, extension/callback provider host proof/exploit/report, automation service lifecycle and installed-host service smoke/Vantix handoff, scope/approval/rate-limit/audit gates, long-running soak evidence, full-fidelity operational material, and report-export-only redaction.',
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
