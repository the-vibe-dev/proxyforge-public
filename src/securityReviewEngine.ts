import type { ProjectSafetyPolicy, Severity } from './types';

export type SecurityReviewStatus = 'pass' | 'warning' | 'fail';
export type SecurityReviewCategory =
  | 'local-listener'
  | 'secret-redaction'
  | 'exploit-control'
  | 'safety-policy'
  | 'signed-trust'
  | 'artifact-hygiene'
  | 'agent-control'
  | 'platform-pin'
  | 'production-gate';

export interface SecurityReviewFinding {
  id: string;
  category: SecurityReviewCategory;
  status: SecurityReviewStatus;
  severity: Severity;
  title: string;
  detail: string;
  recommendation: string;
  evidence: string[];
}

export interface LocalListenerSecuritySurface {
  id: string;
  name: string;
  mode: 'local-http' | 'local-dns' | 'local-smtp' | 'hybrid-local' | 'public-relay' | 'desktop-proxy' | string;
  host: string;
  port?: number;
  publicBaseUrl?: string;
  protocols: string[];
  retentionHours?: number;
  signingKeyId?: string;
  enabled: boolean;
}

export interface SecretSecuritySurface {
  id: string;
  name: string;
  source: 'ai-provider' | 'report-signing' | 'audit-export' | 'session-profile' | 'callback-listener' | 'extension' | 'project-file' | string;
  valuePreview?: string;
  redacted: boolean;
  persisted: boolean;
}

export interface ExploitControlSurface {
  id: string;
  name: string;
  approvalRequired: boolean;
  scopeGate: boolean;
  rateLimit: boolean;
  stopCondition: boolean;
  nonDestructiveDefault: boolean;
  operatorRole?: string;
}

export interface SignedTrustSurface {
  id: string;
  name: string;
  signatureStatus: 'verified' | 'signed' | 'unsigned' | 'missing-secret' | 'mismatch' | 'unknown';
  trustPolicy: 'deny-unsigned' | 'review-required' | 'allow-local' | string;
}

export interface AgentControlSecuritySurface {
  id: string;
  name: string;
  commandCount: number;
  requiredCommands: string[];
  implementedCommands: string[];
  preservesOperationalSecrets: boolean;
  reportPhaseRedaction: boolean;
  scopeGate: boolean;
  approvalGate: boolean;
  writesOperationalArtifacts: boolean;
  packagedEntryPoint: boolean;
  externalCwdProof: boolean;
}

export interface PlatformPinSecuritySurface {
  id: string;
  name: string;
  platform: 'linux' | 'windows' | 'macos' | string;
  lane: string;
  status: 'passed' | 'pinned' | 'blocked' | 'failed' | 'unknown' | string;
  nonBlocking: boolean;
  reason: string;
  evidence: string[];
}

export interface ProductionGateSecuritySurface {
  id: string;
  name: string;
  fastSuitePassed: boolean;
  fullSuitePlanValidated: boolean;
  nightlyWorkflowScheduled: boolean;
  artifactUploadPolicy: boolean;
  coverageOwners: boolean;
  zeroFlakeBudget: boolean;
  operatorGuidePackaged: boolean;
  installGuideLinked: boolean;
  releaseEvidenceLinked: boolean;
  securityReviewRequired: boolean;
  retentionDays?: number;
}

export interface ReleaseSecurityReviewInput {
  projectName: string;
  generatedAt?: string;
  safetyPolicy: ProjectSafetyPolicy;
  localListeners: LocalListenerSecuritySurface[];
  secretSurfaces: SecretSecuritySurface[];
  exploitControls: ExploitControlSurface[];
  signedTrustSurfaces?: SignedTrustSurface[];
  agentControls?: AgentControlSecuritySurface[];
  platformPins?: PlatformPinSecuritySurface[];
  productionGates?: ProductionGateSecuritySurface[];
  artifactPaths?: string[];
}

export interface ReleaseSecurityReviewPackage {
  id: string;
  kind: 'proxyforge-release-security-review';
  projectName: string;
  generatedAt: string;
  status: SecurityReviewStatus;
  highestSeverity: Severity;
  findingCount: number;
  passedCount: number;
  warningCount: number;
  failedCount: number;
  categories: Record<SecurityReviewCategory, number>;
  findings: SecurityReviewFinding[];
  summary: string;
  releaseGate: string;
  content: string;
}

const severityRank: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const categories: SecurityReviewCategory[] = [
  'local-listener',
  'secret-redaction',
  'exploit-control',
  'safety-policy',
  'signed-trust',
  'artifact-hygiene',
  'agent-control',
  'platform-pin',
  'production-gate',
];

export function buildReleaseSecurityReviewPackage(input: ReleaseSecurityReviewInput): ReleaseSecurityReviewPackage {
  const generatedAt = input.generatedAt ?? new Date().toISOString();
  const findings = evaluateReleaseSecurityReview(input);
  const failedCount = findings.filter((finding) => finding.status === 'fail').length;
  const warningCount = findings.filter((finding) => finding.status === 'warning').length;
  const passedCount = findings.filter((finding) => finding.status === 'pass').length;
  const status: SecurityReviewStatus = failedCount ? 'fail' : warningCount ? 'warning' : 'pass';
  const highestSeverity = findings
    .map((finding) => finding.severity)
    .sort((left, right) => severityRank[right] - severityRank[left])[0] ?? 'info';
  const counts = Object.fromEntries(categories.map((category) => [category, 0])) as Record<SecurityReviewCategory, number>;
  for (const finding of findings) counts[finding.category] += 1;
  const releaseGate = status === 'pass'
    ? 'Release security review passed for local listener, report-phase secret redaction, exploit control, agent control, platform pin, production gate, and artifact hygiene gates.'
    : status === 'warning'
      ? 'Release security review has warnings that should be cleared before Production Ready.'
      : 'Release security review failed; block Production Ready release until failed findings are fixed.';
  const summary = `${input.projectName} release security review ${status}: ${passedCount} pass, ${warningCount} warning, ${failedCount} fail.`;
  const content = renderReleaseSecurityReview({
    input,
    generatedAt,
    status,
    highestSeverity,
    findings,
    summary,
    releaseGate,
  });
  return {
    id: `security-review-${slug(input.projectName)}-${generatedAt.replace(/[:.]/g, '-')}`,
    kind: 'proxyforge-release-security-review',
    projectName: input.projectName,
    generatedAt,
    status,
    highestSeverity,
    findingCount: findings.length,
    passedCount,
    warningCount,
    failedCount,
    categories: counts,
    findings,
    summary,
    releaseGate,
    content,
  };
}

export function evaluateReleaseSecurityReview(input: ReleaseSecurityReviewInput): SecurityReviewFinding[] {
  return [
    ...reviewSafetyPolicy(input.safetyPolicy),
    ...reviewLocalListeners(input.localListeners),
    ...reviewSecretSurfaces(input.secretSurfaces),
    ...reviewExploitControls(input.exploitControls),
    ...reviewSignedTrust(input.signedTrustSurfaces ?? []),
    ...reviewAgentControls(input.agentControls ?? []),
    ...reviewPlatformPins(input.platformPins ?? []),
    ...reviewProductionGates(input.productionGates ?? []),
    ...reviewArtifactHygiene(input.artifactPaths ?? []),
  ];
}

export function redactSecurityReviewText(value: string) {
  return value
    .replace(/(authorization:\s*(?:bearer|basic)\s+)[^\s\r\n]+/gi, '$1[redacted]')
    .replace(/((?:cookie|set-cookie):\s*)[^\r\n]+/gi, '$1[redacted]')
    .replace(/((?:api[_-]?key|access[_-]?token|refresh[_-]?token|session|secret|password|signing[_-]?secret)\s*[=:]\s*)["']?[^"',\s;&]+/gi, '$1[redacted]')
    .replace(/(sk-[A-Za-z0-9_-]{12,})/g, '[redacted]');
}

function reviewSafetyPolicy(policy: ProjectSafetyPolicy): SecurityReviewFinding[] {
  return [
    finding({
      id: 'safety-scope-gate',
      category: 'safety-policy',
      status: policy.requireScopeMatch ? 'pass' : 'fail',
      severity: policy.requireScopeMatch ? 'info' : 'high',
      title: 'Scope gate before active runners',
      detail: policy.requireScopeMatch ? 'Active runners require scope matches before execution.' : 'Active runners can execute without a required scope match.',
      recommendation: 'Require explicit scope matches before proxy replay, scanner, automation, and exploit validation runs.',
      evidence: [`requireScopeMatch=${policy.requireScopeMatch}`],
    }),
    finding({
      id: 'safety-audit-redaction',
      category: 'safety-policy',
      status: policy.auditLogging && policy.redactAuditSecrets ? 'pass' : 'fail',
      severity: policy.auditLogging && policy.redactAuditSecrets ? 'info' : 'high',
      title: 'Audit logging with report-phase redaction',
      detail: policy.auditLogging && policy.redactAuditSecrets ? 'Audit logging is enabled and report-phase redaction is enabled.' : 'Audit logging or report-phase redaction is disabled.',
      recommendation: 'Keep audit logging enabled for full-fidelity operational evidence and redact secrets when producing submission reports or bundles.',
      evidence: [`auditLogging=${policy.auditLogging}`, `redactAuditSecrets=${policy.redactAuditSecrets}`],
    }),
    finding({
      id: 'safety-rate-budget',
      category: 'safety-policy',
      status: policy.maxRequestsPerRun > 0 && policy.maxRequestsPerRun <= 1000 ? 'pass' : 'warning',
      severity: policy.maxRequestsPerRun > 0 && policy.maxRequestsPerRun <= 1000 ? 'info' : 'medium',
      title: 'Request budget and throttle floor',
      detail: `${policy.maxRequestsPerRun} request max and ${policy.minThrottleMs}ms throttle floor are configured.`,
      recommendation: 'Keep per-run request budgets bounded and set a non-zero throttle for noisy/live lanes.',
      evidence: [`maxRequestsPerRun=${policy.maxRequestsPerRun}`, `minThrottleMs=${policy.minThrottleMs}`],
    }),
  ];
}

function reviewLocalListeners(listeners: LocalListenerSecuritySurface[]): SecurityReviewFinding[] {
  if (!listeners.length) {
    return [finding({
      id: 'listener-inventory-empty',
      category: 'local-listener',
      status: 'warning',
      severity: 'medium',
      title: 'Local listener inventory is empty',
      detail: 'No local proxy/OAST/listener surfaces were supplied for review.',
      recommendation: 'Include proxy, callback, WebSocket, and browser listener bindings in the release security review.',
      evidence: ['listeners=0'],
    })];
  }
  return listeners.map((listener) => {
    const local = isLocalHost(listener.host);
    const publicRelay = listener.mode === 'public-relay' || !local;
    const signedPublicRelay = publicRelay && Boolean(listener.signingKeyId) && (listener.retentionHours ?? 0) > 0 && (listener.retentionHours ?? 999) <= 72;
    const safe = listener.enabled ? (publicRelay ? signedPublicRelay : local) : true;
    return finding({
      id: `listener-${slug(listener.id)}`,
      category: 'local-listener',
      status: safe ? 'pass' : 'fail',
      severity: safe ? 'info' : 'critical',
      title: `${listener.name} listener binding`,
      detail: listener.enabled
        ? `${listener.mode} listens on ${listener.host}${listener.port ? `:${listener.port}` : ''} for ${listener.protocols.join(', ')}.`
        : `${listener.name} is disabled.`,
      recommendation: publicRelay
        ? 'Public relay listeners require signed polling, retention limits, and explicit deployment review.'
        : 'Bind desktop listeners to localhost/loopback only unless a reviewed public relay is configured.',
      evidence: [
        `enabled=${listener.enabled}`,
        `host=${listener.host}`,
        `mode=${listener.mode}`,
        `signingKeyId=${listener.signingKeyId ? 'present' : 'missing'}`,
        `retentionHours=${listener.retentionHours ?? 'unset'}`,
      ],
    });
  });
}

function reviewSecretSurfaces(surfaces: SecretSecuritySurface[]): SecurityReviewFinding[] {
  if (!surfaces.length) {
    return [finding({
      id: 'secret-inventory-empty',
      category: 'secret-redaction',
      status: 'warning',
      severity: 'medium',
      title: 'Secret surface inventory is empty',
      detail: 'No AI/report/session/callback secret surfaces were supplied for review.',
      recommendation: 'Enumerate configured secret-bearing surfaces and prove persisted/exported previews are redacted.',
      evidence: ['secretSurfaces=0'],
    })];
  }
  return surfaces.map((surface) => {
    const preview = surface.valuePreview ?? '';
    const redactedPreview = redactSecurityReviewText(preview);
    const leaks = Boolean(preview) && redactedPreview !== preview && !/\[redacted\]/i.test(preview);
    const safe = surface.redacted && !leaks;
    return finding({
      id: `secret-${slug(surface.id)}`,
      category: 'secret-redaction',
      status: safe ? 'pass' : 'fail',
      severity: safe ? 'info' : 'high',
      title: `${surface.name} secret handling`,
      detail: safe
        ? `${surface.source} preview is redacted before persistence/export.`
        : `${surface.source} preview may persist or export raw secret material.`,
      recommendation: 'Preserve operational secrets for execution and redact token, cookie, signing-secret, and API-key values in submission reports and bundles.',
      evidence: [
        `source=${surface.source}`,
        `persisted=${surface.persisted}`,
        `redacted=${surface.redacted}`,
        `preview=${redactedPreview || 'empty'}`,
      ],
    });
  });
}

function reviewExploitControls(controls: ExploitControlSurface[]): SecurityReviewFinding[] {
  if (!controls.length) {
    return [finding({
      id: 'exploit-control-inventory-empty',
      category: 'exploit-control',
      status: 'warning',
      severity: 'medium',
      title: 'Exploit control inventory is empty',
      detail: 'No exploit validation controls were supplied for review.',
      recommendation: 'Include approval, scope, rate, destructive-mode, and stop-condition controls for Exploit Lab before release.',
      evidence: ['exploitControls=0'],
    })];
  }
  return controls.map((control) => {
    const missing = [
      !control.approvalRequired ? 'approval gate' : '',
      !control.scopeGate ? 'scope gate' : '',
      !control.rateLimit ? 'rate limit' : '',
      !control.stopCondition ? 'stop condition' : '',
      !control.nonDestructiveDefault ? 'non-destructive default' : '',
    ].filter(Boolean);
    return finding({
      id: `exploit-${slug(control.id)}`,
      category: 'exploit-control',
      status: missing.length ? 'fail' : 'pass',
      severity: missing.length ? 'critical' : 'info',
      title: `${control.name} exploit control`,
      detail: missing.length ? `Missing ${missing.join(', ')}.` : 'Approval, scope, rate, stop, and non-destructive defaults are present.',
      recommendation: 'Require approval gates, scope gates, rate limits, stop-on-proof behavior, and non-destructive defaults for exploit execution.',
      evidence: [
        `approvalRequired=${control.approvalRequired}`,
        `scopeGate=${control.scopeGate}`,
        `rateLimit=${control.rateLimit}`,
        `stopCondition=${control.stopCondition}`,
        `nonDestructiveDefault=${control.nonDestructiveDefault}`,
        `operatorRole=${control.operatorRole ?? 'unset'}`,
      ],
    });
  });
}

function reviewSignedTrust(surfaces: SignedTrustSurface[]): SecurityReviewFinding[] {
  if (!surfaces.length) return [];
  return surfaces.map((surface) => {
    const safe = ['verified', 'signed'].includes(surface.signatureStatus) || surface.trustPolicy === 'deny-unsigned';
    return finding({
      id: `trust-${slug(surface.id)}`,
      category: 'signed-trust',
      status: safe ? 'pass' : 'warning',
      severity: safe ? 'info' : 'medium',
      title: `${surface.name} signed trust policy`,
      detail: `${surface.signatureStatus} with policy ${surface.trustPolicy}.`,
      recommendation: 'Keep extension, organizer, governance, and evidence packages signed or deny unsigned package execution by default.',
      evidence: [`signatureStatus=${surface.signatureStatus}`, `trustPolicy=${surface.trustPolicy}`],
    });
  });
}

function reviewAgentControls(surfaces: AgentControlSecuritySurface[]): SecurityReviewFinding[] {
  if (!surfaces.length) return [];
  return surfaces.map((surface) => {
    const implemented = new Set(surface.implementedCommands);
    const missingCommands = surface.requiredCommands.filter((command) => !implemented.has(command));
    const missingControls = [
      !surface.preservesOperationalSecrets ? 'full-fidelity operational output' : '',
      !surface.reportPhaseRedaction ? 'report-phase redaction' : '',
      !surface.scopeGate ? 'scope gate' : '',
      !surface.approvalGate ? 'approval gate' : '',
      !surface.writesOperationalArtifacts ? 'operational artifact output' : '',
      !surface.packagedEntryPoint ? 'packaged app.asar entrypoint proof' : '',
      !surface.externalCwdProof ? 'external-cwd runtime proof' : '',
    ].filter(Boolean);
    const safe = missingCommands.length === 0 && missingControls.length === 0;
    return finding({
      id: `agent-${slug(surface.id)}`,
      category: 'agent-control',
      status: safe ? 'pass' : 'fail',
      severity: safe ? 'info' : 'high',
      title: `${surface.name} agent control surface`,
      detail: safe
        ? `${surface.commandCount} agent commands satisfy required coverage and phase-aware secret handling.`
        : `Agent surface is missing ${[...missingCommands.map((command) => `command ${command}`), ...missingControls].join(', ')}.`,
      recommendation: 'Keep Codex, Claude, and Vantix agent commands covered by scope gates, active approval gates, full-fidelity operational outputs, artifact paths, and report-phase redaction.',
      evidence: [
        `commandCount=${surface.commandCount}`,
        `requiredCommands=${surface.requiredCommands.join(',')}`,
        `missingCommands=${missingCommands.join(',') || 'none'}`,
        `preservesOperationalSecrets=${surface.preservesOperationalSecrets}`,
        `reportPhaseRedaction=${surface.reportPhaseRedaction}`,
        `scopeGate=${surface.scopeGate}`,
        `approvalGate=${surface.approvalGate}`,
        `writesOperationalArtifacts=${surface.writesOperationalArtifacts}`,
        `packagedEntryPoint=${surface.packagedEntryPoint}`,
        `externalCwdProof=${surface.externalCwdProof}`,
      ],
    });
  });
}

function reviewPlatformPins(surfaces: PlatformPinSecuritySurface[]): SecurityReviewFinding[] {
  if (!surfaces.length) return [];
  return surfaces.map((surface) => {
    const status = surface.status.toLowerCase();
    const passed = status === 'passed';
    const pinned = ['pinned', 'blocked'].includes(status) && surface.nonBlocking && surface.reason.trim().length > 0 && surface.evidence.length > 0;
    const safe = passed || pinned;
    return finding({
      id: `platform-pin-${slug(surface.id)}`,
      category: 'platform-pin',
      status: safe ? 'pass' : 'fail',
      severity: safe ? 'info' : 'high',
      title: `${surface.name} platform verification lane`,
      detail: passed
        ? `${surface.platform} ${surface.lane} passed.`
        : pinned
          ? `${surface.platform} ${surface.lane} is explicitly pinned as nonblocking: ${surface.reason}`
          : `${surface.platform} ${surface.lane} is not passed or explicitly pinned as nonblocking.`,
      recommendation: 'Pass platform release lanes directly, or record a specific nonblocking pin with evidence when host policy prevents one OS/browser trust-store proof.',
      evidence: [
        `platform=${surface.platform}`,
        `lane=${surface.lane}`,
        `status=${surface.status}`,
        `nonBlocking=${surface.nonBlocking}`,
        `reason=${surface.reason}`,
        ...surface.evidence.map((item) => `evidence=${item}`),
      ],
    });
  });
}

function reviewProductionGates(surfaces: ProductionGateSecuritySurface[]): SecurityReviewFinding[] {
  if (!surfaces.length) return [];
  return surfaces.map((surface) => {
    const missing = [
      !surface.fastSuitePassed ? 'fast regression pass' : '',
      !surface.fullSuitePlanValidated ? 'full-suite plan validation' : '',
      !surface.nightlyWorkflowScheduled ? 'scheduled nightly workflow' : '',
      !surface.artifactUploadPolicy ? 'artifact upload policy' : '',
      !surface.coverageOwners ? 'coverage owner metadata' : '',
      !surface.zeroFlakeBudget ? 'zero-flake default budget' : '',
      !surface.operatorGuidePackaged ? 'packaged operator guide' : '',
      !surface.installGuideLinked ? 'install guide link' : '',
      !surface.releaseEvidenceLinked ? 'release evidence link' : '',
      !surface.securityReviewRequired ? 'security review release gate' : '',
    ].filter(Boolean);
    const retentionSafe = (surface.retentionDays ?? 0) >= 14;
    const safe = missing.length === 0 && retentionSafe;
    return finding({
      id: `production-gate-${slug(surface.id)}`,
      category: 'production-gate',
      status: safe ? 'pass' : 'fail',
      severity: safe ? 'info' : 'high',
      title: `${surface.name} production release gate`,
      detail: safe
        ? 'CI, release evidence, operator docs, and security-review release gates are present.'
        : `Production release gate is missing ${[...missing, ...(!retentionSafe ? ['artifact retention >= 14 days'] : [])].join(', ')}.`,
      recommendation: 'Require fast regression, full/nightly plan metadata, artifact retention, coverage ownership, zero-flake policy, packaged operator docs, release evidence linkage, and this security review before Production Ready.',
      evidence: [
        `fastSuitePassed=${surface.fastSuitePassed}`,
        `fullSuitePlanValidated=${surface.fullSuitePlanValidated}`,
        `nightlyWorkflowScheduled=${surface.nightlyWorkflowScheduled}`,
        `artifactUploadPolicy=${surface.artifactUploadPolicy}`,
        `coverageOwners=${surface.coverageOwners}`,
        `zeroFlakeBudget=${surface.zeroFlakeBudget}`,
        `operatorGuidePackaged=${surface.operatorGuidePackaged}`,
        `installGuideLinked=${surface.installGuideLinked}`,
        `releaseEvidenceLinked=${surface.releaseEvidenceLinked}`,
        `securityReviewRequired=${surface.securityReviewRequired}`,
        `retentionDays=${surface.retentionDays ?? 'unset'}`,
      ],
    });
  });
}

function reviewArtifactHygiene(paths: string[]): SecurityReviewFinding[] {
  if (!paths.length) return [];
  return paths.map((artifactPath) => {
    const safe = /^test-results\/|^release\/|^\.gitignored\/|^docs\//.test(artifactPath);
    return finding({
      id: `artifact-${slug(artifactPath)}`,
      category: 'artifact-hygiene',
      status: safe ? 'pass' : 'warning',
      severity: safe ? 'info' : 'low',
      title: `${artifactPath} artifact hygiene`,
      detail: safe ? 'Artifact path is tracked or ignored by release policy.' : 'Artifact path is outside the usual release/test-results/docs lanes.',
      recommendation: 'Keep generated artifacts in ignored release/test-results/.gitignored paths or committed docs evidence.',
      evidence: [`path=${artifactPath}`],
    });
  });
}

function renderReleaseSecurityReview(context: {
  input: ReleaseSecurityReviewInput;
  generatedAt: string;
  status: SecurityReviewStatus;
  highestSeverity: Severity;
  findings: SecurityReviewFinding[];
  summary: string;
  releaseGate: string;
}) {
  const lines = [
    `# ${context.input.projectName} Release Security Review`,
    '',
    `Generated: ${context.generatedAt}`,
    `Status: ${context.status}`,
    `Highest severity: ${context.highestSeverity}`,
    '',
    '## Summary',
    '',
    context.summary,
    context.releaseGate,
    '',
    '## Findings',
    '',
    ...context.findings.flatMap((finding) => [
      `### ${finding.title}`,
      '',
      `Status: ${finding.status}`,
      `Severity: ${finding.severity}`,
      `Category: ${finding.category}`,
      '',
      redactSecurityReviewText(finding.detail),
      '',
      `Recommendation: ${redactSecurityReviewText(finding.recommendation)}`,
      '',
      ...finding.evidence.map((item) => `- ${redactSecurityReviewText(item)}`),
      '',
    ]),
  ];
  return lines.join('\n');
}

function finding(findingInput: SecurityReviewFinding): SecurityReviewFinding {
  return {
    ...findingInput,
    detail: redactSecurityReviewText(findingInput.detail),
    recommendation: redactSecurityReviewText(findingInput.recommendation),
    evidence: findingInput.evidence.map(redactSecurityReviewText),
  };
}

function isLocalHost(host: string) {
  return /^(localhost|127(?:\.\d{1,3}){3}|\[?::1\]?|0:0:0:0:0:0:0:1)$/i.test(host.trim());
}

function slug(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 80) || 'item';
}
