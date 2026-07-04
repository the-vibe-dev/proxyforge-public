import type {
  AnvilDefinition,
  AnvilFixture,
  AnvilHeadlessRun,
  AnvilPackageReview,
  AnvilRuleLibrary,
  AnvilValidationRun,
  HttpExchange,
  Issue,
} from './types';

export interface AnvilParityEvidenceRequest {
  definition: AnvilDefinition;
  library?: AnvilRuleLibrary;
  fixtures?: AnvilFixture[];
  validationRun?: AnvilValidationRun;
  headlessRun?: AnvilHeadlessRun;
  packageReview?: AnvilPackageReview;
  promotedIssue?: Issue;
  exchanges?: HttpExchange[];
  generatedAt?: string;
}

export interface AnvilParityEvidencePackage {
  id: string;
  kind: 'proxyforge-anvil-custom-check-parity-package';
  schemaVersion: 1;
  generatedAt: string;
  definition: {
    id: string;
    name: string;
    language: AnvilDefinition['language'];
    phase: AnvilDefinition['phase'];
    runScope: AnvilDefinition['runScope'];
    severity: AnvilDefinition['severity'];
    confidence: AnvilDefinition['confidence'];
    tags: string[];
    source: string;
  };
  reusableLibrary?: {
    id: string;
    name: string;
    trust: AnvilRuleLibrary['trust'];
    ruleIds: string[];
    content: string;
  };
  fixtureCoverage: {
    fixtureCount: number;
    positiveFixtureCount: number;
    negativeFixtureCount: number;
    passedCount: number;
    failedCount: number;
    fixtures: Array<{
      id: string;
      name: string;
      expected: AnvilFixture['expected'];
      status: AnvilFixture['status'];
      requestRaw: string;
      responseRaw: string;
      evidence: string;
    }>;
  };
  validation?: {
    id: string;
    status: AnvilValidationRun['status'];
    requestCount: number;
    issueCount: number;
    auditItemCount: number;
    loggerCount: number;
    reportReady: boolean;
    content: string;
  };
  headless?: {
    id: string;
    targetUrl: string;
    status: AnvilHeadlessRun['status'];
    requestCount: number;
    issueCount: number;
    auditItemCount: number;
    loggerCount: number;
    builtInChecksDisabled: boolean;
    extensionChecksDisabled: boolean;
    issueIds: string[];
    exchangeIds: string[];
    reportReady: boolean;
    content: string;
  };
  packageReview?: {
    id: string;
    status: AnvilPackageReview['status'];
    packageDigest: string;
    signature: AnvilPackageReview['signature'];
    reusableRuleCount: number;
    fixtureCount: number;
    findingCount: number;
    content: string;
  };
  scannerHandoff?: {
    issueId: string;
    title: string;
    severity: Issue['severity'];
    confidence: Issue['confidence'];
    status: Issue['status'];
    detail: string;
    remediation: string;
  };
  reportAttachments: Array<{
    id: string;
    kind: 'definition' | 'rule-library' | 'fixture-validation' | 'headless-run' | 'package-review' | 'scanner-finding';
    artifactId: string;
    reportReady: boolean;
    redactionPhase: 'report-export-only';
  }>;
  rawExchangeSamples: Array<{
    id: string;
    method: string;
    host: string;
    path: string;
    status: number;
    source: HttpExchange['source'];
    tags: string[];
    requestRaw: string;
    responseRaw: string;
  }>;
  operationalSecretSignals: string[];
  requirements: {
    plainTextDefinitionPreserved: boolean;
    reusableLibraryCovered: boolean;
    positiveNegativeFixturesCovered: boolean;
    fixtureValidationPassed: boolean;
    headlessCustomOnlyCovered: boolean;
    signedPackageReviewCovered: boolean;
    scannerIssueHandoffCovered: boolean;
    reportsHandoffCovered: boolean;
    rawExecutorMaterialPreserved: boolean;
    operationalSecretsPreserved: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  reportReady: true;
  summary: string;
  content: string;
}

export function buildAnvilParityEvidencePackage(request: AnvilParityEvidenceRequest): AnvilParityEvidencePackage {
  const generatedAt = request.generatedAt ?? new Date().toISOString();
  const fixtures = (request.fixtures ?? []).filter((fixture) => fixture.checkId === request.definition.id);
  const rawExchangeSamples = buildAnvilRawExchangeSamples(request.exchanges ?? [], fixtures, request.headlessRun?.exchangeIds ?? []);
  const operationalSecretSignals = anvilOperationalSecretSignals(
    request.definition.source,
    request.library?.content ?? '',
    request.validationRun?.content ?? '',
    request.headlessRun?.content ?? '',
    request.packageReview?.content ?? '',
    ...fixtures.flatMap((fixture) => [fixture.requestRaw, fixture.responseRaw, fixture.evidence]),
    ...rawExchangeSamples.flatMap((sample) => [sample.requestRaw, sample.responseRaw]),
  );
  const reportAttachments = buildAnvilReportAttachments(request);
  const fixtureCoverage = {
    fixtureCount: fixtures.length,
    positiveFixtureCount: fixtures.filter((fixture) => fixture.expected === 'match').length,
    negativeFixtureCount: fixtures.filter((fixture) => fixture.expected === 'no-match').length,
    passedCount: fixtures.filter((fixture) => fixture.status === 'passed').length,
    failedCount: fixtures.filter((fixture) => fixture.status === 'failed').length,
    fixtures: fixtures.map((fixture) => ({
      id: fixture.id,
      name: fixture.name,
      expected: fixture.expected,
      status: fixture.status,
      requestRaw: fixture.requestRaw,
      responseRaw: fixture.responseRaw,
      evidence: fixture.evidence,
    })),
  };
  const requirements = {
    plainTextDefinitionPreserved: /\.?anvil|given\s+(?:request|response)|report issue|metadata:/i.test(request.definition.source),
    reusableLibraryCovered: Boolean(request.library?.content && request.library.ruleIds.includes(request.definition.id)),
    positiveNegativeFixturesCovered: fixtureCoverage.positiveFixtureCount > 0 && fixtureCoverage.negativeFixtureCount > 0,
    fixtureValidationPassed: Boolean(request.validationRun && request.validationRun.status === 'passed' && request.validationRun.reportReady),
    headlessCustomOnlyCovered: Boolean(request.headlessRun?.builtInChecksDisabled && request.headlessRun.extensionChecksDisabled && request.headlessRun.reportReady),
    signedPackageReviewCovered: Boolean(request.packageReview?.signature.status === 'verified' && request.packageReview.status !== 'blocked'),
    scannerIssueHandoffCovered: Boolean(request.promotedIssue?.id && request.promotedIssue.title),
    reportsHandoffCovered: reportAttachments.length >= 5 && reportAttachments.every((attachment) => attachment.reportReady && attachment.redactionPhase === 'report-export-only'),
    rawExecutorMaterialPreserved: fixtures.some((fixture) => fixture.requestRaw.trim() && fixture.responseRaw.trim()) || rawExchangeSamples.some((sample) => sample.requestRaw.trim() && sample.responseRaw.trim()),
    operationalSecretsPreserved: operationalSecretSignals.length > 0,
    reportPhaseOnlyRedaction: true,
  };
  const body = {
    kind: 'proxyforge-anvil-custom-check-parity-package' as const,
    schemaVersion: 1 as const,
    generatedAt,
    definition: {
      id: request.definition.id,
      name: request.definition.name,
      language: request.definition.language,
      phase: request.definition.phase,
      runScope: request.definition.runScope,
      severity: request.definition.severity,
      confidence: request.definition.confidence,
      tags: request.definition.tags,
      source: request.definition.source,
    },
    reusableLibrary: request.library ? {
      id: request.library.id,
      name: request.library.name,
      trust: request.library.trust,
      ruleIds: request.library.ruleIds,
      content: request.library.content,
    } : undefined,
    fixtureCoverage,
    validation: request.validationRun ? {
      id: request.validationRun.id,
      status: request.validationRun.status,
      requestCount: request.validationRun.requestCount,
      issueCount: request.validationRun.issueCount,
      auditItemCount: request.validationRun.auditItemCount,
      loggerCount: request.validationRun.loggerCount,
      reportReady: request.validationRun.reportReady,
      content: request.validationRun.content,
    } : undefined,
    headless: request.headlessRun ? {
      id: request.headlessRun.id,
      targetUrl: request.headlessRun.targetUrl,
      status: request.headlessRun.status,
      requestCount: request.headlessRun.requestCount,
      issueCount: request.headlessRun.issueCount,
      auditItemCount: request.headlessRun.auditItemCount,
      loggerCount: request.headlessRun.loggerCount,
      builtInChecksDisabled: request.headlessRun.builtInChecksDisabled,
      extensionChecksDisabled: request.headlessRun.extensionChecksDisabled,
      issueIds: request.headlessRun.issueIds,
      exchangeIds: request.headlessRun.exchangeIds,
      reportReady: request.headlessRun.reportReady,
      content: request.headlessRun.content,
    } : undefined,
    packageReview: request.packageReview ? {
      id: request.packageReview.id,
      status: request.packageReview.status,
      packageDigest: request.packageReview.packageDigest,
      signature: request.packageReview.signature,
      reusableRuleCount: request.packageReview.reusableRuleCount,
      fixtureCount: request.packageReview.fixtureCount,
      findingCount: request.packageReview.findingCount,
      content: request.packageReview.content,
    } : undefined,
    scannerHandoff: request.promotedIssue ? {
      issueId: request.promotedIssue.id,
      title: request.promotedIssue.title,
      severity: request.promotedIssue.severity,
      confidence: request.promotedIssue.confidence,
      status: request.promotedIssue.status,
      detail: request.promotedIssue.detail,
      remediation: request.promotedIssue.remediation,
    } : undefined,
    reportAttachments,
    rawExchangeSamples,
    operationalSecretSignals,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved' as const,
    reportRedactionBoundary: 'redact-only-during-report-export' as const,
    reportReady: true as const,
  };
  const content = JSON.stringify(body, null, 2);
  return {
    id: `anvil-parity-${simpleDigest(content).slice(0, 12)}`,
    ...body,
    summary: `Anvil parity package preserved ${request.definition.name}, ${fixtureCoverage.fixtureCount} fixture(s), ${request.validationRun?.requestCount ?? 0} validation request(s), ${request.headlessRun?.requestCount ?? 0} headless request(s), ${request.packageReview?.signature.status ?? 'unsigned'} package review, ${request.promotedIssue ? 1 : 0} Scanner handoff, and ${operationalSecretSignals.length} operational secret signal(s).`,
    content,
  };
}

function buildAnvilRawExchangeSamples(exchanges: HttpExchange[], fixtures: AnvilFixture[], headlessExchangeIds: string[]) {
  const fixturePairs = fixtures.map((fixture, index) => {
    const fixtureStatus = Number(/^HTTP\/\d(?:\.\d)?\s+(\d+)/im.exec(fixture.responseRaw)?.[1] ?? 0);
    return {
      id: fixture.id,
      method: 'FIXTURE',
      host: 'anvil.fixture',
      path: `/${index + 1}`,
      status: fixtureStatus,
      source: 'scanner' as const,
      tags: ['anvil-fixture', `expected:${fixture.expected}`, `status:${fixture.status}`],
      requestRaw: fixture.requestRaw,
      responseRaw: fixture.responseRaw,
    };
  });
  const selectedExchangeIds = new Set(headlessExchangeIds);
  const selectedExchanges = exchanges
    .filter((exchange) => selectedExchangeIds.has(exchange.id))
    .slice(0, 8)
    .map((exchange) => ({
      id: exchange.id,
      method: exchange.method,
      host: exchange.host,
      path: exchange.path,
      status: exchange.status,
      source: exchange.source,
      tags: exchange.tags,
      requestRaw: exchange.requestRaw,
      responseRaw: exchange.responseRaw,
    }));
  return [...fixturePairs, ...selectedExchanges].slice(0, 16);
}

function buildAnvilReportAttachments(request: AnvilParityEvidenceRequest) {
  return [
    attachment('definition', request.definition.id, true),
    ...(request.library ? [attachment('rule-library', request.library.id, true)] : []),
    ...(request.validationRun ? [attachment('fixture-validation', request.validationRun.id, request.validationRun.reportReady)] : []),
    ...(request.headlessRun ? [attachment('headless-run', request.headlessRun.id, request.headlessRun.reportReady)] : []),
    ...(request.packageReview ? [attachment('package-review', request.packageReview.id, request.packageReview.status !== 'blocked')] : []),
    ...(request.promotedIssue ? [attachment('scanner-finding', request.promotedIssue.id, request.promotedIssue.status !== 'false-positive')] : []),
  ];
}

function attachment(kind: AnvilParityEvidencePackage['reportAttachments'][number]['kind'], artifactId: string, reportReady: boolean) {
  return {
    id: `${artifactId}-${kind}`,
    kind,
    artifactId,
    reportReady,
    redactionPhase: 'report-export-only' as const,
  };
}

function anvilOperationalSecretSignals(...rawValues: string[]) {
  const text = rawValues.join('\n');
  const signals: string[] = [];
  if (/^authorization:\s*\S+/im.test(text)) signals.push('authorization-header');
  if (/^cookie:\s*\S+/im.test(text)) signals.push('cookie-header');
  if (/^x-api-key:\s*\S+/im.test(text)) signals.push('x-api-key-header');
  if (/^idempotency-key:\s*\S+/im.test(text)) signals.push('idempotency-key-header');
  if (/(bearer\s+[a-z0-9._~+/=-]+|api[_-]?key|access[_-]?token|refresh[_-]?token|secret|session=|eyJ[a-z0-9_-]+\.)/i.test(text)) {
    signals.push('secret-like-material');
  }
  return Array.from(new Set(signals));
}

function simpleDigest(value: string) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `${hash.toString(16).padStart(8, '0')}${value.length.toString(16).padStart(8, '0')}`;
}
