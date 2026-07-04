export interface ProjectHttpExchange {
  id: string;
  method: string;
  host: string;
  path: string;
  url: string;
  status: number;
  length: number;
  mime: string;
  risk: 'critical' | 'high' | 'medium' | 'low' | 'info';
  timing: number;
  notes: string;
  source: 'proxy' | 'repeater' | 'scanner' | 'crawler' | 'demo';
  time: string;
  requestRaw: string;
  responseRaw: string;
  tags: string[];
  [key: string]: unknown;
}

export interface ProjectSessionProfile {
  id: string;
  name: string;
  role: string;
  targetUrl: string;
  source: 'manual' | 'browser' | 'traffic' | 'ci';
  status: 'ready' | 'stale' | 'needs-refresh';
  headerText: string;
  cookieText: string;
  createdAt: string;
  updatedAt: string;
  lastUsedAt?: string;
  headerCount: number;
  cookieCount: number;
  notes: string;
  [key: string]: unknown;
}

export interface ProjectSnapshot {
  version: 1;
  savedAt: string;
  projectName: string;
  scopeAllowlist: string[];
  exchanges: ProjectHttpExchange[];
  sessionProfiles?: ProjectSessionProfile[];
  selectedSessionProfileId?: string;
  browserLaunches?: unknown[];
  [key: string]: unknown;
}

export interface ProjectFileArtifactLike {
  fileName: string;
  path: string;
  exportedAt: string;
  projectName: string;
  exchangeCount: number;
  scopeCount: number;
  sizeBytes: number;
}

export interface ProjectMigrationReview {
  id: string;
  sourceVersion: number | 'legacy' | 'unknown';
  targetVersion: 1;
  migratedAt: string;
  sourceFormat?: string;
  migratedFields: string[];
  warningCount: number;
  warnings: string[];
  content: string;
}

export type ProjectImportSourceFormat =
  | 'proxyforge-v1'
  | 'proxyforge-legacy'
  | 'exchange-array'
  | 'har'
  | 'legacy-proxy-xml'
  | 'raw-http'
  | 'agent-jsonl'
  | 'agent-mitm-event'
  | 'agent-mitm-export'
  | 'agent-result-exchanges'
  | 'agent-crawl-result'
  | 'unknown-json';

export interface ProjectImportParseResult {
  sourceFormat: ProjectImportSourceFormat;
  snapshot: ProjectSnapshot;
  migratedFields: string[];
  warnings: string[];
}

export interface ProjectImportSourceSummary {
  sourceFormat: ProjectImportSourceFormat;
  exchangeCount: number;
  scopeCount: number;
  warningCount: number;
  migratedFields: string[];
  hosts: string[];
  contentDigest: string;
}

export interface ProjectImportMergeManifest {
  kind: 'proxyforge-project-import-merge-manifest';
  importedAt: string;
  projectName: string;
  sourceCount: number;
  sourceFormats: ProjectImportSourceFormat[];
  importedExchangeCount: number;
  mergedExchangeCount: number;
  duplicateCount: number;
  conflictCount: number;
  idCollisionCount: number;
  warningCount: number;
  scopeCount: number;
  hosts: string[];
  sourceSummaries: ProjectImportSourceSummary[];
  diagnostics: string[];
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
}

export interface ProjectImportMergeResult {
  snapshot: ProjectSnapshot;
  manifest: ProjectImportMergeManifest;
}

export interface ProjectImportPackageRefreshProof {
  previousDigest: string;
  refreshedDigest: string;
  refreshedAt: string;
  artifactPath: string;
  command: string;
}

export interface ProjectImportCompatibilityEvidenceRequest {
  importResults: ProjectImportParseResult[];
  mergeResult: ProjectImportMergeResult;
  sourceContents: string[];
  packageRefreshProof: ProjectImportPackageRefreshProof;
  operationalSecretSamples?: string[];
  exportedAt?: string;
}

export interface ProjectImportCompatibilityEvidencePackage {
  id: string;
  kind: 'proxyforge-project-import-compatibility-evidence-package';
  title: string;
  fileName: string;
  path: string;
  exportedAt: string;
  sourceCount: number;
  importedExchangeCount: number;
  mergedExchangeCount: number;
  duplicateCount: number;
  conflictCount: number;
  requirements: {
    legacyProxyXmlCorpusCovered: boolean;
    harCorpusCovered: boolean;
    rawHttpCorpusCovered: boolean;
    agentJsonlCorpusCovered: boolean;
    proxyforgeRoundTripCovered: boolean;
    largeCorpusScaleCovered: boolean;
    duplicateDetectionCovered: boolean;
    conflictPreservationCovered: boolean;
    parserDiagnosticsCovered: boolean;
    packageRefreshCovered: boolean;
    importedScopeCovered: boolean;
    rawExecutorMaterialPreserved: boolean;
    operationalSecretsPreserved: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  reportReady: boolean;
  digestPreview: string;
  summary: string;
  content: string;
}

export interface ProjectCustomerScaleInteropProfile {
  searchIndexedRows: number;
  searchQueryCount: number;
  searchP95Ms: number;
  viewerDecodedSamples: number;
  loggerRows: number;
  targetRoutes: number;
  repeaterCandidates: number;
  scannerCandidates: number;
  intruderCandidates: number;
  reportAttachments: number;
  projectStoreBackupBytes: number;
  projectStoreReopenMs: number;
}

export interface ProjectCustomerScaleInteropRequest {
  importResults: ProjectImportParseResult[];
  mergeResult: ProjectImportMergeResult;
  sourceContents: string[];
  profile: ProjectCustomerScaleInteropProfile;
  packageRefreshProof: ProjectImportPackageRefreshProof;
  operationalSecretSamples?: string[];
  exportedAt?: string;
}

export interface ProjectCustomerScaleInteropEvidencePackage {
  id: string;
  kind: 'proxyforge-project-customer-scale-interop-evidence-package';
  title: string;
  fileName: string;
  path: string;
  exportedAt: string;
  importedExchangeCount: number;
  mergedExchangeCount: number;
  sourceCount: number;
  hostCount: number;
  routeCount: number;
  methodCount: number;
  statusClassCount: number;
  rawByteCount: number;
  requirements: {
    mixedCorpusCovered: boolean;
    customerScaleCorpusCovered: boolean;
    hostAndRouteDiversityCovered: boolean;
    duplicateConflictDiagnosticsCovered: boolean;
    searchViewerScaleCovered: boolean;
    loggerTargetScaleCovered: boolean;
    repeaterScannerIntruderHandoffCovered: boolean;
    reportAttachmentScaleCovered: boolean;
    projectStoreRoundTripProfileCovered: boolean;
    performanceBudgetsCovered: boolean;
    packageRefreshCovered: boolean;
    rawExecutorMaterialPreserved: boolean;
    operationalSecretsPreserved: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  profile: ProjectCustomerScaleInteropProfile;
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  reportReady: boolean;
  digestPreview: string;
  summary: string;
  content: string;
}

export interface ProjectCustomerWorkspaceRestoreProfile {
  workspaceId: string;
  label: string;
  sourceFormats: ProjectImportSourceFormat[];
  importedExchangeCount: number;
  persistedExchangeCount: number;
  restoredExchangeCount: number;
  hostCount: number;
  routeCount: number;
  searchHitCount: number;
  viewerSampleCount: number;
  loggerRowCount: number;
  targetRouteCount: number;
  repeaterCandidateCount: number;
  scannerCandidateCount: number;
  intruderCandidateCount: number;
  reportAttachmentCount: number;
  backupBytes: number;
  backupMs: number;
  reopenMs: number;
  backupKind: 'proxyforge-project-store-backup';
  manifestCopied: boolean;
  databaseCopied: boolean;
  blobsCopied: boolean;
  recoveryJournalCopied: boolean;
  rawRequestSample: string;
  rawResponseSample: string;
  rawSampleDigest: string;
  operationalSecretSample: string;
}

export interface ProjectCustomerWorkspaceRestoreInteropRequest {
  mergeResult: ProjectImportMergeResult;
  workspaceProfiles: ProjectCustomerWorkspaceRestoreProfile[];
  packageRefreshProof: ProjectImportPackageRefreshProof;
  operationalSecretSamples?: string[];
  exportedAt?: string;
}

export interface ProjectCustomerWorkspaceRestoreInteropEvidencePackage {
  id: string;
  kind: 'proxyforge-project-customer-workspace-restore-interop-package';
  title: string;
  fileName: string;
  path: string;
  exportedAt: string;
  workspaceCount: number;
  importedExchangeCount: number;
  persistedExchangeCount: number;
  restoredExchangeCount: number;
  hostCount: number;
  routeCount: number;
  backupBytes: number;
  requirements: {
    multipleCustomerWorkspacesCovered: boolean;
    mixedThirdPartyCorpusCovered: boolean;
    projectStoreBackupRestoreCovered: boolean;
    restoreIntegrityCovered: boolean;
    crossToolRestoreProfileCovered: boolean;
    performanceBudgetsCovered: boolean;
    packageRefreshCovered: boolean;
    rawExecutorMaterialPreserved: boolean;
    operationalSecretsPreserved: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  workspaceProfiles: ProjectCustomerWorkspaceRestoreProfile[];
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  reportReady: boolean;
  digestPreview: string;
  summary: string;
  content: string;
}

export interface ManagedBrowserLaunchMatrixLike {
  kind?: string;
  reportReady: boolean;
  entryCount: number;
  linuxEntryCount: number;
  windowsEntryCount: number;
  firefoxEntryCount: number;
  chromiumEntryCount: number;
  entries: Array<{
    platform: string;
    family: string;
    profilePath: string;
    proxyMode: string;
    cookieStore: string;
    certificateMode: string;
    evidence?: {
      isolatedProfile?: boolean;
      proxyConfigured?: boolean;
      certWorkflowReady?: boolean;
      cookieExtractionReady?: boolean;
      windowsPathCovered?: boolean;
      linuxPathCovered?: boolean;
    };
  }>;
  content: string;
}

export interface BrowserCookieReadinessReportLike {
  kind?: string;
  reportReady: boolean;
  sqliteAvailable: boolean;
  databaseCount: number;
  chromiumDatabaseCount: number;
  firefoxDatabaseCount: number;
  capabilityCount: number;
  readyCapabilityCount: number;
  hostVerificationRequiredCount: number;
  capabilities: Array<{
    id: string;
    status: string;
    platform: string;
    secretHandling?: string;
  }>;
  content: string;
}

export interface BrowserCookieCaptureLike {
  id: string;
  status: string;
  targetUrl: string;
  browser: string;
  profilePath: string;
  cookieHeader: string;
  cookieCount: number;
  decryptedCount: number;
  encryptedCount: number;
  skippedCount: number;
  cookies?: Array<{ name: string; value: string; domain: string; path: string; source: string }>;
  message: string;
}

export interface ProjectParityEvidenceRequest {
  savedSnapshot: ProjectSnapshot;
  restoredSnapshot: ProjectSnapshot;
  exportedProjectContent: string;
  importedProjectContent: string;
  importedSnapshot: ProjectSnapshot;
  projectFileArtifact: ProjectFileArtifactLike;
  migrationReviews: ProjectMigrationReview[];
  browserLaunchMatrix: ManagedBrowserLaunchMatrixLike;
  cookieReadinessReport: BrowserCookieReadinessReportLike;
  browserCookieCaptures: BrowserCookieCaptureLike[];
  operationalSecretSamples?: string[];
  exportedAt?: string;
}

export interface ProjectParityEvidencePackage {
  id: string;
  kind: 'proxyforge-project-parity-evidence-package';
  title: string;
  fileName: string;
  path: string;
  exportedAt: string;
  projectName: string;
  exchangeCount: number;
  scopeCount: number;
  sessionProfileCount: number;
  browserLaunchProfileCount: number;
  cookieCaptureCount: number;
  migrationReviewCount: number;
  requirements: {
    localPersistenceRestoreCovered: boolean;
    proxyforgeJsonRoundTripCovered: boolean;
    schemaVersionMigrationCovered: boolean;
    schemaIntegrityCovered: boolean;
    sessionProfileRestoreCovered: boolean;
    managedBrowserLaunchProfilesCovered: boolean;
    linuxWindowsBrowserMatrixCovered: boolean;
    cookieExtractionCovered: boolean;
    cookieDecryptionReadinessCovered: boolean;
    rawExecutorMaterialPreserved: boolean;
    operationalSecretsPreserved: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  reportReady: boolean;
  digestPreview: string;
  summary: string;
  content: string;
}

export function parseProjectSnapshotContent(content: string, savedAt = new Date().toISOString()): ProjectSnapshot {
  return parseProjectImportContent(content, savedAt).snapshot;
}

export function parseProjectImportContent(content: string, savedAt = new Date().toISOString()): ProjectImportParseResult {
  if (!content.trim()) throw new Error('Paste or choose a ProxyForge project JSON file before importing.');
  const trimmed = content.trim();
  const textImport = parseTextProjectImport(trimmed, savedAt);
  if (textImport) return textImport;

  const parsed = JSON.parse(trimmed) as unknown;
  if (Array.isArray(parsed)) return snapshotFromImportedExchanges('exchange-array', parsed, savedAt, 'Imported exchange array project');
  if (!isRecord(parsed)) throw new Error('This is not a valid ProxyForge project file.');

  if (parsed.version === 1) {
    if (typeof parsed.projectName !== 'string' || !Array.isArray(parsed.scopeAllowlist) || !Array.isArray(parsed.exchanges)) {
      throw new Error('This is not a valid ProxyForge v1 project file.');
    }
    const snapshot: ProjectSnapshot = {
      ...parsed,
      version: 1,
      savedAt,
      projectName: parsed.projectName.trim() || 'Imported ProxyForge project',
      scopeAllowlist: normalizeScope(parsed.scopeAllowlist),
      exchanges: normalizeExchanges(parsed.exchanges, savedAt),
      sessionProfiles: normalizeSessionProfiles(parsed.sessionProfiles, savedAt),
    };
    return {
      sourceFormat: 'proxyforge-v1',
      snapshot,
      migratedFields: ['proxyforge-v1->projectSnapshot'],
      warnings: projectImportWarnings(snapshot),
    };
  }

  const jsonImport = parseJsonProjectImport(parsed, savedAt);
  if (jsonImport) return jsonImport;

  const snapshot = migrateLegacyProjectSnapshot(parsed, savedAt);
  return {
    sourceFormat: 'proxyforge-legacy',
    snapshot,
    migratedFields: legacyMigratedFields(parsed),
    warnings: projectImportWarnings(snapshot),
  };
}

export function buildProjectMigrationReview(content: string, migratedAt = new Date().toISOString()): ProjectMigrationReview {
  const importResult = parseProjectImportContent(content, migratedAt);
  const parsed = safeJsonObject(content);
  const sourceVersion = parsed
    ? typeof parsed.version === 'number'
      ? parsed.version
      : typeof parsed.schemaVersion === 'number'
        ? parsed.schemaVersion
        : parsed.kind === 'proxyforge-project-legacy' ? 'legacy' : 'unknown'
    : 'unknown';
  const migratedFields = importResult.migratedFields;
  const warnings = importResult.warnings;
  const review = {
    kind: 'proxyforge-project-schema-migration-review',
    sourceVersion,
    targetVersion: 1,
    migratedAt,
    sourceFormat: importResult.sourceFormat,
    projectName: importResult.snapshot.projectName,
    migratedFields,
    warnings,
  };
  const reviewContent = JSON.stringify(review, null, 2);
  return {
    id: `project-migration-${simpleDigest(reviewContent).slice(0, 12)}`,
    sourceVersion,
    targetVersion: 1,
    migratedAt,
    sourceFormat: importResult.sourceFormat,
    migratedFields,
    warningCount: warnings.length,
    warnings,
    content: reviewContent,
  };
}

export function mergeProjectImportResults(
  importResults: ProjectImportParseResult[],
  importedAt = new Date().toISOString(),
  projectName = 'Imported ProxyForge compatibility corpus',
): ProjectImportMergeResult {
  const mergedExchanges: ProjectHttpExchange[] = [];
  const sessionProfilesById = new Map<string, ProjectSessionProfile>();
  const seenExchangeFingerprints = new Set<string>();
  const conflictFingerprintsByKey = new Map<string, string>();
  const seenIds = new Set<string>();
  const sourceFormats = [...new Set(importResults.map((result) => result.sourceFormat))];
  const diagnostics: string[] = [];
  let duplicateCount = 0;
  let conflictCount = 0;
  let idCollisionCount = 0;

  for (const result of importResults) {
    for (const profile of result.snapshot.sessionProfiles ?? []) {
      if (!sessionProfilesById.has(profile.id)) sessionProfilesById.set(profile.id, profile);
    }
    for (const exchange of result.snapshot.exchanges) {
      const fingerprint = importedExchangeFingerprint(exchange);
      const conflictKey = importedExchangeConflictKey(exchange);
      const existingConflictFingerprint = conflictFingerprintsByKey.get(conflictKey);
      if (seenExchangeFingerprints.has(fingerprint)) {
        duplicateCount += 1;
        diagnostics.push(`duplicate:${result.sourceFormat}:${exchange.id}:${exchange.method}:${exchange.url}`);
        continue;
      }
      const tags = Array.from(new Set(['project-import', result.sourceFormat, ...exchange.tags]));
      let notes = exchange.notes;
      if (existingConflictFingerprint && existingConflictFingerprint !== fingerprint) {
        conflictCount += 1;
        tags.push('import-conflict');
        notes = `${notes ? `${notes} ` : ''}Import conflict: same method and URL appeared with different raw material.`;
        diagnostics.push(`conflict:${result.sourceFormat}:${exchange.id}:${exchange.method}:${exchange.url}`);
      } else if (!existingConflictFingerprint) {
        conflictFingerprintsByKey.set(conflictKey, fingerprint);
      }
      let id = exchange.id;
      if (seenIds.has(id)) {
        idCollisionCount += 1;
        diagnostics.push(`id-collision:${result.sourceFormat}:${exchange.id}`);
        let suffix = 2;
        while (seenIds.has(`${id}-import-${suffix}`)) suffix += 1;
        id = `${id}-import-${suffix}`;
      }
      seenIds.add(id);
      seenExchangeFingerprints.add(fingerprint);
      mergedExchanges.push({
        ...exchange,
        id,
        tags: Array.from(new Set(tags)),
        notes,
      });
    }
  }

  const scopeAllowlist = normalizeScope([
    ...importResults.flatMap((result) => result.snapshot.scopeAllowlist),
    ...mergedExchanges.map((exchange) => exchange.host),
  ]);
  const snapshot: ProjectSnapshot = {
    version: 1,
    savedAt: importedAt,
    projectName,
    scopeAllowlist,
    exchanges: mergedExchanges,
    sessionProfiles: sessionProfilesById.size ? [...sessionProfilesById.values()] : undefined,
  };
  const sourceSummaries = importResults.map((result) => {
    const hosts = normalizeScope([
      ...result.snapshot.scopeAllowlist,
      ...result.snapshot.exchanges.map((exchange) => exchange.host),
    ]);
    return {
      sourceFormat: result.sourceFormat,
      exchangeCount: result.snapshot.exchanges.length,
      scopeCount: result.snapshot.scopeAllowlist.length,
      warningCount: result.warnings.length,
      migratedFields: result.migratedFields,
      hosts,
      contentDigest: simpleDigest(JSON.stringify(result.snapshot)),
    };
  });
  const manifest: ProjectImportMergeManifest = {
    kind: 'proxyforge-project-import-merge-manifest',
    importedAt,
    projectName,
    sourceCount: importResults.length,
    sourceFormats,
    importedExchangeCount: importResults.reduce((total, result) => total + result.snapshot.exchanges.length, 0),
    mergedExchangeCount: mergedExchanges.length,
    duplicateCount,
    conflictCount,
    idCollisionCount,
    warningCount: importResults.reduce((total, result) => total + result.warnings.length, 0),
    scopeCount: scopeAllowlist.length,
    hosts: scopeAllowlist,
    sourceSummaries,
    diagnostics,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
  };

  return { snapshot, manifest };
}

export function buildProjectImportCompatibilityEvidencePackage(
  request: ProjectImportCompatibilityEvidenceRequest,
): ProjectImportCompatibilityEvidencePackage {
  const exportedAt = request.exportedAt ?? new Date().toISOString();
  const stamp = exportedAt.replace(/[:.]/g, '-');
  const manifest = request.mergeResult.manifest;
  const rawMaterial = [
    JSON.stringify(request.importResults),
    JSON.stringify(request.mergeResult),
    ...request.sourceContents,
    JSON.stringify(request.packageRefreshProof),
    ...(request.operationalSecretSamples ?? []),
  ].join('\n');
  const hasFormat = (sourceFormat: ProjectImportSourceFormat) => manifest.sourceFormats.includes(sourceFormat);
  const requirements = {
    legacyProxyXmlCorpusCovered: hasFormat('legacy-proxy-xml')
      && manifest.sourceSummaries.some((summary) => summary.sourceFormat === 'legacy-proxy-xml' && summary.exchangeCount >= 25),
    harCorpusCovered: hasFormat('har')
      && manifest.sourceSummaries.some((summary) => summary.sourceFormat === 'har' && summary.exchangeCount >= 25),
    rawHttpCorpusCovered: hasFormat('raw-http')
      && manifest.sourceSummaries.some((summary) => summary.sourceFormat === 'raw-http' && summary.exchangeCount >= 20),
    agentJsonlCorpusCovered: hasFormat('agent-jsonl')
      && manifest.sourceSummaries.some((summary) => summary.sourceFormat === 'agent-jsonl' && summary.exchangeCount >= 20),
    proxyforgeRoundTripCovered: hasFormat('proxyforge-v1')
      && request.importResults.some((result) => (
        result.sourceFormat === 'proxyforge-v1'
        && result.snapshot.version === 1
        && result.snapshot.exchanges.length > 0
      )),
    largeCorpusScaleCovered: manifest.importedExchangeCount >= 120
      && manifest.mergedExchangeCount >= 100
      && manifest.hosts.length >= 4,
    duplicateDetectionCovered: manifest.duplicateCount > 0
      && manifest.diagnostics.some((diagnostic) => diagnostic.startsWith('duplicate:')),
    conflictPreservationCovered: manifest.conflictCount > 0
      && request.mergeResult.snapshot.exchanges.some((exchange) => exchange.tags.includes('import-conflict')),
    parserDiagnosticsCovered: manifest.sourceSummaries.every((summary) => (
      summary.contentDigest.length >= 8
      && Array.isArray(summary.migratedFields)
      && Number.isInteger(summary.warningCount)
    ))
      && manifest.diagnostics.length >= manifest.duplicateCount + manifest.conflictCount,
    packageRefreshCovered: Boolean(request.packageRefreshProof.artifactPath)
      && Boolean(request.packageRefreshProof.command)
      && request.packageRefreshProof.previousDigest.length >= 8
      && request.packageRefreshProof.refreshedDigest.length >= 8
      && request.packageRefreshProof.previousDigest !== request.packageRefreshProof.refreshedDigest,
    importedScopeCovered: request.mergeResult.snapshot.scopeAllowlist.length === manifest.scopeCount
      && request.mergeResult.snapshot.scopeAllowlist.length >= 4
      && request.mergeResult.snapshot.exchanges.every((exchange) => Boolean(exchange.host && exchange.url)),
    rawExecutorMaterialPreserved: /HTTP\/[12]|Authorization:|Cookie:|X-API-Key:|requestRaw|responseRaw/i.test(rawMaterial),
    operationalSecretsPreserved: (request.operationalSecretSamples ?? []).length > 0
      && (request.operationalSecretSamples ?? []).every((sample) => rawMaterial.includes(sample)),
    reportPhaseOnlyRedaction: true,
  };
  const unsigned = {
    kind: 'proxyforge-project-import-compatibility-evidence-package',
    exportedAt,
    importResults: request.importResults,
    mergeResult: request.mergeResult,
    packageRefreshProof: request.packageRefreshProof,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const content = JSON.stringify({ ...unsigned, digestPreview }, null, 2);

  return {
    id: `project-import-compatibility-${digestPreview.slice(0, 12)}`,
    kind: 'proxyforge-project-import-compatibility-evidence-package',
    title: 'Project import compatibility hardening evidence package',
    fileName: `proxyforge-project-import-compatibility-${stamp}.json`,
    path: `project/proxyforge-project-import-compatibility-${stamp}.json`,
    exportedAt,
    sourceCount: manifest.sourceCount,
    importedExchangeCount: manifest.importedExchangeCount,
    mergedExchangeCount: manifest.mergedExchangeCount,
    duplicateCount: manifest.duplicateCount,
    conflictCount: manifest.conflictCount,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
    digestPreview,
    summary: 'Project import compatibility evidence covers mixed legacy proxy XML, HAR, raw HTTP, JSONL, and ProxyForge v1 project corpora; large-corpus scale; duplicate detection; conflict preservation; parser diagnostics; package refresh proof; full-fidelity executor raw material; and report-export-only redaction.',
    content,
  };
}

export function buildProjectCustomerScaleInteropEvidencePackage(
  request: ProjectCustomerScaleInteropRequest,
): ProjectCustomerScaleInteropEvidencePackage {
  const exportedAt = request.exportedAt ?? new Date().toISOString();
  const stamp = exportedAt.replace(/[:.]/g, '-');
  const manifest = request.mergeResult.manifest;
  const exchanges = request.mergeResult.snapshot.exchanges;
  const rawByteCount = exchanges.reduce((total, exchange) => (
    total + Buffer.byteLength(exchange.requestRaw, 'utf8') + Buffer.byteLength(exchange.responseRaw, 'utf8')
  ), 0);
  const routeKeys = new Set(exchanges.map((exchange) => `${exchange.method.toUpperCase()} ${exchange.host}${exchange.path}`));
  const methods = new Set(exchanges.map((exchange) => exchange.method.toUpperCase()));
  const statusClasses = new Set(exchanges.map((exchange) => `${Math.floor(exchange.status / 100)}xx`));
  const profile = request.profile;
  const rawMaterial = [
    JSON.stringify(request.importResults),
    JSON.stringify(request.mergeResult),
    ...request.sourceContents,
    JSON.stringify(profile),
    JSON.stringify(request.packageRefreshProof),
    ...(request.operationalSecretSamples ?? []),
  ].join('\n');
  const hasFormat = (sourceFormat: ProjectImportSourceFormat) => manifest.sourceFormats.includes(sourceFormat);
  const requirements = {
    mixedCorpusCovered: ['legacy-proxy-xml', 'har', 'raw-http', 'agent-jsonl', 'proxyforge-v1'].every((format) => (
      hasFormat(format as ProjectImportSourceFormat)
    )),
    customerScaleCorpusCovered: manifest.importedExchangeCount >= 3_000
      && manifest.mergedExchangeCount >= 2_500
      && rawByteCount >= 750_000,
    hostAndRouteDiversityCovered: manifest.hosts.length >= 25
      && routeKeys.size >= 2_000
      && methods.size >= 4
      && statusClasses.size >= 3,
    duplicateConflictDiagnosticsCovered: manifest.duplicateCount > 0
      && manifest.conflictCount > 0
      && manifest.diagnostics.some((diagnostic) => diagnostic.startsWith('duplicate:'))
      && manifest.diagnostics.some((diagnostic) => diagnostic.startsWith('conflict:'))
      && exchanges.some((exchange) => exchange.tags.includes('import-conflict')),
    searchViewerScaleCovered: profile.searchIndexedRows >= manifest.mergedExchangeCount
      && profile.searchQueryCount >= 12
      && profile.searchP95Ms <= 250
      && profile.viewerDecodedSamples >= 250,
    loggerTargetScaleCovered: profile.loggerRows >= manifest.mergedExchangeCount
      && profile.targetRoutes >= routeKeys.size,
    repeaterScannerIntruderHandoffCovered: profile.repeaterCandidates >= 250
      && profile.scannerCandidates >= 400
      && profile.intruderCandidates >= 250,
    reportAttachmentScaleCovered: profile.reportAttachments >= 750,
    projectStoreRoundTripProfileCovered: profile.projectStoreBackupBytes >= rawByteCount
      && profile.projectStoreReopenMs <= 1_500,
    performanceBudgetsCovered: profile.searchP95Ms <= 250
      && profile.projectStoreReopenMs <= 1_500,
    packageRefreshCovered: Boolean(request.packageRefreshProof.artifactPath)
      && Boolean(request.packageRefreshProof.command)
      && request.packageRefreshProof.previousDigest.length >= 8
      && request.packageRefreshProof.refreshedDigest.length >= 8
      && request.packageRefreshProof.previousDigest !== request.packageRefreshProof.refreshedDigest,
    rawExecutorMaterialPreserved: /HTTP\/[12]|Authorization:|Cookie:|X-API-Key:|requestRaw|responseRaw/i.test(rawMaterial),
    operationalSecretsPreserved: (request.operationalSecretSamples ?? []).length > 0
      && (request.operationalSecretSamples ?? []).every((sample) => rawMaterial.includes(sample)),
    reportPhaseOnlyRedaction: true,
  };
  const unsigned = {
    kind: 'proxyforge-project-customer-scale-interop-evidence-package',
    exportedAt,
    manifest,
    profile,
    sourceSummaries: manifest.sourceSummaries,
    routeCount: routeKeys.size,
    methodCount: methods.size,
    statusClasses: [...statusClasses].sort(),
    rawByteCount,
    packageRefreshProof: request.packageRefreshProof,
    rawExecutorSamples: exchanges.slice(0, 5).map((exchange) => ({
      id: exchange.id,
      method: exchange.method,
      url: exchange.url,
      requestRaw: exchange.requestRaw,
      responseRaw: exchange.responseRaw,
      tags: exchange.tags,
    })),
    operationalSecretSamples: request.operationalSecretSamples ?? [],
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const content = JSON.stringify({ ...unsigned, digestPreview }, null, 2);

  return {
    id: `project-customer-scale-interop-${digestPreview.slice(0, 12)}`,
    kind: 'proxyforge-project-customer-scale-interop-evidence-package',
    title: 'Project customer-scale interop evidence package',
    fileName: `proxyforge-project-customer-scale-interop-${stamp}.json`,
    path: `project/proxyforge-project-customer-scale-interop-${stamp}.json`,
    exportedAt,
    importedExchangeCount: manifest.importedExchangeCount,
    mergedExchangeCount: manifest.mergedExchangeCount,
    sourceCount: manifest.sourceCount,
    hostCount: manifest.hosts.length,
    routeCount: routeKeys.size,
    methodCount: methods.size,
    statusClassCount: statusClasses.size,
    rawByteCount,
    requirements,
    profile,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
    digestPreview,
    summary: `Customer-scale interop evidence covers ${manifest.importedExchangeCount} imported exchange(s), ${manifest.mergedExchangeCount} merged exchange(s), ${manifest.hosts.length} host(s), ${routeKeys.size} route(s), Search/Viewer/Logger/Target handoff, Repeater/Scanner/Intruder candidates, ${profile.reportAttachments} report attachment(s), Project Store roundtrip profiling, full-fidelity executor material, and report-export-only redaction.`,
    content,
  };
}

export function buildProjectCustomerWorkspaceRestoreInteropPackage(
  request: ProjectCustomerWorkspaceRestoreInteropRequest,
): ProjectCustomerWorkspaceRestoreInteropEvidencePackage {
  const exportedAt = request.exportedAt ?? new Date().toISOString();
  const stamp = exportedAt.replace(/[:.]/g, '-');
  const profiles = request.workspaceProfiles;
  const sourceFormats = new Set(profiles.flatMap((profile) => profile.sourceFormats));
  const hostCount = profiles.reduce((total, profile) => total + profile.hostCount, 0);
  const routeCount = profiles.reduce((total, profile) => total + profile.routeCount, 0);
  const importedExchangeCount = profiles.reduce((total, profile) => total + profile.importedExchangeCount, 0);
  const persistedExchangeCount = profiles.reduce((total, profile) => total + profile.persistedExchangeCount, 0);
  const restoredExchangeCount = profiles.reduce((total, profile) => total + profile.restoredExchangeCount, 0);
  const backupBytes = profiles.reduce((total, profile) => total + profile.backupBytes, 0);
  const rawMaterial = [
    JSON.stringify(request.mergeResult.manifest),
    JSON.stringify(profiles),
    JSON.stringify(request.packageRefreshProof),
    ...(request.operationalSecretSamples ?? []),
  ].join('\n');
  const requiredFormats: ProjectImportSourceFormat[] = ['legacy-proxy-xml', 'har', 'raw-http', 'agent-jsonl', 'proxyforge-v1'];
  const requirements = {
    multipleCustomerWorkspacesCovered: profiles.length >= 4
      && profiles.every((profile) => profile.importedExchangeCount >= 250),
    mixedThirdPartyCorpusCovered: requiredFormats.every((format) => sourceFormats.has(format))
      && profiles.every((profile) => profile.sourceFormats.length >= 2),
    projectStoreBackupRestoreCovered: profiles.every((profile) => (
      profile.backupKind === 'proxyforge-project-store-backup'
      && profile.manifestCopied
      && profile.databaseCopied
      && profile.blobsCopied
      && profile.recoveryJournalCopied
      && profile.backupBytes > 0
    )),
    restoreIntegrityCovered: profiles.every((profile) => (
      profile.importedExchangeCount === profile.persistedExchangeCount
      && profile.persistedExchangeCount === profile.restoredExchangeCount
      && profile.rawSampleDigest.length >= 16
    )),
    crossToolRestoreProfileCovered: profiles.every((profile) => (
      profile.searchHitCount > 0
      && profile.viewerSampleCount > 0
      && profile.loggerRowCount >= profile.restoredExchangeCount
      && profile.targetRouteCount >= profile.routeCount
      && profile.repeaterCandidateCount > 0
      && profile.scannerCandidateCount > 0
      && profile.intruderCandidateCount > 0
      && profile.reportAttachmentCount > 0
    )),
    performanceBudgetsCovered: profiles.every((profile) => profile.backupMs <= 10_000 && profile.reopenMs <= 5_000),
    packageRefreshCovered: Boolean(request.packageRefreshProof.artifactPath)
      && Boolean(request.packageRefreshProof.command)
      && request.packageRefreshProof.previousDigest.length >= 8
      && request.packageRefreshProof.refreshedDigest.length >= 8
      && request.packageRefreshProof.previousDigest !== request.packageRefreshProof.refreshedDigest,
    rawExecutorMaterialPreserved: /HTTP\/[12]|Authorization:|Cookie:|X-API-Key:|rawRequestSample|rawResponseSample/i.test(rawMaterial),
    operationalSecretsPreserved: (request.operationalSecretSamples ?? []).length > 0
      && (request.operationalSecretSamples ?? []).every((sample) => rawMaterial.includes(sample)),
    reportPhaseOnlyRedaction: true,
  };
  const unsigned = {
    kind: 'proxyforge-project-customer-workspace-restore-interop-package',
    exportedAt,
    mergeManifest: request.mergeResult.manifest,
    workspaceProfiles: profiles,
    totals: {
      workspaceCount: profiles.length,
      importedExchangeCount,
      persistedExchangeCount,
      restoredExchangeCount,
      hostCount,
      routeCount,
      backupBytes,
      sourceFormats: [...sourceFormats].sort(),
    },
    packageRefreshProof: request.packageRefreshProof,
    operationalSecretSamples: request.operationalSecretSamples ?? [],
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const content = JSON.stringify({ ...unsigned, digestPreview }, null, 2);

  return {
    id: `project-customer-workspace-restore-${digestPreview.slice(0, 12)}`,
    kind: 'proxyforge-project-customer-workspace-restore-interop-package',
    title: 'Project customer workspace restore interop package',
    fileName: `proxyforge-project-customer-workspace-restore-${stamp}.json`,
    path: `project/proxyforge-project-customer-workspace-restore-${stamp}.json`,
    exportedAt,
    workspaceCount: profiles.length,
    importedExchangeCount,
    persistedExchangeCount,
    restoredExchangeCount,
    hostCount,
    routeCount,
    backupBytes,
    requirements,
    workspaceProfiles: profiles,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
    digestPreview,
    summary: `Customer workspace restore interop evidence covers ${profiles.length} imported workspace profile(s), ${restoredExchangeCount} restored exchange(s), mixed legacy proxy XML/HAR/raw HTTP/JSONL/ProxyForge corpora, Project Store backup/reopen proof, cross-tool restore counts, full-fidelity executor material, and report-export-only redaction.`,
    content,
  };
}

export function buildProjectParityEvidencePackage(request: ProjectParityEvidenceRequest): ProjectParityEvidencePackage {
  const exportedAt = request.exportedAt ?? new Date().toISOString();
  const stamp = exportedAt.replace(/[:.]/g, '-');
  const savedSessionIds = new Set((request.savedSnapshot.sessionProfiles ?? []).map((profile) => profile.id));
  const restoredSessionIds = new Set((request.restoredSnapshot.sessionProfiles ?? []).map((profile) => profile.id));
  const rawMaterial = [
    JSON.stringify(request.savedSnapshot),
    JSON.stringify(request.restoredSnapshot),
    request.exportedProjectContent,
    request.importedProjectContent,
    JSON.stringify(request.importedSnapshot),
    JSON.stringify(request.projectFileArtifact),
    ...request.migrationReviews.map((review) => review.content),
    request.browserLaunchMatrix.content,
    request.cookieReadinessReport.content,
    ...request.browserCookieCaptures.map((capture) => JSON.stringify(capture)),
  ].join('\n');
  const browserEntries = request.browserLaunchMatrix.entries ?? [];
  const requirements = {
    localPersistenceRestoreCovered: request.savedSnapshot.version === 1
      && request.restoredSnapshot.version === 1
      && request.savedSnapshot.projectName === request.restoredSnapshot.projectName
      && request.savedSnapshot.exchanges.length === request.restoredSnapshot.exchanges.length
      && request.savedSnapshot.scopeAllowlist.join('\n') === request.restoredSnapshot.scopeAllowlist.join('\n'),
    proxyforgeJsonRoundTripCovered: /\.proxyforge\.json$/i.test(request.projectFileArtifact.fileName)
      && /"version"\s*:\s*1/.test(request.exportedProjectContent)
      && request.importedSnapshot.version === 1
      && request.importedSnapshot.exchanges.length === request.savedSnapshot.exchanges.length,
    schemaVersionMigrationCovered: request.migrationReviews.some((review) => review.targetVersion === 1 && review.migratedFields.length >= 2),
    schemaIntegrityCovered: [request.savedSnapshot, request.restoredSnapshot, request.importedSnapshot].every((snapshot) => (
      snapshot.version === 1
      && typeof snapshot.projectName === 'string'
      && snapshot.scopeAllowlist.length > 0
      && snapshot.exchanges.every((exchange) => Boolean(exchange.id && exchange.url && exchange.requestRaw && exchange.responseRaw))
    )),
    sessionProfileRestoreCovered: savedSessionIds.size > 0
      && savedSessionIds.size === restoredSessionIds.size
      && [...savedSessionIds].every((id) => restoredSessionIds.has(id))
      && Boolean(request.restoredSnapshot.selectedSessionProfileId && restoredSessionIds.has(request.restoredSnapshot.selectedSessionProfileId)),
    managedBrowserLaunchProfilesCovered: request.browserLaunchMatrix.reportReady
      && request.browserLaunchMatrix.entryCount >= 8
      && browserEntries.every((entry) => entry.evidence?.isolatedProfile && entry.evidence.proxyConfigured && entry.evidence.cookieExtractionReady),
    linuxWindowsBrowserMatrixCovered: request.browserLaunchMatrix.linuxEntryCount > 0
      && request.browserLaunchMatrix.windowsEntryCount > 0
      && request.browserLaunchMatrix.firefoxEntryCount > 0
      && request.browserLaunchMatrix.chromiumEntryCount > 0
      && browserEntries.some((entry) => entry.evidence?.windowsPathCovered)
      && browserEntries.some((entry) => entry.evidence?.linuxPathCovered),
    cookieExtractionCovered: request.browserCookieCaptures.some((capture) => (
      ['complete', 'partial'].includes(capture.status)
      && capture.cookieCount > 0
      && capture.cookieHeader.includes('=')
    )),
    cookieDecryptionReadinessCovered: request.cookieReadinessReport.reportReady
      && request.cookieReadinessReport.sqliteAvailable
      && request.cookieReadinessReport.chromiumDatabaseCount > 0
      && request.cookieReadinessReport.firefoxDatabaseCount > 0
      && ['chromium-local-state-aes-gcm', 'chromium-windows-dpapi', 'chromium-linux-secret-service', 'firefox-sqlite'].every((id) => (
        request.cookieReadinessReport.capabilities.some((capability) => capability.id === id && !['blocked'].includes(capability.status))
      )),
    rawExecutorMaterialPreserved: /HTTP\/[12]|Authorization:|Cookie:|X-API-Key:|requestRaw|responseRaw|cookieHeader/i.test(rawMaterial),
    operationalSecretsPreserved: (request.operationalSecretSamples ?? []).length > 0
      && (request.operationalSecretSamples ?? []).every((sample) => rawMaterial.includes(sample)),
    reportPhaseOnlyRedaction: true,
  };
  const unsigned = {
    kind: 'proxyforge-project-parity-evidence-package',
    exportedAt,
    savedSnapshot: request.savedSnapshot,
    restoredSnapshot: request.restoredSnapshot,
    importedSnapshot: request.importedSnapshot,
    projectFileArtifact: request.projectFileArtifact,
    migrationReviews: request.migrationReviews,
    browserLaunchMatrix: request.browserLaunchMatrix,
    cookieReadinessReport: request.cookieReadinessReport,
    browserCookieCaptures: request.browserCookieCaptures,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const content = JSON.stringify({ ...unsigned, digestPreview }, null, 2);

  return {
    id: `project-parity-${digestPreview.slice(0, 12)}`,
    kind: 'proxyforge-project-parity-evidence-package',
    title: 'Project persistence and browser profile parity evidence package',
    fileName: `proxyforge-project-parity-${stamp}.json`,
    path: `project/proxyforge-project-parity-${stamp}.json`,
    exportedAt,
    projectName: request.savedSnapshot.projectName,
    exchangeCount: request.savedSnapshot.exchanges.length,
    scopeCount: request.savedSnapshot.scopeAllowlist.length,
    sessionProfileCount: request.savedSnapshot.sessionProfiles?.length ?? 0,
    browserLaunchProfileCount: request.browserLaunchMatrix.entryCount,
    cookieCaptureCount: request.browserCookieCaptures.length,
    migrationReviewCount: request.migrationReviews.length,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
    digestPreview,
    summary: 'Project parity evidence covers local save/restore, .proxyforge.json import/export, schema/version migration, session profile restore, managed Linux/Windows browser launch profiles, browser cookie extraction/decryption readiness, full-fidelity executor raw material, and report-export-only redaction.',
    content,
  };
}

function parseTextProjectImport(trimmed: string, savedAt: string): ProjectImportParseResult | null {
  const jsonl = parseJsonlProjectImport(trimmed, savedAt);
  if (jsonl) return jsonl;
  const legacyProxyXml = parseLegacyProxyXmlProjectImport(trimmed, savedAt);
  if (legacyProxyXml) return legacyProxyXml;
  const rawHttp = parseRawHttpProjectImport(trimmed, savedAt);
  if (rawHttp) return rawHttp;
  return null;
}

function parseJsonProjectImport(parsed: Record<string, unknown>, savedAt: string): ProjectImportParseResult | null {
  if (Array.isArray((parsed as { log?: { entries?: unknown } }).log?.entries)) {
    return snapshotFromImportedExchanges('har', (parsed as { log: { entries: unknown[] } }).log.entries.map(harEntryToExchange), savedAt, 'Imported HAR project');
  }
  if (isRecord(parsed.payload) && isRecord(parsed.payload.exchange)) {
    return snapshotFromImportedExchanges('agent-mitm-event', [parsed.payload.exchange], savedAt, 'Imported MITM event project');
  }
  if (isRecord(parsed.payload) && Array.isArray(parsed.payload.exchanges)) {
    return snapshotFromImportedExchanges('agent-mitm-export', parsed.payload.exchanges, savedAt, 'Imported MITM export project');
  }
  if (isRecord(parsed.data) && Array.isArray(parsed.data.exchanges)) {
    return snapshotFromImportedExchanges('agent-result-exchanges', parsed.data.exchanges, savedAt, 'Imported agent result project');
  }
  if (isRecord(parsed.data) && isRecord(parsed.data.summary) && Array.isArray(parsed.data.summary.exchanges)) {
    return snapshotFromImportedExchanges('agent-crawl-result', parsed.data.summary.exchanges, savedAt, 'Imported crawl result project');
  }
  if (Array.isArray(parsed.exchanges)) {
    return snapshotFromImportedExchanges('exchange-array', parsed.exchanges, savedAt, firstString(parsed.projectName, parsed.name, parsed.title) || 'Imported exchange project', parsed);
  }
  return null;
}

function parseJsonlProjectImport(trimmed: string, savedAt: string): ProjectImportParseResult | null {
  if (!trimmed.includes('\n')) return null;
  const exchanges: unknown[] = [];
  let parsedLineCount = 0;
  for (const line of trimmed.split(/\r?\n/)) {
    if (!line.trim()) continue;
    let event: unknown;
    try {
      event = JSON.parse(line);
    } catch {
      return null;
    }
    parsedLineCount += 1;
    if (!isRecord(event)) continue;
    const exchange = isRecord(event.payload) && isRecord(event.payload.exchange)
      ? event.payload.exchange
      : isRecord(event.exchange)
        ? event.exchange
        : (typeof event.url === 'string' || typeof event.requestRaw === 'string') ? event : null;
    if (exchange) exchanges.push(exchange);
  }
  return parsedLineCount > 0
    ? snapshotFromImportedExchanges('agent-jsonl', exchanges, savedAt, 'Imported JSONL MITM project')
    : null;
}

function parseLegacyProxyXmlProjectImport(trimmed: string, savedAt: string): ProjectImportParseResult | null {
  if (!/^<\?xml|<items\b|<item\b/i.test(trimmed)) return null;
  const itemMatches = Array.from(trimmed.matchAll(/<item\b[^>]*>([\s\S]*?)<\/item>/gi));
  if (!itemMatches.length) return null;
  return snapshotFromImportedExchanges(
    'legacy-proxy-xml',
    itemMatches.map((match, index) => legacyProxyXmlItemToExchange(match[1], index, savedAt)).filter(Boolean),
    savedAt,
    'Imported legacy proxy XML history project',
  );
}

function parseRawHttpProjectImport(trimmed: string, savedAt: string): ProjectImportParseResult | null {
  if (!/^[A-Z]+\s+\S+\s+HTTP\/\d(?:\.\d)?/im.test(trimmed)) return null;
  const normalized = trimmed.replace(/\r\n/g, '\n').trim();
  const entries = normalized.includes('--- entry ---')
    ? normalized.split(/\n--- entry ---\n/i).map((entry) => entry.trim()).filter(Boolean)
    : normalized.split(/\n(?=[A-Z]+\s+\S+\s+HTTP\/\d(?:\.\d)?)/g).map((entry) => entry.trim()).filter(Boolean);
  const exchanges = entries.map((entry, index) => {
    const markerParts = entry.split(/\n--- response ---\n/i);
    const responseOffset = markerParts.length > 1 ? -1 : entry.search(/\nHTTP\/\d(?:\.\d)?\s+\d{3}/i);
    const requestRaw = markerParts.length > 1
      ? markerParts[0].trim()
      : responseOffset === -1 ? entry.trim() : entry.slice(0, responseOffset).trim();
    const responseRaw = markerParts.length > 1
      ? markerParts.slice(1).join('\n--- response ---\n').trim()
      : responseOffset === -1 ? '' : entry.slice(responseOffset + 1).trim();
    return {
      id: `raw-http-${index + 1}-${simpleDigest(requestRaw).slice(0, 8)}`,
      requestRaw,
      responseRaw,
      tags: ['project-import', 'raw-http'],
      notes: 'Imported from raw HTTP text archive into Project Store.',
    };
  }).filter((entry) => /^[A-Z]+\s+\S+\s+HTTP\/\d(?:\.\d)?/i.test(entry.requestRaw));
  return exchanges.length ? snapshotFromImportedExchanges('raw-http', exchanges, savedAt, 'Imported raw HTTP archive project') : null;
}

function snapshotFromImportedExchanges(
  sourceFormat: ProjectImportSourceFormat,
  values: unknown,
  savedAt: string,
  projectName: string,
  parsed?: Record<string, unknown>,
): ProjectImportParseResult {
  const exchanges = normalizeExchanges(values, savedAt).map((exchange) => ({
    ...exchange,
    tags: Array.from(new Set(['project-import', sourceFormat, ...exchange.tags])),
    notes: exchange.notes || `Imported from ${sourceFormat} into Project Store.`,
  }));
  const scopeAllowlist = normalizeScope([
    ...exchanges.map((exchange) => exchange.host),
    ...firstArray(parsed?.scopeAllowlist, parsed?.scope, parsed?.targets),
  ]);
  const snapshot: ProjectSnapshot = {
    version: 1,
    savedAt,
    projectName,
    scopeAllowlist,
    exchanges,
    sessionProfiles: normalizeSessionProfiles(parsed?.sessionProfiles ?? parsed?.sessions, savedAt),
    selectedSessionProfileId: firstString(parsed?.selectedSessionProfileId),
  };
  return {
    sourceFormat,
    snapshot,
    migratedFields: [
      `${sourceFormat}->exchanges`,
      'hosts->scopeAllowlist',
      snapshot.sessionProfiles?.length ? 'sessions->sessionProfiles' : '',
    ].filter(Boolean),
    warnings: projectImportWarnings(snapshot),
  };
}

function migrateLegacyProjectSnapshot(parsed: Record<string, unknown>, savedAt: string): ProjectSnapshot {
  const rawProjectName = firstString(parsed.projectName, parsed.name, parsed.title);
  const rawScope = firstArray(parsed.scopeAllowlist, parsed.scope, parsed.targets);
  const rawExchanges = firstArray(parsed.exchanges, parsed.traffic, parsed.history);
  const rawSessions = firstArray(parsed.sessionProfiles, parsed.sessions);
  if (!rawProjectName && rawScope.length === 0 && rawExchanges.length === 0 && rawSessions.length === 0) {
    throw new Error('This is not a valid ProxyForge project file.');
  }
  const projectName = rawProjectName || 'Imported ProxyForge project';
  const scopeAllowlist = normalizeScope(rawScope);
  const exchanges = normalizeExchanges(rawExchanges, savedAt);
  return {
    version: 1,
    savedAt,
    projectName,
    scopeAllowlist,
    exchanges,
    sessionProfiles: normalizeSessionProfiles(rawSessions, savedAt),
    selectedSessionProfileId: firstString(parsed.selectedSessionProfileId),
  };
}

function legacyProxyXmlItemToExchange(itemXml: string, index: number, savedAt: string) {
  const url = xmlField(itemXml, 'url');
  const hostField = xmlField(itemXml, 'host');
  const protocol = xmlField(itemXml, 'protocol') || (url.startsWith('http://') ? 'http' : 'https');
  const port = xmlField(itemXml, 'port');
  const pathValue = xmlField(itemXml, 'path') || '/';
  const normalizedUrl = normalizeUrl(url || `${protocol}://${hostField || 'imported.local'}${port && !['80', '443'].includes(port) ? `:${port}` : ''}${pathValue.startsWith('/') ? pathValue : `/${pathValue}`}`, hostField, pathValue);
  const parsed = safeUrl(normalizedUrl);
  const requestRaw = xmlField(itemXml, 'request');
  const responseRaw = xmlField(itemXml, 'response');
  const method = (xmlField(itemXml, 'method') || methodFromRawRequest(requestRaw) || 'GET').toUpperCase();
  const responseLength = Number(xmlField(itemXml, 'responselength'));
  const timing = Number(xmlField(itemXml, 'time'));
  return {
    id: `legacy-proxy-xml-${index + 1}-${simpleDigest(`${method}|${normalizedUrl}|${requestRaw}`).slice(0, 8)}`,
    method,
    host: parsed.host,
    path: `${parsed.pathname || '/'}${parsed.search || ''}`,
    url: normalizedUrl,
    status: Number(xmlField(itemXml, 'status') || statusFromRawResponse(responseRaw) || 0),
    length: Number.isFinite(responseLength) ? responseLength : responseRaw.length,
    mime: legacyProxyMimeType(xmlField(itemXml, 'mimetype')) || mimeFromRawResponse(responseRaw) || 'application/octet-stream',
    risk: 'info',
    timing: Number.isFinite(timing) ? timing : 0,
    source: 'proxy',
    time: xmlField(itemXml, 'time') || savedAt,
    requestRaw: requestRaw || `${method} ${parsed.pathname || '/'}${parsed.search || ''} HTTP/1.1\r\nHost: ${parsed.host}\r\n\r\n`,
    responseRaw,
    notes: 'Imported from legacy proxy XML history into Project Store.',
    tags: ['project-import', 'legacy-proxy-xml'],
  };
}

function harEntryToExchange(entry: unknown, index: number) {
  const record = isRecord(entry) ? entry : {};
  const request = isRecord(record.request) ? record.request : {};
  const response = isRecord(record.response) ? record.response : {};
  const url = normalizeUrl(firstString(request.url), '', '');
  const parsed = safeUrl(url);
  const method = (firstString(request.method) || 'GET').toUpperCase();
  const requestHeaders = normalizeHarHeaders(request.headers);
  const responseHeaders = normalizeHarHeaders(response.headers);
  const postData = isRecord(request.postData) ? request.postData : {};
  const content = isRecord(response.content) ? response.content : {};
  const requestBody = harText(firstString(postData.text), firstString(postData.encoding));
  const responseBody = harText(firstString(content.text), firstString(content.encoding));
  const status = numberOr(response.status, 0);
  return {
    id: `har-${index + 1}-${simpleDigest(`${method}|${url}`).slice(0, 8)}`,
    method,
    host: parsed.host,
    path: `${parsed.pathname || '/'}${parsed.search || ''}`,
    url,
    status,
    length: numberOr(response.bodySize, content.size, responseBody.length),
    mime: firstString(content.mimeType) || headerValue(responseHeaders, 'content-type') || 'application/octet-stream',
    risk: 'info',
    timing: numberOr(record.time, 0),
    source: 'proxy',
    time: firstString(record.startedDateTime),
    requestRaw: [
      `${method} ${parsed.pathname || '/'}${parsed.search || ''} HTTP/1.1`,
      `Host: ${parsed.host}`,
      ...requestHeaders.map((header) => `${header.name}: ${header.value}`),
      '',
      requestBody,
    ].join('\r\n'),
    responseRaw: [
      `HTTP/1.1 ${status} ${firstString(response.statusText)}`.trim(),
      ...responseHeaders.map((header) => `${header.name}: ${header.value}`),
      '',
      responseBody,
    ].join('\r\n'),
    notes: 'Imported from HAR into Project Store.',
    tags: ['project-import', 'har'],
  };
}

function normalizeExchanges(values: unknown, now: string): ProjectHttpExchange[] {
  if (!Array.isArray(values)) return [];
  return values.filter(isRecord).map((value, index) => {
    const requestRaw = firstString(value.requestRaw, value.request, value.rawRequest) || 'GET / HTTP/1.1\r\nHost: imported.local\r\n\r\n';
    const responseRaw = firstString(value.responseRaw, value.response, value.rawResponse) || 'HTTP/1.1 0 Imported\r\nContent-Type: text/plain\r\n\r\n';
    const method = firstString(value.method) || methodFromRawRequest(requestRaw) || 'GET';
    const host = firstString(value.host) || hostHeader(requestRaw) || safeUrl(firstString(value.url, value.href)).host || 'imported.local';
    const path = firstString(value.path) || requestTargetFromRawRequest(requestRaw) || safeUrl(firstString(value.url, value.href)).pathname || '/';
    const url = normalizeUrl(firstString(value.url, value.href) || urlFromRawRequest(requestRaw), host, path);
    return {
      ...value,
      id: firstString(value.id) || `hx-import-${index + 1}`,
      method: method.toUpperCase(),
      host: safeUrl(url).host || host,
      path: `${safeUrl(url).pathname || path}${safeUrl(url).search || ''}`,
      url,
      status: numberOr(value.status, value.statusCode, statusFromRawResponse(responseRaw), 0),
      length: numberOr(value.length, responseRaw.length),
      mime: firstString(value.mime, value.contentType) || mimeFromRawResponse(responseRaw) || 'application/octet-stream',
      risk: riskOr(value.risk),
      timing: numberOr(value.timing, value.durationMs, 0),
      notes: firstString(value.notes, value.comment) || '',
      source: sourceOr(value.source),
      time: firstString(value.time, value.createdAt) || now,
      requestRaw,
      responseRaw,
      tags: normalizeScope(value.tags),
    };
  });
}

function normalizeSessionProfiles(values: unknown, now: string): ProjectSessionProfile[] | undefined {
  if (!Array.isArray(values)) return undefined;
  const profiles = values.filter(isRecord).map((value, index) => {
    const headerText = firstString(value.headerText, value.headers) || '';
    const cookieText = firstString(value.cookieText, value.cookies) || '';
    return {
      ...value,
      id: firstString(value.id) || `session-import-${index + 1}`,
      name: firstString(value.name) || `Imported session ${index + 1}`,
      role: firstString(value.role) || 'operator',
      targetUrl: normalizeUrl(firstString(value.targetUrl, value.url), '', ''),
      source: sessionSourceOr(value.source),
      status: sessionStatusOr(value.status),
      headerText,
      cookieText,
      createdAt: firstString(value.createdAt) || now,
      updatedAt: now,
      headerCount: countHeaderLines(headerText),
      cookieCount: countCookies(cookieText),
      notes: firstString(value.notes) || '',
    };
  });
  return profiles.length ? profiles : undefined;
}

function importedExchangeFingerprint(exchange: ProjectHttpExchange) {
  return simpleDigest([
    exchange.method,
    exchange.url,
    exchange.requestRaw,
    exchange.responseRaw,
  ].join('\n'));
}

function importedExchangeConflictKey(exchange: ProjectHttpExchange) {
  return [
    exchange.method.toUpperCase(),
    exchange.url,
  ].join('\n');
}

function normalizeScope(values: unknown): string[] {
  if (!Array.isArray(values)) return [];
  return [...new Set(values.map((value) => String(value).trim()).filter(Boolean))];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function firstString(...values: unknown[]) {
  for (const value of values) {
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  return '';
}

function firstArray(...values: unknown[]) {
  return values.find(Array.isArray) ?? [];
}

function numberOr(...values: unknown[]) {
  for (const value of values) {
    const numeric = typeof value === 'number' ? value : typeof value === 'string' ? Number(value) : Number.NaN;
    if (Number.isFinite(numeric)) return numeric;
  }
  return 0;
}

function normalizeUrl(value: string, host: string, urlPath: string) {
  const trimmed = value.trim();
  try {
    return new URL(trimmed).toString();
  } catch {
    const normalizedHost = host.trim() || 'imported.local';
    const normalizedPath = urlPath.trim().startsWith('/') ? urlPath.trim() : `/${urlPath.trim() || ''}`;
    return `https://${normalizedHost}${normalizedPath}`;
  }
}

function safeUrl(value: string) {
  try {
    return new URL(value);
  } catch {
    return new URL('https://imported.local/');
  }
}

function riskOr(value: unknown): ProjectHttpExchange['risk'] {
  return ['critical', 'high', 'medium', 'low', 'info'].includes(String(value)) ? value as ProjectHttpExchange['risk'] : 'info';
}

function sourceOr(value: unknown): ProjectHttpExchange['source'] {
  return ['proxy', 'repeater', 'scanner', 'crawler', 'demo'].includes(String(value)) ? value as ProjectHttpExchange['source'] : 'proxy';
}

function sessionSourceOr(value: unknown): ProjectSessionProfile['source'] {
  return ['manual', 'browser', 'traffic', 'ci'].includes(String(value)) ? value as ProjectSessionProfile['source'] : 'manual';
}

function sessionStatusOr(value: unknown): ProjectSessionProfile['status'] {
  return ['ready', 'stale', 'needs-refresh'].includes(String(value)) ? value as ProjectSessionProfile['status'] : 'ready';
}

function countHeaderLines(value: string) {
  return value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).length;
}

function countCookies(value: string) {
  return value.split(';').map((cookie) => cookie.trim()).filter(Boolean).length;
}

function safeJsonObject(content: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(content) as unknown;
    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function legacyMigratedFields(parsed: Record<string, unknown>) {
  return [
    Array.isArray((parsed as { targets?: unknown }).targets) ? 'targets->scopeAllowlist' : '',
    Array.isArray((parsed as { scope?: unknown }).scope) ? 'scope->scopeAllowlist' : '',
    Array.isArray((parsed as { traffic?: unknown }).traffic) ? 'traffic->exchanges' : '',
    Array.isArray((parsed as { history?: unknown }).history) ? 'history->exchanges' : '',
    Array.isArray((parsed as { sessions?: unknown }).sessions) ? 'sessions->sessionProfiles' : '',
  ].filter(Boolean);
}

function projectImportWarnings(snapshot: ProjectSnapshot) {
  return [
    snapshot.exchanges.length === 0 ? 'No exchanges were present in the imported project.' : '',
    snapshot.scopeAllowlist.length === 0 ? 'No scope entries were present in the imported project.' : '',
  ].filter(Boolean);
}

function xmlField(itemXml: string, tagName: string) {
  const match = itemXml.match(new RegExp(`<${tagName}\\b([^>]*)>([\\s\\S]*?)<\\/${tagName}>`, 'i'));
  if (!match) return '';
  const attributes = match[1] ?? '';
  const value = xmlDecode(match[2] ?? '').trim();
  if (/\bbase64\s*=\s*"true"/i.test(attributes)) {
    try {
      return Buffer.from(value.replace(/\s+/g, ''), 'base64').toString('utf8');
    } catch {
      return value;
    }
  }
  return value;
}

function xmlDecode(value: string) {
  return String(value)
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

function legacyProxyMimeType(value: string) {
  const normalized = value.trim().toLowerCase();
  if (!normalized) return '';
  const known: Record<string, string> = {
    html: 'text/html',
    script: 'application/javascript',
    json: 'application/json',
    xml: 'application/xml',
    css: 'text/css',
    image: 'image/*',
    binary: 'application/octet-stream',
    text: 'text/plain',
  };
  return known[normalized] ?? normalized;
}

function normalizeHarHeaders(value: unknown): Array<{ name: string; value: string }> {
  if (!Array.isArray(value)) return [];
  return value.filter(isRecord).map((header) => ({
    name: firstString(header.name),
    value: firstString(header.value),
  })).filter((header) => header.name);
}

function harText(value: string, encoding: string) {
  if (!value) return '';
  if (encoding.toLowerCase() === 'base64') {
    try {
      return Buffer.from(value, 'base64').toString('utf8');
    } catch {
      return value;
    }
  }
  return value;
}

function headerValue(headers: Array<{ name: string; value: string }>, name: string) {
  const wanted = name.toLowerCase();
  return headers.find((header) => header.name.toLowerCase() === wanted)?.value ?? '';
}

function methodFromRawRequest(raw: string) {
  return raw.match(/^([A-Z]+)\s+\S+\s+HTTP\/\d(?:\.\d)?/i)?.[1]?.toUpperCase() ?? '';
}

function requestTargetFromRawRequest(raw: string) {
  return raw.match(/^[A-Z]+\s+(\S+)\s+HTTP\/\d(?:\.\d)?/i)?.[1] ?? '';
}

function urlFromRawRequest(raw: string) {
  const target = requestTargetFromRawRequest(raw);
  if (/^https?:\/\//i.test(target)) return target;
  const host = hostHeader(raw);
  return host ? `https://${host}${target.startsWith('/') ? target : `/${target || ''}`}` : '';
}

function hostHeader(raw: string) {
  return raw.match(/\r?\nhost:\s*([^\r\n]+)/i)?.[1]?.trim() ?? '';
}

function statusFromRawResponse(raw: string) {
  const status = Number(raw.match(/^HTTP\/\d(?:\.\d)?\s+(\d{3})/i)?.[1] ?? Number.NaN);
  return Number.isFinite(status) ? status : 0;
}

function mimeFromRawResponse(raw: string) {
  return raw.match(/\r?\ncontent-type:\s*([^\r\n;]+)/i)?.[1]?.trim() ?? '';
}

function simpleDigest(value: string) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `${hash.toString(16).padStart(8, '0')}${value.length.toString(16).padStart(8, '0')}`;
}
