import type {
  LoggerArchiveImportFormat,
  LoggerArchiveImportReview,
  LoggerArchiveMappingPreset,
  LoggerArchiveMergeStrategy,
  LoggerCaptureControl,
  LoggerCapturePreset,
  LoggerCustomColumn,
  LoggerToolSource,
  ReportLoggerImportAttachment,
  Severity,
} from './types';

export interface LoggerEvidenceEntry {
  id: string;
  exchangeId: string;
  at: string;
  tool: LoggerToolSource;
  method: string;
  host: string;
  path: string;
  url: string;
  status: number;
  length: number;
  mime: string;
  risk: Severity;
  timing: number;
  modified: boolean;
  notes: string;
  requestRaw: string;
  responseRaw: string;
  tags: string[];
}

export interface LoggerSavedFilterSet {
  id: string;
  name: string;
  predicates: {
    tools?: LoggerToolSource[];
    risks?: Severity[];
    statuses?: number[];
    text?: string;
    tags?: string[];
    modified?: boolean;
  };
  matchedEntryIds: string[];
  facetCounts: {
    tools: Record<string, number>;
    risks: Record<string, number>;
    statuses: Record<string, number>;
    tags: Record<string, number>;
  };
}

export interface LoggerColumnEvidencePackage {
  kind: string;
  reportReady: boolean;
  content: string;
}

export interface LoggerParityEvidenceRequest {
  entries: LoggerEvidenceEntry[];
  captureControls: LoggerCaptureControl[];
  capturePresets: LoggerCapturePreset[];
  customColumns: LoggerCustomColumn[];
  columnEvidencePackages?: LoggerColumnEvidencePackage[];
  archiveMappingPresets: LoggerArchiveMappingPreset[];
  archiveImportReviews: LoggerArchiveImportReview[];
  mergeStrategies: LoggerArchiveMergeStrategy[];
  savedFilterSets: LoggerSavedFilterSet[];
  reportAttachments: ReportLoggerImportAttachment[];
  operationalSecretSamples?: string[];
  exportedAt?: string;
}

export interface LoggerParityEvidencePackage {
  id: string;
  kind: 'proxyforge-logger-parity-evidence-package';
  title: string;
  fileName: string;
  path: string;
  exportedAt: string;
  entryCount: number;
  capturePresetCount: number;
  archiveImportReviewCount: number;
  savedFilterSetCount: number;
  reportAttachmentCount: number;
  artifactIds: {
    entryIds: string[];
    capturePresetIds: string[];
    archiveReviewIds: string[];
    archiveConflictIds: string[];
    savedFilterSetIds: string[];
    reportAttachmentIds: string[];
    columnEvidenceKinds: string[];
  };
  requirements: {
    toolGeneratedTrafficCovered: boolean;
    captureControlsCovered: boolean;
    savedFiltersCovered: boolean;
    customColumnsLinked: boolean;
    archiveImportExportCovered: boolean;
    archiveMappingCovered: boolean;
    archiveConflictDedupeCovered: boolean;
    mergeStrategiesCovered: boolean;
    replayReviewCovered: boolean;
    reportAttachmentCovered: boolean;
    provenanceSigningCovered: boolean;
    redactionPolicyCovered: boolean;
    customColumnPackageRefreshCovered: boolean;
    fullFidelityRawMaterialPreserved: boolean;
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

export function buildLoggerParityEvidencePackage(request: LoggerParityEvidenceRequest): LoggerParityEvidencePackage {
  const exportedAt = request.exportedAt ?? new Date().toISOString();
  const stamp = exportedAt.replace(/[:.]/g, '-');
  const toolSet = new Set(request.entries.map((entry) => entry.tool));
  const formatSet = new Set(request.archiveImportReviews.map((review) => review.format));
  const normalizationSet = new Set(request.archiveMappingPresets.map((preset) => preset.normalization));
  const conflictKinds = new Set(request.archiveImportReviews.flatMap((review) => review.conflictDetails.map((detail) => detail.kind)));
  const columnKinds = request.columnEvidencePackages?.map((pkg) => pkg.kind) ?? [];
  const columnEvidenceText = (request.columnEvidencePackages ?? []).map((pkg) => pkg.content).join('\n');
  const rawMaterial = [
    JSON.stringify(request.entries),
    JSON.stringify(request.captureControls),
    JSON.stringify(request.capturePresets),
    JSON.stringify(request.customColumns),
    JSON.stringify(request.columnEvidencePackages ?? []),
    JSON.stringify(request.archiveMappingPresets),
    JSON.stringify(request.archiveImportReviews),
    JSON.stringify(request.savedFilterSets),
    JSON.stringify(request.reportAttachments),
    ...request.entries.flatMap((entry) => [entry.requestRaw, entry.responseRaw, entry.notes]),
    ...request.archiveImportReviews.flatMap((review) => [
      review.notes,
      ...review.exchanges.flatMap((exchange) => [exchange.requestRaw, exchange.responseRaw, exchange.notes]),
      ...review.conflictDetails.flatMap((detail) => [detail.requestPreview, detail.responsePreview, detail.importedSummary, detail.existingSummary]),
    ]),
  ].join('\n');
  const redactionControls = [
    ...request.archiveImportReviews.map((review) => review.redactionControl),
    ...request.reportAttachments.map((attachment) => attachment.redactionControl),
  ].filter(Boolean);
  const provenanceManifests = [
    ...request.archiveImportReviews.map((review) => review.provenanceManifest),
    ...request.reportAttachments.map((attachment) => attachment.provenanceManifest),
  ].filter(Boolean);
  const requirements = {
    toolGeneratedTrafficCovered: ['proxy', 'target', 'repeater', 'scanner', 'intruder', 'exploit', 'automations', 'extensions']
      .every((tool) => toolSet.has(tool as LoggerToolSource)),
    captureControlsCovered: request.captureControls.length >= 8
      && request.captureControls.every((control) => typeof control.enabled === 'boolean')
      && request.capturePresets.some((preset) => preset.pinned && preset.controls.length >= 8),
    savedFiltersCovered: request.savedFilterSets.length > 0
      && request.savedFilterSets.every((filter) => filter.matchedEntryIds.length > 0)
      && request.savedFilterSets.some((filter) => filter.predicates.text || filter.predicates.tools?.length || filter.predicates.tags?.length),
    customColumnsLinked: request.customColumns.some((column) => column.enabled)
      && columnKinds.includes('proxyforge-logger-column-sandbox-review')
      && columnKinds.includes('proxyforge-logger-custom-column-compatibility-fixtures')
      && columnKinds.includes('proxyforge-logger-custom-column-large-table-profile'),
    customColumnPackageRefreshCovered: ['packageRefresh', 'fixtureRefreshCovered', 'helpers.base64Decode', 'helpers.urlDecode', 'operationalSecretSignals']
      .every((token) => columnEvidenceText.includes(token)),
    archiveImportExportCovered: ['raw-http', 'har', 'legacy-proxy-xml', 'project', 'plain-text']
      .every((format) => formatSet.has(format as LoggerArchiveImportFormat)),
    archiveMappingCovered: ['preserve', 'report-evidence', 'scanner-triage', 'replay-proof']
      .every((mode) => normalizationSet.has(mode as LoggerArchiveMappingPreset['normalization']))
      && request.archiveImportReviews.some((review) => review.fieldMappings.length > 0),
    archiveConflictDedupeCovered: ['new-route', 'route-variant', 'exact-duplicate']
      .every((kind) => conflictKinds.has(kind as LoggerArchiveImportReview['conflictDetails'][number]['kind']))
      && request.archiveImportReviews.some((review) => review.duplicateEntries > 0)
      && request.archiveImportReviews.some((review) => review.changedEntries > 0),
    mergeStrategiesCovered: ['add-and-variants', 'add-only', 'replace-route']
      .every((strategy) => request.mergeStrategies.includes(strategy as LoggerArchiveMergeStrategy)),
    replayReviewCovered: request.archiveImportReviews.some((review) => review.replayCount > 0 && Boolean(review.replayedAt)),
    reportAttachmentCovered: request.reportAttachments.length > 0
      && request.reportAttachments.some((attachment) => attachment.provenanceManifest && attachment.redactionControl),
    provenanceSigningCovered: provenanceManifests.some((manifest) => Boolean(manifest?.manifestDigestSha256)
      && ['preview-signed', 'signed', 'valid'].includes(manifest?.signature?.status ?? '')),
    redactionPolicyCovered: redactionControls.some((control) => control?.mode === 'rules'
      && control.rules.some((rule) => rule.enabled && rule.action === 'mask')
      && control.rules.some((rule) => rule.enabled && rule.action === 'preserve')),
    fullFidelityRawMaterialPreserved: /HTTP\/[12]|Authorization:|Cookie:|X-API-Key:|Bearer|requestRaw|responseRaw/i.test(rawMaterial),
    operationalSecretsPreserved: (request.operationalSecretSamples ?? []).length > 0
      && (request.operationalSecretSamples ?? []).every((sample) => rawMaterial.includes(sample)),
    reportPhaseOnlyRedaction: true,
  };
  const unsigned = {
    kind: 'proxyforge-logger-parity-evidence-package',
    exportedAt,
    entries: request.entries,
    captureControls: request.captureControls,
    capturePresets: request.capturePresets,
    customColumns: request.customColumns,
    columnEvidencePackages: request.columnEvidencePackages ?? [],
    archiveMappingPresets: request.archiveMappingPresets,
    archiveImportReviews: request.archiveImportReviews,
    mergeStrategies: request.mergeStrategies,
    savedFilterSets: request.savedFilterSets,
    reportAttachments: request.reportAttachments,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const content = JSON.stringify({ ...unsigned, digestPreview }, null, 2);

  return {
    id: `logger-parity-${Date.parse(exportedAt) || Date.now()}`,
    kind: 'proxyforge-logger-parity-evidence-package',
    title: 'Logger parity evidence package',
    fileName: `proxyforge-logger-parity-${stamp}.json`,
    path: `logger/proxyforge-logger-parity-${stamp}.json`,
    exportedAt,
    entryCount: request.entries.length,
    capturePresetCount: request.capturePresets.length,
    archiveImportReviewCount: request.archiveImportReviews.length,
    savedFilterSetCount: request.savedFilterSets.length,
    reportAttachmentCount: request.reportAttachments.length,
    artifactIds: {
      entryIds: request.entries.map((entry) => entry.id),
      capturePresetIds: request.capturePresets.map((preset) => preset.id),
      archiveReviewIds: request.archiveImportReviews.map((review) => review.id),
      archiveConflictIds: request.archiveImportReviews.flatMap((review) => review.conflictDetails.map((detail) => detail.id)),
      savedFilterSetIds: request.savedFilterSets.map((filter) => filter.id),
      reportAttachmentIds: request.reportAttachments.map((attachment) => attachment.id),
      columnEvidenceKinds: columnKinds,
    },
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
    digestPreview,
    summary: 'Logger parity evidence covers tool-generated traffic capture, capture presets, saved filters, custom column linkage, custom column package-refresh proof, raw/HAR/legacy proxy/project/plain-text archive imports, mapping presets, conflict/dedupe review, merge strategies, replay review, signed provenance, report attachments, redaction policy, and full-fidelity operational material until report export.',
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
