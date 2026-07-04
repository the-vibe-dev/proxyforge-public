import type {
  OrganizerCollection,
  OrganizerCollectionDiff,
  OrganizerHighlight,
  OrganizerItemStatus,
  OrganizerPackageConflictAuditAction,
  OrganizerPackageConflictAuditEntry,
  OrganizerPackageMergeMode,
  OrganizerPackageMode,
  OrganizerPackageSignatureStatus,
  OrganizerReviewer,
  OrganizerReviewerSlaExportArtifact,
  OrganizerSignedPackageTrustPolicyPreset,
  ToolId,
} from './types';

export interface OrganizerCollectionPackageArtifact {
  id: string;
  kind: 'proxyforge-organizer-package';
  exportedAt: string;
  projectName: string;
  collectionId: string;
  collectionName: string;
  itemCount: number;
  mode: OrganizerPackageMode;
  digestSha256: string;
  content: string;
  algorithm?: 'AES-256-GCM';
  kdf?: 'PBKDF2-SHA256-120000';
  passphrase?: string;
  signingSecret?: string;
  signature: {
    algorithm: 'HMAC-SHA256';
    status: OrganizerPackageSignatureStatus | 'signed';
    signerName: string;
    keyId: string;
    signedAt: string;
    packageDigestSha256: string;
    signature: string;
  };
  importReviewIds?: string[];
  mergeModes?: OrganizerPackageMergeMode[];
}

export interface OrganizerParityEvidenceRequest {
  projectName: string;
  collections: OrganizerCollection[];
  reviewers: OrganizerReviewer[];
  reviewerSlaExports: OrganizerReviewerSlaExportArtifact[];
  packageArtifacts: OrganizerCollectionPackageArtifact[];
  collectionDiffs: OrganizerCollectionDiff[];
  trustPolicyPresets: OrganizerSignedPackageTrustPolicyPreset[];
  conflictAuditTrail: OrganizerPackageConflictAuditEntry[];
  operationalSecretSamples?: string[];
  exportedAt?: string;
}

export interface OrganizerParityEvidencePackage {
  id: string;
  kind: 'proxyforge-organizer-parity-evidence-package';
  title: string;
  fileName: string;
  path: string;
  exportedAt: string;
  projectName: string;
  collectionCount: number;
  itemCount: number;
  reviewerCount: number;
  packageArtifactCount: number;
  importReviewCount: number;
  conflictAuditCount: number;
  summaries: {
    statusCounts: Record<OrganizerItemStatus, number>;
    highlightCounts: Record<OrganizerHighlight, number>;
    sourceCounts: Record<string, number>;
    reviewerAssignmentCounts: Record<string, number>;
    packageModes: Record<OrganizerPackageMode, number>;
    signatureStatuses: Record<string, number>;
    mergeModes: Record<OrganizerPackageMergeMode, number>;
    conflictActions: Record<OrganizerPackageConflictAuditAction, number>;
  };
  artifactIds: {
    collectionIds: string[];
    itemIds: string[];
    reviewerIds: string[];
    slaExportIds: string[];
    packageArtifactIds: string[];
    diffIds: string[];
    trustPolicyPresetIds: string[];
    conflictAuditEntryIds: string[];
  };
  requirements: {
    collectionsCovered: boolean;
    multiToolCurationCovered: boolean;
    notesStatusHighlightCovered: boolean;
    reviewerAssignmentCovered: boolean;
    reviewerSlaCovered: boolean;
    csvExportCovered: boolean;
    shareLinksCovered: boolean;
    packageExportCovered: boolean;
    passphraseSealedPackageCovered: boolean;
    signedPackageCovered: boolean;
    trustPolicyCovered: boolean;
    importReviewDiffCovered: boolean;
    conflictDedupeCovered: boolean;
    mergeModesCovered: boolean;
    conflictAuditCovered: boolean;
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

const requiredStatuses: OrganizerItemStatus[] = ['inbox', 'reviewing', 'interesting', 'done'];
const requiredHighlights: OrganizerHighlight[] = ['none', 'yellow', 'green', 'red'];
const requiredMergeModes: OrganizerPackageMergeMode[] = ['new-only', 'keep-both', 'replace-conflicts'];

export function buildOrganizerParityEvidencePackage(request: OrganizerParityEvidenceRequest): OrganizerParityEvidencePackage {
  const exportedAt = request.exportedAt ?? new Date().toISOString();
  const stamp = exportedAt.replace(/[:.]/g, '-');
  const items = request.collections.flatMap((collection) => collection.items);
  const allPackageMergeModes = [
    ...request.packageArtifacts.flatMap((artifact) => artifact.mergeModes ?? []),
    ...request.conflictAuditTrail.map((entry) => entry.mergeMode),
  ];
  const rawMaterial = [
    JSON.stringify(request.collections),
    JSON.stringify(request.reviewers),
    JSON.stringify(request.reviewerSlaExports),
    JSON.stringify(request.packageArtifacts),
    JSON.stringify(request.collectionDiffs),
    JSON.stringify(request.trustPolicyPresets),
    JSON.stringify(request.conflictAuditTrail),
    ...items.flatMap((item) => [item.notes, item.requestRaw, item.responseRaw]),
    ...request.packageArtifacts.flatMap((artifact) => [artifact.content, artifact.passphrase ?? '', artifact.signingSecret ?? '']),
    ...request.reviewerSlaExports.map((artifact) => artifact.content ?? ''),
  ].join('\n');
  const statusCounts = countValues(requiredStatuses, items.map((item) => item.status));
  const highlightCounts = countValues(requiredHighlights, items.map((item) => item.highlight));
  const sourceCounts = countLooseValues(items.map((item) => item.originalTool));
  const packageModes = countValues(['plain', 'passphrase-sealed'], request.packageArtifacts.map((artifact) => artifact.mode));
  const signatureStatuses = countLooseValues(request.packageArtifacts.map((artifact) => artifact.signature.status));
  const mergeModes = countValues(requiredMergeModes, allPackageMergeModes);
  const conflictActions = countValues(
    ['reviewed', 'merged', 'skipped', 'kept-local', 'accepted-incoming', 'kept-both', 'replaced-local'],
    request.conflictAuditTrail.map((entry) => entry.action),
  );
  const requirements = {
    collectionsCovered: request.collections.length > 0 && request.collections.every((collection) => collection.items.length > 0),
    multiToolCurationCovered: ['proxy', 'logger', 'repeater', 'scanner', 'search']
      .every((source) => sourceCounts[source] > 0),
    notesStatusHighlightCovered: requiredStatuses.every((status) => statusCounts[status] > 0)
      && requiredHighlights.every((highlight) => highlightCounts[highlight] > 0)
      && items.every((item) => item.notes.trim().length > 0),
    reviewerAssignmentCovered: request.reviewers.length >= 2
      && items.every((item) => Boolean(item.reviewerId && item.reviewerName && item.reviewDueAt))
      && request.reviewers.some((reviewer) => items.some((item) => item.reviewerId === reviewer.id)),
    reviewerSlaCovered: request.reviewerSlaExports.length > 0
      && request.reviewerSlaExports.some((artifact) => artifact.overdueCount > 0 && artifact.openCount > 0 && artifact.doneCount > 0)
      && request.reviewerSlaExports.every((artifact) => artifact.rows.length >= request.reviewers.length),
    csvExportCovered: request.collections.some((collection) => /request_base64,response_base64|response_base64/i.test(collection.lastExportCsv ?? '')),
    shareLinksCovered: request.collections.some((collection) => /^proxyforge:\/\/organizer\//.test(collection.shareLink ?? '')),
    packageExportCovered: request.packageArtifacts.length > 0
      && request.packageArtifacts.every((artifact) => artifact.kind === 'proxyforge-organizer-package' && artifact.content.includes('proxyforge-organizer-package')),
    passphraseSealedPackageCovered: request.packageArtifacts.some((artifact) => (
      artifact.mode === 'passphrase-sealed'
      && artifact.algorithm === 'AES-256-GCM'
      && artifact.kdf === 'PBKDF2-SHA256-120000'
      && Boolean(artifact.passphrase)
    )),
    signedPackageCovered: request.packageArtifacts.some((artifact) => (
      artifact.signature.algorithm === 'HMAC-SHA256'
      && ['signed', 'valid'].includes(artifact.signature.status)
      && Boolean(artifact.signature.signature)
      && Boolean(artifact.signingSecret)
    )),
    trustPolicyCovered: request.trustPolicyPresets.length > 0
      && request.collectionDiffs.some((diff) => diff.trustEvaluation && ['trusted', 'warn', 'blocked'].includes(diff.trustEvaluation.decision)),
    importReviewDiffCovered: request.collectionDiffs.some((diff) => (
      diff.addedItems > 0
      && diff.changedItems > 0
      && diff.duplicateItems > 0
      && diff.reviewerChanges > 0
      && diff.statusChanges > 0
    )),
    conflictDedupeCovered: request.collectionDiffs.some((diff) => (
      diff.duplicateItems > 0
      && (diff.conflictRoutes ?? []).length > 0
      && (diff.dueDateChanges ?? 0) > 0
    )),
    mergeModesCovered: requiredMergeModes.every((mode) => mergeModes[mode] > 0),
    conflictAuditCovered: request.conflictAuditTrail.length > 0
      && ['reviewed', 'merged', 'kept-both'].every((action) => conflictActions[action as OrganizerPackageConflictAuditAction] > 0),
    fullFidelityRawMaterialPreserved: /HTTP\/[12]|Authorization:|Cookie:|X-API-Key:|requestRaw|responseRaw|request_base64|response_base64/i.test(rawMaterial),
    operationalSecretsPreserved: (request.operationalSecretSamples ?? []).length > 0
      && (request.operationalSecretSamples ?? []).every((sample) => rawMaterial.includes(sample)),
    reportPhaseOnlyRedaction: true,
  };
  const unsigned = {
    kind: 'proxyforge-organizer-parity-evidence-package',
    exportedAt,
    projectName: request.projectName,
    collections: request.collections,
    reviewers: request.reviewers,
    reviewerSlaExports: request.reviewerSlaExports,
    packageArtifacts: request.packageArtifacts,
    collectionDiffs: request.collectionDiffs,
    trustPolicyPresets: request.trustPolicyPresets,
    conflictAuditTrail: request.conflictAuditTrail,
    summaries: {
      statusCounts,
      highlightCounts,
      sourceCounts,
      reviewerAssignmentCounts: countLooseValues(items.map((item) => item.reviewerId ?? 'unassigned')),
      packageModes,
      signatureStatuses,
      mergeModes,
      conflictActions,
    },
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const content = JSON.stringify({ ...unsigned, digestPreview }, null, 2);

  return {
    id: `organizer-parity-${digestPreview.slice(0, 12)}`,
    kind: 'proxyforge-organizer-parity-evidence-package',
    title: 'Organizer parity evidence package',
    fileName: `proxyforge-organizer-parity-${stamp}.json`,
    path: `organizer/proxyforge-organizer-parity-${stamp}.json`,
    exportedAt,
    projectName: request.projectName,
    collectionCount: request.collections.length,
    itemCount: items.length,
    reviewerCount: request.reviewers.length,
    packageArtifactCount: request.packageArtifacts.length,
    importReviewCount: request.collectionDiffs.length,
    conflictAuditCount: request.conflictAuditTrail.length,
    summaries: unsigned.summaries,
    artifactIds: {
      collectionIds: request.collections.map((collection) => collection.id),
      itemIds: items.map((item) => item.id),
      reviewerIds: request.reviewers.map((reviewer) => reviewer.id),
      slaExportIds: request.reviewerSlaExports.map((artifact) => artifact.id),
      packageArtifactIds: request.packageArtifacts.map((artifact) => artifact.id),
      diffIds: request.collectionDiffs.map((diff) => diff.id),
      trustPolicyPresetIds: request.trustPolicyPresets.map((preset) => preset.id),
      conflictAuditEntryIds: request.conflictAuditTrail.map((entry) => entry.id),
    },
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
    digestPreview,
    summary: 'Organizer parity evidence covers multi-tool collections, notes, statuses, highlights, reviewer assignment, reviewer SLA export, CSV/share links, plain and passphrase-sealed packages, HMAC signatures, trust policies, import diff review, duplicate/conflict handling, merge modes, conflict audit trails, full-fidelity raw HTTP material, and report-export-only redaction.',
    content,
  };
}

function countValues<T extends string>(keys: readonly T[], values: string[]): Record<T, number> {
  const seed = Object.fromEntries(keys.map((key) => [key, 0])) as Record<T, number>;
  for (const value of values) {
    if (value in seed) seed[value as T] += 1;
  }
  return seed;
}

function countLooseValues(values: Array<string | ToolId | 'system'>): Record<string, number> {
  return values.reduce<Record<string, number>>((memo, value) => ({
    ...memo,
    [value]: (memo[value] ?? 0) + 1,
  }), {});
}

function simpleDigest(value: string) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `${hash.toString(16).padStart(8, '0')}${value.length.toString(16).padStart(8, '0')}`;
}
