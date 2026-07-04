export interface AnalysisLinkedEvidencePackage {
  id?: string;
  kind?: string;
  title?: string;
  content?: string;
  summary?: string;
  reportReady?: boolean;
  status?: string;
  requirements?: Record<string, boolean>;
  digestPreview?: string;
}

export interface AnalysisToolRefreshEvidenceRequest {
  searchPackage: AnalysisLinkedEvidencePackage;
  loggerPackage: AnalysisLinkedEvidencePackage;
  organizerPackage: AnalysisLinkedEvidencePackage;
  viewerPackage: AnalysisLinkedEvidencePackage;
  sequencerPackage: AnalysisLinkedEvidencePackage;
  decoderPackage: AnalysisLinkedEvidencePackage;
  comparerPackage: AnalysisLinkedEvidencePackage;
  generatedAt?: string;
  operationalSecretSamples?: string[];
}

export interface AnalysisLinkedPackageDigest {
  id: string;
  kind: string;
  digest: string;
  reportReady: boolean;
  sourceLength: number;
}

export interface AnalysisToolRefreshEvidencePackage {
  id: string;
  kind: 'proxyforge-analysis-tool-refresh-evidence-package';
  title: string;
  fileName: string;
  path: string;
  generatedAt: string;
  linkedPackageKinds: string[];
  packageRefreshProof: {
    refreshedAt: string;
    requiredPackageKinds: string[];
    linkedPackageIds: string[];
    linkedPackageKinds: string[];
    linkedPackageDigests: AnalysisLinkedPackageDigest[];
    stalePackageIds: string[];
    freshDigest: string;
    rawMaterialDigestPreview: string;
  };
  requirements: {
    searchRefreshCovered: boolean;
    loggerRefreshCovered: boolean;
    organizerRefreshCovered: boolean;
    viewerRefreshCovered: boolean;
    sequencerRefreshCovered: boolean;
    decoderRefreshCovered: boolean;
    comparerRefreshCovered: boolean;
    packageRefreshCovered: boolean;
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

const REQUIRED_PACKAGE_KINDS = [
  'proxyforge-search-parity-evidence-package',
  'proxyforge-logger-parity-evidence-package',
  'proxyforge-organizer-parity-evidence-package',
  'proxyforge-viewer-parity-evidence-package',
  'proxyforge-sequencer-parity-evidence-package',
  'proxyforge-decoder-parity-evidence-package',
  'proxyforge-comparer-parity-evidence-package',
] as const;

type RequiredPackageKind = typeof REQUIRED_PACKAGE_KINDS[number];

interface LinkedPackageSlot {
  item: AnalysisLinkedEvidencePackage;
  fallbackKind: RequiredPackageKind;
  prefix: string;
  marker: RegExp;
}

export function buildAnalysisToolRefreshEvidencePackage(request: AnalysisToolRefreshEvidenceRequest): AnalysisToolRefreshEvidencePackage {
  const generatedAt = request.generatedAt ?? new Date().toISOString();
  const stamp = generatedAt.replace(/[:.]/g, '-');
  const slots: LinkedPackageSlot[] = [
    {
      item: request.searchPackage,
      fallbackKind: 'proxyforge-search-parity-evidence-package',
      prefix: 'analysis-search',
      marker: /fullTextSearchCovered|semanticRankingCovered|persistentIndexCovered|largeProjectSoakCovered/i,
    },
    {
      item: request.loggerPackage,
      fallbackKind: 'proxyforge-logger-parity-evidence-package',
      prefix: 'analysis-logger',
      marker: /toolGeneratedTrafficCovered|archiveImportExportCovered|archiveConflictDedupeCovered|customColumn|package-refresh|packageRefresh/i,
    },
    {
      item: request.organizerPackage,
      fallbackKind: 'proxyforge-organizer-parity-evidence-package',
      prefix: 'analysis-organizer',
      marker: /collectionsCovered|passphraseSealedPackageCovered|conflictAuditCovered|reviewer|sealed/i,
    },
    {
      item: request.viewerPackage,
      fallbackKind: 'proxyforge-viewer-parity-evidence-package',
      prefix: 'analysis-viewer',
      marker: /rawViewCovered|prettyJsonViewCovered|graphqlViewCovered|replayComparisonExportsCovered|reportAttachmentCovered/i,
    },
    {
      item: request.sequencerPackage,
      fallbackKind: 'proxyforge-sequencer-parity-evidence-package',
      prefix: 'analysis-sequencer',
      marker: /tokenLocationExtractionCovered|largeSampleReliabilityCovered|fipsCapCovered|fullFidelityTokenSamplesPreserved/i,
    },
    {
      item: request.decoderPackage,
      fallbackKind: 'proxyforge-decoder-parity-evidence-package',
      prefix: 'analysis-decoder',
      marker: /encodeDecodeHashFormatCovered|jweDecryptEditReencryptCovered|transform|golden|reportPhaseOnlyRedaction/i,
    },
    {
      item: request.comparerPackage,
      fallbackKind: 'proxyforge-comparer-parity-evidence-package',
      prefix: 'analysis-comparer',
      marker: /structuredHttpDiffCovered|normalizationPresetsCovered|wordDiff|byteDiff|textDiff/i,
    },
  ];
  const linkedPackageDigests = slots.map(({ item, fallbackKind, prefix }, index) => {
    const text = linkedPackageText(item);
    return {
      id: linkedPackageId(item, index, prefix),
      kind: linkedPackageKind(item, fallbackKind),
      digest: simpleDigest(text),
      reportReady: linkedPackageReady(item),
      sourceLength: text.length,
    };
  });
  const linkedPackageKinds = uniqueValues(linkedPackageDigests.map((item) => item.kind));
  const stalePackageIds = linkedPackageDigests.filter((item) => !item.reportReady).map((item) => item.id);
  const rawMaterial = [
    ...slots.map(({ item }) => linkedPackageText(item)),
    ...(request.operationalSecretSamples ?? []),
  ].join('\n');
  const operationalSecretSamples = (request.operationalSecretSamples ?? []).map((sample) => sample.trim()).filter(Boolean);
  const packageRefreshProof = {
    refreshedAt: generatedAt,
    requiredPackageKinds: [...REQUIRED_PACKAGE_KINDS],
    linkedPackageIds: linkedPackageDigests.map((item) => item.id),
    linkedPackageKinds,
    linkedPackageDigests,
    stalePackageIds,
    freshDigest: simpleDigest(linkedPackageDigests.map((item) => `${item.id}:${item.kind}:${item.digest}:${item.reportReady}:${item.sourceLength}`).join('|')),
    rawMaterialDigestPreview: simpleDigest(rawMaterial),
  };
  const hasRequiredKind = (kind: RequiredPackageKind) => linkedPackageKinds.includes(kind);
  const slotCovered = (fallbackKind: RequiredPackageKind) => {
    const slot = slots.find((item) => item.fallbackKind === fallbackKind);
    if (!slot) return false;
    const text = linkedPackageText(slot.item);
    return linkedPackageKind(slot.item, slot.fallbackKind) === fallbackKind
      && linkedPackageReady(slot.item)
      && slot.marker.test(text);
  };
  const requirements = {
    searchRefreshCovered: slotCovered('proxyforge-search-parity-evidence-package'),
    loggerRefreshCovered: slotCovered('proxyforge-logger-parity-evidence-package'),
    organizerRefreshCovered: slotCovered('proxyforge-organizer-parity-evidence-package'),
    viewerRefreshCovered: slotCovered('proxyforge-viewer-parity-evidence-package'),
    sequencerRefreshCovered: slotCovered('proxyforge-sequencer-parity-evidence-package'),
    decoderRefreshCovered: slotCovered('proxyforge-decoder-parity-evidence-package'),
    comparerRefreshCovered: slotCovered('proxyforge-comparer-parity-evidence-package'),
    packageRefreshCovered: REQUIRED_PACKAGE_KINDS.every(hasRequiredKind)
      && stalePackageIds.length === 0
      && linkedPackageDigests.length === REQUIRED_PACKAGE_KINDS.length,
    rawExecutorMaterialPreserved: /HTTP\/[12]|Authorization:|Cookie:|Bearer|session=|X-API-Key:|token|secret|key/i.test(rawMaterial),
    operationalSecretsPreserved: operationalSecretSamples.length > 0
      && operationalSecretSamples.every((sample) => rawMaterial.includes(sample)),
    reportPhaseOnlyRedaction: /redact-only-during-report-export|report-export-only|reportPhaseOnlyRedaction/i.test(rawMaterial),
  };
  const digestPreview = simpleDigest(JSON.stringify({
    generatedAt,
    packageRefreshProof,
    requirements,
  }));
  const content = JSON.stringify({
    kind: 'proxyforge-analysis-tool-refresh-evidence-package',
    generatedAt,
    linkedPackages: slots.map(({ item, fallbackKind, prefix }, index) => ({
      id: linkedPackageId(item, index, prefix),
      kind: linkedPackageKind(item, fallbackKind),
      reportReady: linkedPackageReady(item),
      content: linkedPackageText(item),
    })),
    packageRefreshProof,
    requirements,
    operationalSecretSamples,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    digestPreview,
  }, null, 2);

  return {
    id: `analysis-tool-refresh-${digestPreview.slice(0, 12)}`,
    kind: 'proxyforge-analysis-tool-refresh-evidence-package',
    title: 'Analysis tool package-refresh evidence',
    fileName: `proxyforge-analysis-tool-refresh-evidence-${stamp}.json`,
    path: `analysis/proxyforge-analysis-tool-refresh-evidence-${stamp}.json`,
    generatedAt,
    linkedPackageKinds,
    packageRefreshProof,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
    digestPreview,
    summary: `Analysis tool refresh links Search, Logger, Organizer, Viewer, Sequencer, Decoder, and Comparer package digests with ${stalePackageIds.length} stale package(s).`,
    content,
  };
}

function linkedPackageKind(item: AnalysisLinkedEvidencePackage, fallbackKind: RequiredPackageKind) {
  if (item.kind) return item.kind;
  const parsed = parseContentObject(item);
  return typeof parsed?.kind === 'string' ? parsed.kind : fallbackKind;
}

function linkedPackageId(item: AnalysisLinkedEvidencePackage, index: number, prefix: string) {
  if (item.id) return item.id;
  const parsed = parseContentObject(item);
  if (typeof parsed?.id === 'string') return parsed.id;
  const digest = simpleDigest(linkedPackageText(item));
  return `${prefix}-${index + 1}-${digest.slice(0, 8)}`;
}

function linkedPackageText(item: AnalysisLinkedEvidencePackage) {
  if (item.content) return item.content;
  if (item.summary) return item.summary;
  return JSON.stringify(item);
}

function linkedPackageReady(item: AnalysisLinkedEvidencePackage) {
  if (item.reportReady === false) return false;
  if (/failed|blocked|stale/i.test(item.status ?? '')) return false;
  const parsed = parseContentObject(item);
  const requirements = item.requirements ?? parsed?.requirements;
  if (requirements && typeof requirements === 'object' && !Array.isArray(requirements)) {
    return Object.values(requirements as Record<string, unknown>).every((value) => value !== false);
  }
  return true;
}

function parseContentObject(item: AnalysisLinkedEvidencePackage): Record<string, unknown> | undefined {
  if (!item.content) return undefined;
  try {
    const parsed = JSON.parse(item.content) as unknown;
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
  } catch {
    return undefined;
  }
  return undefined;
}

function uniqueValues(values: string[]) {
  return Array.from(new Set(values.filter(Boolean))).sort((left, right) => left.localeCompare(right));
}

function simpleDigest(value: string) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `${hash.toString(16).padStart(8, '0')}${value.length.toString(16).padStart(8, '0')}`;
}
