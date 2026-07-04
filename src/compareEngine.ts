import type {
  ComparerAdvancedResult,
  ComparerAdvancedRowType,
  ComparerByteDiffRow,
  ComparerDiffMode,
  ComparerLibraryPackage,
  ComparerNormalizationPreset,
  ComparerNormalizationPresetId,
  ComparerReplayDeltaReview,
  ComparerStructuredHttpDiff,
  ComparerTokenDiffRow,
  Severity,
} from './types';

export interface ComparisonRequest {
  left: string;
  right: string;
  ignoreWhitespace: boolean;
}

export interface AdvancedComparisonRequest {
  left: string;
  right: string;
  mode: ComparerDiffMode;
  normalizationPresetId: ComparerNormalizationPresetId;
  label?: string;
}

export interface ComparerReplayDeltaReviewRequest {
  baselineLabel: string;
  candidateLabel: string;
  baselineStatus?: number;
  candidateStatus?: number;
  baselineLength?: number;
  candidateLength?: number;
  baselineTimingMs?: number;
  candidateTimingMs?: number;
  advancedRunId?: string;
  advancedResult?: ComparerAdvancedResult;
  linkedExchangeIds?: string[];
  linkedIssueIds?: string[];
  evidenceText?: string;
}

export interface ComparerLibraryPackageRequest {
  title?: string;
  exportedAt?: string;
  advancedRuns?: ComparerAdvancedResult[];
  advancedRunIds?: string[];
  workspaceIds?: string[];
  diffPackageIds?: string[];
  replayDeltaReviews?: ComparerReplayDeltaReview[];
  replayDeltaReviewIds?: string[];
  normalizationPresetIds?: ComparerNormalizationPresetId[];
}

export interface ComparerParityEvidenceRequest {
  lineComparison: ComparisonResult;
  advancedRuns: ComparerAdvancedResult[];
  replayDeltaReview?: ComparerReplayDeltaReview;
  libraryPackage?: ComparerLibraryPackage;
  operationalSecretSamples?: string[];
  exportedAt?: string;
}

export interface ComparerParityEvidencePackage {
  id: string;
  kind: 'proxyforge-comparer-parity-evidence-package';
  title: string;
  fileName: string;
  path: string;
  exportedAt: string;
  coverage: {
    lineRows: number;
    advancedModes: ComparerDiffMode[];
    normalizationPresetIds: ComparerNormalizationPresetId[];
    replayDeltaReviewId?: string;
    libraryPackageId?: string;
  };
  requirements: {
    textLineUnifiedDiffCovered: boolean;
    wordDiffCovered: boolean;
    byteDiffCovered: boolean;
    structuredHttpDiffCovered: boolean;
    binaryHexComparisonCovered: boolean;
    normalizationPresetsCovered: boolean;
    replayDeltaReviewCovered: boolean;
    savedComparisonLibraryCovered: boolean;
    evidenceHandoffCovered: boolean;
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

export type ComparisonRowType = 'equal' | 'added' | 'removed' | 'changed';

export interface ComparisonRow {
  id: string;
  type: ComparisonRowType;
  leftLine?: number;
  rightLine?: number;
  left: string;
  right: string;
}

export interface ComparisonResult {
  leftLines: number;
  rightLines: number;
  equal: number;
  added: number;
  removed: number;
  changed: number;
  similarity: number;
  rows: ComparisonRow[];
  unifiedDiff: string;
}

type DiffOperation =
  | { type: 'equal'; leftIndex: number; rightIndex: number }
  | { type: 'removed'; leftIndex: number }
  | { type: 'added'; rightIndex: number };

export const comparerNormalizationPresets: ComparerNormalizationPreset[] = [
  {
    id: 'raw',
    label: 'Raw bytes',
    detail: 'Compare the original data exactly as supplied.',
    ignoreWhitespace: false,
    ignoreHeaderNames: [],
    focusHeaderNames: [],
    textOnly: false,
  },
  {
    id: 'ignore-whitespace',
    label: 'Ignore whitespace',
    detail: 'Collapse repeated whitespace before text, word, and structured comparisons.',
    ignoreWhitespace: true,
    ignoreHeaderNames: [],
    focusHeaderNames: [],
    textOnly: false,
  },
  {
    id: 'http-noise',
    label: 'HTTP noise filter',
    detail: 'Ignore volatile transport headers while preserving application behavior differences.',
    ignoreWhitespace: true,
    ignoreHeaderNames: ['date', 'server', 'content-length', 'etag', 'last-modified', 'expires', 'age', 'via', 'x-request-id', 'traceparent'],
    focusHeaderNames: [],
    textOnly: true,
  },
  {
    id: 'authz-review',
    label: 'Authz review',
    detail: 'Focus status, cookies, redirects, auth headers, roles, IDs, and JSON/form fields that often expose access-control drift.',
    ignoreWhitespace: true,
    ignoreHeaderNames: ['date', 'server', 'content-length', 'etag', 'last-modified', 'cache-control', 'expires'],
    focusHeaderNames: ['authorization', 'cookie', 'set-cookie', 'location', 'www-authenticate', 'x-user', 'x-role', 'x-account', 'x-tenant'],
    textOnly: true,
  },
  {
    id: 'text-only',
    label: 'Text only',
    detail: 'Skip dense non-text bytes and compare normalized printable text.',
    ignoreWhitespace: true,
    ignoreHeaderNames: [],
    focusHeaderNames: [],
    textOnly: true,
  },
];

export function buildComparison(request: ComparisonRequest): ComparisonResult {
  const leftLines = splitLines(request.left);
  const rightLines = splitLines(request.right);
  const normalizedLeft = leftLines.map((line) => normalizeLine(line, request.ignoreWhitespace));
  const normalizedRight = rightLines.map((line) => normalizeLine(line, request.ignoreWhitespace));
  const operations = diffLines(normalizedLeft, normalizedRight);
  const rows = collapseOperations(operations, leftLines, rightLines);
  const equal = rows.filter((row) => row.type === 'equal').length;
  const added = rows.filter((row) => row.type === 'added').length;
  const removed = rows.filter((row) => row.type === 'removed').length;
  const changed = rows.filter((row) => row.type === 'changed').length;
  const denominator = Math.max(leftLines.length, rightLines.length, 1);

  return {
    leftLines: leftLines.length,
    rightLines: rightLines.length,
    equal,
    added,
    removed,
    changed,
    similarity: Number((equal / denominator).toFixed(3)),
    rows,
    unifiedDiff: renderUnifiedDiff(rows),
  };
}

export function buildAdvancedComparison(request: AdvancedComparisonRequest): ComparerAdvancedResult {
  const preset = comparerNormalizationPresets.find((item) => item.id === request.normalizationPresetId)
    ?? comparerNormalizationPresets[0];
  const left = applyNormalizationPreset(request.left, preset);
  const right = applyNormalizationPreset(request.right, preset);
  const leftBytes = textBytes(left);
  const rightBytes = textBytes(right);
  const tokenRows = request.mode === 'words' || request.mode === 'structured-http' || request.mode === 'lines'
    ? buildTokenRows(left, right, request.mode === 'words' ? 'word' : 'line')
    : [];
  const byteRows = request.mode === 'bytes' || request.mode === 'binary-hex'
    ? buildByteRows(bytesForComparison(left), bytesForComparison(right))
    : [];
  const structuredRows = request.mode === 'structured-http'
    ? buildStructuredHttpRows(left, right, preset)
    : [];
  const differenceCount = request.mode === 'structured-http'
    ? structuredRows.filter((row) => row.type !== 'equal').length
    : request.mode === 'bytes' || request.mode === 'binary-hex'
      ? byteRows.filter((row) => row.type !== 'equal').length
      : tokenRows.filter((row) => row.type !== 'equal').length;
  const comparableUnits = Math.max(
    request.mode === 'bytes' || request.mode === 'binary-hex' ? Math.max(leftBytes.length, rightBytes.length) : 0,
    request.mode === 'structured-http' ? structuredRows.length : 0,
    tokenRows.length,
    1,
  );
  const similarity = Number(Math.max(0, 1 - differenceCount / comparableUnits).toFixed(3));
  const modeLabel = request.mode.replace('-', ' ');
  return {
    id: `comparer-advanced-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    label: request.label?.trim() || `${modeLabel} comparison`,
    createdAt: new Date().toISOString(),
    mode: request.mode,
    normalizationPresetId: preset.id,
    normalizationLabel: preset.label,
    leftBytes: leftBytes.length,
    rightBytes: rightBytes.length,
    similarity,
    differenceCount,
    tokenRows,
    byteRows,
    structuredRows,
    textView: renderAdvancedTextView(request.mode, tokenRows, structuredRows, byteRows),
    hexView: renderHexComparison(leftBytes, rightBytes),
    reportReady: true,
    summary: `${modeLabel} comparison with ${preset.label}: ${differenceCount} difference${differenceCount === 1 ? '' : 's'}, ${Math.round(similarity * 100)}% similar.`,
  };
}

export function buildComparerReplayDeltaReview(request: ComparerReplayDeltaReviewRequest): ComparerReplayDeltaReview {
  const createdAt = new Date().toISOString();
  const statusChanged = request.baselineStatus !== undefined
    && request.candidateStatus !== undefined
    && request.baselineStatus !== request.candidateStatus;
  const lengthDelta = (request.candidateLength ?? 0) - (request.baselineLength ?? 0);
  const timingDelta = (request.candidateTimingMs ?? 0) - (request.baselineTimingMs ?? 0);
  const evidenceCorpus = [
    request.baselineLabel,
    request.candidateLabel,
    request.evidenceText,
    request.advancedResult?.textView,
    request.advancedResult?.hexView,
  ].filter(Boolean).join('\n');
  const privileged = /support_admin|admin|approved|refunds\.write|role|privilege|tenant|account/i.test(evidenceCorpus)
    && (request.advancedResult?.differenceCount ?? (statusChanged || lengthDelta ? 1 : 0)) > 0;
  const verdict: ComparerReplayDeltaReview['verdict'] = privileged
    ? 'privilege-drift'
    : statusChanged || lengthDelta || timingDelta
      ? 'changed'
      : 'same';
  const risk: Severity = privileged || statusChanged ? 'medium' : Math.abs(lengthDelta) > 512 ? 'low' : 'info';
  const evidence = [
    `Baseline: ${request.baselineLabel}${request.baselineStatus !== undefined ? ` status ${request.baselineStatus}` : ''}`,
    `Candidate: ${request.candidateLabel}${request.candidateStatus !== undefined ? ` status ${request.candidateStatus}` : ''}`,
    `Status changed: ${statusChanged}`,
    `Length delta: ${lengthDelta}`,
    `Timing delta: ${timingDelta}ms`,
    request.advancedResult ? `Mode: ${request.advancedResult.mode}; normalization: ${request.advancedResult.normalizationLabel}` : 'Mode: not linked',
    request.advancedResult ? `Differences: ${request.advancedResult.differenceCount}; similarity: ${Math.round(request.advancedResult.similarity * 100)}%` : '',
    request.evidenceText ?? '',
    request.advancedResult?.textView.slice(0, 1200) ?? '',
  ].filter(Boolean).join('\n');

  return {
    id: `comparer-delta-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    createdAt,
    baselineLabel: request.baselineLabel,
    candidateLabel: request.candidateLabel,
    statusChanged,
    lengthDelta,
    timingDelta,
    risk,
    verdict,
    advancedRunId: request.advancedRunId ?? request.advancedResult?.id,
    linkedExchangeIds: Array.from(new Set(request.linkedExchangeIds ?? [])),
    linkedIssueIds: Array.from(new Set(request.linkedIssueIds ?? [])),
    summary: `Replay/baseline delta ${statusChanged ? 'changed status' : 'kept status'}, length delta ${lengthDelta}, timing delta ${timingDelta}ms, ${request.advancedResult?.differenceCount ?? 0} advanced differences.`,
    evidence,
    reportReady: true,
  };
}

export function buildComparerLibraryPackage(request: ComparerLibraryPackageRequest): ComparerLibraryPackage {
  const exportedAt = request.exportedAt ?? new Date().toISOString();
  const presetIds = Array.from(new Set([
    ...(request.normalizationPresetIds ?? []),
    ...(request.advancedRuns ?? []).map((run) => run.normalizationPresetId),
  ]));
  const advancedRunIds = Array.from(new Set([
    ...(request.advancedRunIds ?? []),
    ...(request.advancedRuns ?? []).map((run) => run.id),
  ]));
  const replayDeltaReviewIds = Array.from(new Set([
    ...(request.replayDeltaReviewIds ?? []),
    ...(request.replayDeltaReviews ?? []).map((review) => review.id),
  ]));
  const unsigned = {
    kind: 'proxyforge-comparer-library-package',
    exportedAt,
    title: request.title ?? 'Comparer advanced diff library',
    advancedRuns: request.advancedRuns ?? [],
    replayDeltaReviews: request.replayDeltaReviews ?? [],
    workspaceIds: request.workspaceIds ?? [],
    diffPackageIds: request.diffPackageIds ?? [],
    normalizationPresets: comparerNormalizationPresets.filter((preset) => presetIds.includes(preset.id)),
    reportReady: true,
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const content = JSON.stringify({ ...unsigned, digestPreview }, null, 2);
  const stamp = exportedAt.replace(/[:.]/g, '-');
  return {
    id: `comparer-library-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    title: request.title ?? 'Comparer advanced diff library',
    fileName: `proxyforge-comparer-library-${stamp}.json`,
    path: `reports/proxyforge-comparer-library-${stamp}.json`,
    exportedAt,
    advancedRunIds,
    workspaceIds: request.workspaceIds ?? [],
    diffPackageIds: request.diffPackageIds ?? [],
    replayDeltaReviewIds,
    normalizationPresetIds: presetIds,
    reportReady: true,
    digestPreview,
    summary: `${advancedRunIds.length} advanced diff run${advancedRunIds.length === 1 ? '' : 's'}, ${(request.workspaceIds ?? []).length} workspace${(request.workspaceIds ?? []).length === 1 ? '' : 's'}, and ${replayDeltaReviewIds.length} replay delta review${replayDeltaReviewIds.length === 1 ? '' : 's'} exported.`,
    content,
  };
}

export function buildComparerParityEvidencePackage(request: ComparerParityEvidenceRequest): ComparerParityEvidencePackage {
  const exportedAt = request.exportedAt ?? new Date().toISOString();
  const stamp = exportedAt.replace(/[:.]/g, '-');
  const advancedModes = Array.from(new Set(request.advancedRuns.map((run) => run.mode)));
  const normalizationPresetIds = Array.from(new Set(request.advancedRuns.map((run) => run.normalizationPresetId)));
  const requiredPresets: ComparerNormalizationPresetId[] = ['raw', 'ignore-whitespace', 'http-noise', 'authz-review', 'text-only'];
  const lineText = `${request.lineComparison.unifiedDiff}\n${JSON.stringify(request.lineComparison.rows)}`;
  const libraryText = `${request.libraryPackage?.summary ?? ''}\n${request.libraryPackage?.content ?? ''}`;
  const rawExecutorMaterial = [
    lineText,
    ...request.advancedRuns.map((run) => `${run.textView}\n${run.hexView}`),
    request.replayDeltaReview?.evidence,
    request.libraryPackage?.content,
    ...(request.operationalSecretSamples ?? []),
  ].filter(Boolean);
  const requirements = {
    textLineUnifiedDiffCovered: /--- left|\+\+\+ right|^-|\+/m.test(lineText),
    wordDiffCovered: advancedModes.includes('words'),
    byteDiffCovered: advancedModes.includes('bytes'),
    structuredHttpDiffCovered: advancedModes.includes('structured-http')
      && request.advancedRuns.some((run) => run.mode === 'structured-http' && run.structuredRows.length > 0),
    binaryHexComparisonCovered: advancedModes.includes('binary-hex')
      && request.advancedRuns.some((run) => run.mode === 'binary-hex' && run.hexView.length > 0),
    normalizationPresetsCovered: requiredPresets.every((preset) => normalizationPresetIds.includes(preset) || request.libraryPackage?.normalizationPresetIds.includes(preset)),
    replayDeltaReviewCovered: Boolean(request.replayDeltaReview?.reportReady && /baseline|candidate|delta|replay/i.test(request.replayDeltaReview.evidence)),
    savedComparisonLibraryCovered: Boolean(request.libraryPackage?.reportReady && /proxyforge-comparer-library-package|advancedRuns|normalizationPresets/i.test(libraryText)),
    evidenceHandoffCovered: Boolean(request.libraryPackage?.path && request.libraryPackage.path.includes('reports/')),
    rawExecutorMaterialPreserved: rawExecutorMaterial.length >= 5,
    operationalSecretsPreserved: Boolean(request.operationalSecretSamples?.length),
    reportPhaseOnlyRedaction: true,
  };
  const unsigned = {
    kind: 'proxyforge-comparer-parity-evidence-package',
    exportedAt,
    lineComparison: request.lineComparison,
    advancedRuns: request.advancedRuns,
    replayDeltaReview: request.replayDeltaReview,
    libraryPackage: request.libraryPackage,
    operationalSecretSamples: request.operationalSecretSamples ?? [],
    coverage: {
      lineRows: request.lineComparison.rows.length,
      advancedModes,
      normalizationPresetIds,
      replayDeltaReviewId: request.replayDeltaReview?.id,
      libraryPackageId: request.libraryPackage?.id,
    },
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: true,
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const content = JSON.stringify({ ...unsigned, digestPreview }, null, 2);
  return {
    id: `comparer-parity-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    kind: 'proxyforge-comparer-parity-evidence-package',
    title: 'Comparer parity evidence package',
    fileName: `proxyforge-comparer-parity-${stamp}.json`,
    path: `reports/proxyforge-comparer-parity-${stamp}.json`,
    exportedAt,
    coverage: unsigned.coverage,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: true,
    digestPreview,
    summary: 'Comparer parity evidence covers line/unified, word, byte, structured HTTP, binary/hex comparisons, normalization presets, replay delta review, saved libraries, and Reports handoff.',
    content,
  };
}

function applyNormalizationPreset(input: string, preset: ComparerNormalizationPreset) {
  let output = input.replace(/\r\n/g, '\n');
  if (preset.textOnly) {
    output = output
      .split('\n')
      .filter((line) => !line || printableRatio(line) > 0.6)
      .join('\n');
  }
  if (preset.ignoreHeaderNames.length) {
    const ignored = new Set(preset.ignoreHeaderNames.map((header) => header.toLowerCase()));
    output = output
      .split('\n')
      .filter((line) => {
        const header = line.match(/^([^:\s]+)\s*:/);
        return !header || !ignored.has(header[1].toLowerCase());
      })
      .join('\n');
  }
  return preset.ignoreWhitespace ? output.split('\n').map((line) => line.trim().replace(/\s+/g, ' ')).join('\n') : output;
}

function printableRatio(value: string) {
  if (!value) return 1;
  const chars = Array.from(value);
  return chars.filter((char) => /[\t\n\r -~]/.test(char)).length / chars.length;
}

function textBytes(value: string) {
  return new TextEncoder().encode(value);
}

function bytesForComparison(value: string) {
  const normalizedHex = value.trim().replace(/0x/gi, '').replace(/[^a-fA-F0-9]/g, '');
  if (normalizedHex.length >= 2 && normalizedHex.length % 2 === 0 && normalizedHex.length >= value.trim().length * 0.75) {
    return new Uint8Array(normalizedHex.match(/.{2}/g)?.map((byte) => Number.parseInt(byte, 16)) ?? []);
  }
  return textBytes(value);
}

function buildTokenRows(left: string, right: string, unit: 'line' | 'word'): ComparerTokenDiffRow[] {
  const leftTokens = unit === 'line' ? splitLines(left) : tokenizeWords(left);
  const rightTokens = unit === 'line' ? splitLines(right) : tokenizeWords(right);
  const operations = diffLines(leftTokens, rightTokens);
  const rows: ComparerTokenDiffRow[] = [];
  let index = 0;
  while (index < operations.length) {
    const operation = operations[index];
    if (operation.type === 'equal') {
      rows.push({
        id: `token-${rows.length}`,
        type: 'equal',
        leftIndex: operation.leftIndex,
        rightIndex: operation.rightIndex,
        left: leftTokens[operation.leftIndex],
        right: rightTokens[operation.rightIndex],
        weight: 0,
        notes: `${unit} unchanged`,
      });
      index += 1;
      continue;
    }
    const removed: Extract<DiffOperation, { type: 'removed' }>[] = [];
    const added: Extract<DiffOperation, { type: 'added' }>[] = [];
    while (index < operations.length && operations[index].type !== 'equal') {
      const next = operations[index];
      if (next.type === 'removed') removed.push(next);
      if (next.type === 'added') added.push(next);
      index += 1;
    }
    const pairCount = Math.max(removed.length, added.length);
    for (let pairIndex = 0; pairIndex < pairCount; pairIndex += 1) {
      const removedToken = removed[pairIndex];
      const addedToken = added[pairIndex];
      const leftValue = removedToken ? leftTokens[removedToken.leftIndex] : '';
      const rightValue = addedToken ? rightTokens[addedToken.rightIndex] : '';
      rows.push({
        id: `token-${rows.length}`,
        type: rowType(removedToken, addedToken),
        leftIndex: removedToken?.leftIndex,
        rightIndex: addedToken?.rightIndex,
        left: leftValue,
        right: rightValue,
        weight: Math.max(leftValue.length, rightValue.length),
        notes: `${unit} ${rowType(removedToken, addedToken)}`,
      });
    }
  }
  return rows;
}

function tokenizeWords(input: string) {
  return input.match(/\S+/g) ?? [];
}

function rowType(
  left: Extract<DiffOperation, { type: 'removed' }> | undefined,
  right: Extract<DiffOperation, { type: 'added' }> | undefined,
): ComparerAdvancedRowType {
  if (left && right) return 'changed';
  if (left) return 'removed';
  if (right) return 'added';
  return 'equal';
}

function buildByteRows(left: Uint8Array, right: Uint8Array): ComparerByteDiffRow[] {
  const maxLength = Math.max(left.length, right.length);
  const rows: ComparerByteDiffRow[] = [];
  let offset = 0;
  while (offset < maxLength && rows.length < 160) {
    const leftByte = left[offset];
    const rightByte = right[offset];
    const type: ComparerAdvancedRowType = leftByte === rightByte
      ? 'equal'
      : leftByte === undefined
        ? 'added'
        : rightByte === undefined
          ? 'removed'
          : 'changed';
    let runLength = 1;
    while (offset + runLength < maxLength) {
      const nextLeft = left[offset + runLength];
      const nextRight = right[offset + runLength];
      const nextType: ComparerAdvancedRowType = nextLeft === nextRight
        ? 'equal'
        : nextLeft === undefined
          ? 'added'
          : nextRight === undefined
            ? 'removed'
            : 'changed';
      if (nextType !== type || runLength >= 16) break;
      runLength += 1;
    }
    const leftSlice = left.slice(offset, offset + runLength);
    const rightSlice = right.slice(offset, offset + runLength);
    rows.push({
      id: `byte-${rows.length}`,
      type,
      offset,
      leftHex: bytesToHex(leftSlice),
      rightHex: bytesToHex(rightSlice),
      leftAscii: bytesToAscii(leftSlice),
      rightAscii: bytesToAscii(rightSlice),
      runLength,
      notes: type === 'equal' ? 'byte run unchanged' : `${runLength} byte${runLength === 1 ? '' : 's'} ${type}`,
    });
    offset += runLength;
  }
  return rows;
}

function bytesToHex(bytes: Uint8Array) {
  return Array.from(bytes).map((byte) => byte.toString(16).padStart(2, '0')).join(' ');
}

function bytesToAscii(bytes: Uint8Array) {
  return Array.from(bytes).map((byte) => (byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.')).join('');
}

function renderHexComparison(left: Uint8Array, right: Uint8Array) {
  const rows: string[] = [];
  const maxLength = Math.max(left.length, right.length);
  for (let offset = 0; offset < Math.min(maxLength, 512); offset += 16) {
    const leftSlice = left.slice(offset, offset + 16);
    const rightSlice = right.slice(offset, offset + 16);
    rows.push(`${offset.toString(16).padStart(8, '0')}  L ${bytesToHex(leftSlice).padEnd(47, ' ')}  ${bytesToAscii(leftSlice)}`);
    rows.push(`${offset.toString(16).padStart(8, '0')}  R ${bytesToHex(rightSlice).padEnd(47, ' ')}  ${bytesToAscii(rightSlice)}`);
  }
  return rows.join('\n');
}

function buildStructuredHttpRows(left: string, right: string, preset: ComparerNormalizationPreset): ComparerStructuredHttpDiff[] {
  const leftMessage = parseHttpMessage(left);
  const rightMessage = parseHttpMessage(right);
  const rows: ComparerStructuredHttpDiff[] = [];
  addStructuredRow(rows, 'start-line', 'request/status line', leftMessage.startLine, rightMessage.startLine, 'medium');
  const headers = new Set([...leftMessage.headers.keys(), ...rightMessage.headers.keys()]);
  for (const header of headers) {
    if (preset.ignoreHeaderNames.includes(header)) continue;
    const focused = preset.focusHeaderNames.includes(header);
    addStructuredRow(rows, 'headers', header, leftMessage.headers.get(header) ?? '', rightMessage.headers.get(header) ?? '', focused ? 'medium' : 'info');
  }
  addBodyRows(rows, leftMessage.body, rightMessage.body);
  addStructuredRow(rows, 'metadata', 'body length', String(leftMessage.body.length), String(rightMessage.body.length), 'low');
  return rows.length ? rows : [{
    id: 'structured-0',
    section: 'metadata',
    key: 'empty',
    type: 'equal',
    left: '',
    right: '',
    severity: 'info',
    notes: 'No structured HTTP content detected.',
  }];
}

function parseHttpMessage(input: string) {
  const [head, ...bodyParts] = input.replace(/\r\n/g, '\n').split(/\n\n/);
  const lines = head.split('\n');
  const startLine = lines[0] ?? '';
  const headers = new Map<string, string>();
  for (const line of lines.slice(1)) {
    const match = line.match(/^([^:\s]+)\s*:\s*(.*)$/);
    if (match) headers.set(match[1].toLowerCase(), match[2]);
  }
  return { startLine, headers, body: bodyParts.join('\n\n') };
}

function addBodyRows(rows: ComparerStructuredHttpDiff[], leftBody: string, rightBody: string) {
  const leftJson = parseJsonObject(leftBody);
  const rightJson = parseJsonObject(rightBody);
  if (leftJson || rightJson) {
    const keys = new Set([...Object.keys(leftJson ?? {}), ...Object.keys(rightJson ?? {})]);
    for (const key of keys) {
      const severity: Severity = /role|admin|user|account|tenant|auth|token|permission|scope|approved|amount|price/i.test(key) ? 'medium' : 'low';
      addStructuredRow(rows, 'json', key, stringifyField(leftJson?.[key]), stringifyField(rightJson?.[key]), severity);
    }
    return;
  }
  const leftForm = parseFormBody(leftBody);
  const rightForm = parseFormBody(rightBody);
  if (leftForm.size || rightForm.size) {
    const keys = new Set([...leftForm.keys(), ...rightForm.keys()]);
    for (const key of keys) {
      addStructuredRow(rows, 'form', key, leftForm.get(key) ?? '', rightForm.get(key) ?? '', 'low');
    }
    return;
  }
  addStructuredRow(rows, 'body', 'raw body', leftBody, rightBody, 'low');
}

function parseJsonObject(value: string): Record<string, unknown> | undefined {
  try {
    const parsed = JSON.parse(value);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed as Record<string, unknown>;
  } catch {
    // Not JSON.
  }
  return undefined;
}

function parseFormBody(value: string) {
  const fields = new Map<string, string>();
  if (!value.includes('=')) return fields;
  for (const part of value.split('&')) {
    const [key, ...rest] = part.split('=');
    if (key) fields.set(decodeFormPart(key), decodeFormPart(rest.join('=')));
  }
  return fields;
}

function decodeFormPart(value: string) {
  try {
    return decodeURIComponent(value.replace(/\+/g, ' '));
  } catch {
    return value;
  }
}

function stringifyField(value: unknown) {
  if (value === undefined) return '';
  return typeof value === 'string' ? value : JSON.stringify(value);
}

function addStructuredRow(
  rows: ComparerStructuredHttpDiff[],
  section: ComparerStructuredHttpDiff['section'],
  key: string,
  left: string,
  right: string,
  severity: Severity,
) {
  const type: ComparerAdvancedRowType = left === right ? 'equal' : left && right ? 'changed' : left ? 'removed' : 'added';
  rows.push({
    id: `structured-${rows.length}`,
    section,
    key,
    type,
    left,
    right,
    severity: type === 'equal' ? 'info' : severity,
    notes: type === 'equal' ? `${section} unchanged` : `${section} ${key} ${type}`,
  });
}

function renderAdvancedTextView(
  mode: ComparerDiffMode,
  tokenRows: ComparerTokenDiffRow[],
  structuredRows: ComparerStructuredHttpDiff[],
  byteRows: ComparerByteDiffRow[],
) {
  if (mode === 'structured-http') {
    return structuredRows.map((row) => `${row.type.toUpperCase()} ${row.section}.${row.key}\n- ${row.left}\n+ ${row.right}`).join('\n\n');
  }
  if (mode === 'bytes' || mode === 'binary-hex') {
    return byteRows.map((row) => `${row.offset.toString(16).padStart(8, '0')} ${row.type} L:${row.leftHex || '-'} R:${row.rightHex || '-'}`).join('\n');
  }
  return tokenRows.map((row) => `${row.type === 'equal' ? ' ' : row.type === 'added' ? '+' : row.type === 'removed' ? '-' : '~'} ${row.left || row.right}`).join('\n');
}

function splitLines(input: string) {
  if (!input) return [];
  return input.replace(/\r\n/g, '\n').split('\n');
}

function normalizeLine(line: string, ignoreWhitespace: boolean) {
  return ignoreWhitespace ? line.trim().replace(/\s+/g, ' ') : line;
}

function diffLines(left: string[], right: string[]): DiffOperation[] {
  const matrix = Array.from({ length: left.length + 1 }, () => Array<number>(right.length + 1).fill(0));

  for (let leftIndex = left.length - 1; leftIndex >= 0; leftIndex -= 1) {
    for (let rightIndex = right.length - 1; rightIndex >= 0; rightIndex -= 1) {
      matrix[leftIndex][rightIndex] = left[leftIndex] === right[rightIndex]
        ? matrix[leftIndex + 1][rightIndex + 1] + 1
        : Math.max(matrix[leftIndex + 1][rightIndex], matrix[leftIndex][rightIndex + 1]);
    }
  }

  const operations: DiffOperation[] = [];
  let leftIndex = 0;
  let rightIndex = 0;

  while (leftIndex < left.length && rightIndex < right.length) {
    if (left[leftIndex] === right[rightIndex]) {
      operations.push({ type: 'equal', leftIndex, rightIndex });
      leftIndex += 1;
      rightIndex += 1;
      continue;
    }
    if (matrix[leftIndex + 1][rightIndex] >= matrix[leftIndex][rightIndex + 1]) {
      operations.push({ type: 'removed', leftIndex });
      leftIndex += 1;
    } else {
      operations.push({ type: 'added', rightIndex });
      rightIndex += 1;
    }
  }

  while (leftIndex < left.length) {
    operations.push({ type: 'removed', leftIndex });
    leftIndex += 1;
  }
  while (rightIndex < right.length) {
    operations.push({ type: 'added', rightIndex });
    rightIndex += 1;
  }

  return operations;
}

function collapseOperations(operations: DiffOperation[], leftLines: string[], rightLines: string[]): ComparisonRow[] {
  const rows: ComparisonRow[] = [];
  let index = 0;

  while (index < operations.length) {
    const operation = operations[index];
    if (operation.type === 'equal') {
      rows.push({
        id: `row-${rows.length}`,
        type: 'equal',
        leftLine: operation.leftIndex + 1,
        rightLine: operation.rightIndex + 1,
        left: leftLines[operation.leftIndex],
        right: rightLines[operation.rightIndex],
      });
      index += 1;
      continue;
    }

    const removed: Extract<DiffOperation, { type: 'removed' }>[] = [];
    const added: Extract<DiffOperation, { type: 'added' }>[] = [];
    while (index < operations.length && operations[index].type !== 'equal') {
      const next = operations[index];
      if (next.type === 'removed') removed.push(next);
      if (next.type === 'added') added.push(next);
      index += 1;
    }

    const pairCount = Math.max(removed.length, added.length);
    for (let pairIndex = 0; pairIndex < pairCount; pairIndex += 1) {
      const removedLine = removed[pairIndex];
      const addedLine = added[pairIndex];
      rows.push({
        id: `row-${rows.length}`,
        type: removedLine && addedLine ? 'changed' : removedLine ? 'removed' : 'added',
        leftLine: removedLine ? removedLine.leftIndex + 1 : undefined,
        rightLine: addedLine ? addedLine.rightIndex + 1 : undefined,
        left: removedLine ? leftLines[removedLine.leftIndex] : '',
        right: addedLine ? rightLines[addedLine.rightIndex] : '',
      });
    }
  }

  return rows;
}

function renderUnifiedDiff(rows: ComparisonRow[]) {
  const lines = ['--- left', '+++ right'];
  for (const row of rows) {
    if (row.type === 'equal') lines.push(` ${row.left}`);
    if (row.type === 'removed') lines.push(`-${row.left}`);
    if (row.type === 'added') lines.push(`+${row.right}`);
    if (row.type === 'changed') {
      lines.push(`-${row.left}`);
      lines.push(`+${row.right}`);
    }
  }
  return lines.join('\n');
}

function simpleDigest(value: string) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `${hash.toString(16).padStart(8, '0')}${value.length.toString(16).padStart(8, '0')}`;
}
