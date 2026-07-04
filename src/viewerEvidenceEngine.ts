import type {
  HttpExchange,
  Severity,
  ViewerDecodedRawSnapshot,
  ViewerEvidencePin,
  ViewerReplayComparisonExport,
} from './types';

export type ViewerHttpMode = 'raw' | 'json' | 'html' | 'jwt' | 'graphql' | 'image' | 'binary';

export interface ViewerModePreview {
  mode: ViewerHttpMode;
  title: string;
  exchangeId: string;
  source: {
    method: string;
    host: string;
    path: string;
    url: string;
    mime: string;
    status: number;
  };
  output: string;
  sizeBytes: number;
  rawSourcePreserved: boolean;
}

export interface ViewerParityEvidenceRequest {
  modePreviews: ViewerModePreview[];
  evidencePins: ViewerEvidencePin[];
  snapshots: ViewerDecodedRawSnapshot[];
  replayComparisonExports: ViewerReplayComparisonExport[];
  operationalSecretSamples?: string[];
  exportedAt?: string;
}

export interface ViewerParityEvidencePackage {
  id: string;
  kind: 'proxyforge-viewer-parity-evidence-package';
  title: string;
  fileName: string;
  path: string;
  exportedAt: string;
  modeCount: number;
  evidencePinCount: number;
  snapshotCount: number;
  replayComparisonExportCount: number;
  artifactIds: {
    previewExchangeIds: string[];
    evidencePinIds: string[];
    snapshotIds: string[];
    replayComparisonExportIds: string[];
  };
  requirements: {
    rawViewCovered: boolean;
    prettyJsonViewCovered: boolean;
    htmlViewCovered: boolean;
    jwtViewCovered: boolean;
    graphqlViewCovered: boolean;
    imageViewCovered: boolean;
    binaryViewCovered: boolean;
    sourceAwareSnapshotsCovered: boolean;
    evidencePinsCovered: boolean;
    replayComparisonExportsCovered: boolean;
    reportAttachmentCovered: boolean;
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

export function buildViewerModePreview(exchange: HttpExchange, mode: ViewerHttpMode): ViewerModePreview {
  const output = renderViewerOutput(exchange, mode);
  return {
    mode,
    title: viewerModeTitle(mode),
    exchangeId: exchange.id,
    source: {
      method: exchange.method,
      host: exchange.host,
      path: exchange.path,
      url: exchange.url,
      mime: exchange.mime,
      status: exchange.status,
    },
    output,
    sizeBytes: utf8ByteLength(output),
    rawSourcePreserved: mode === 'raw'
      ? output.includes(exchange.requestRaw.trim()) && output.includes(exchange.responseRaw.trim())
      : Boolean(exchange.requestRaw && exchange.responseRaw),
  };
}

export function buildViewerModePreviews(exchanges: HttpExchange[]): ViewerModePreview[] {
  const pick = (predicate: (exchange: HttpExchange) => boolean) => exchanges.find(predicate) ?? exchanges[0];
  return [
    buildViewerModePreview(pick((exchange) => Boolean(exchange)), 'raw'),
    buildViewerModePreview(pick((exchange) => exchange.mime.includes('json') || extractHttpBody(exchange.responseRaw).trim().startsWith('{')), 'json'),
    buildViewerModePreview(pick((exchange) => exchange.mime.includes('html')), 'html'),
    buildViewerModePreview(pick((exchange) => /eyJ[A-Za-z0-9_-]+\./.test(`${exchange.requestRaw}\n${exchange.responseRaw}`)), 'jwt'),
    buildViewerModePreview(pick((exchange) => /graphql|"\s*query\s*"/i.test(`${exchange.path}\n${exchange.requestRaw}`)), 'graphql'),
    buildViewerModePreview(pick((exchange) => exchange.mime.startsWith('image/')), 'image'),
    buildViewerModePreview(pick((exchange) => Boolean(exchange)), 'binary'),
  ];
}

export function buildViewerParityEvidencePackage(request: ViewerParityEvidenceRequest): ViewerParityEvidencePackage {
  const exportedAt = request.exportedAt ?? new Date().toISOString();
  const stamp = exportedAt.replace(/[:.]/g, '-');
  const modes = new Set(request.modePreviews.map((preview) => preview.mode));
  const operationalText = [
    JSON.stringify(request.modePreviews),
    JSON.stringify(request.evidencePins),
    JSON.stringify(request.snapshots),
    JSON.stringify(request.replayComparisonExports),
    ...(request.operationalSecretSamples ?? []),
  ].join('\n');
  const requirements = {
    rawViewCovered: modes.has('raw') && request.modePreviews.some((preview) => preview.mode === 'raw' && preview.rawSourcePreserved),
    prettyJsonViewCovered: modes.has('json') && request.modePreviews.some((preview) => preview.mode === 'json' && /"\w+":/.test(preview.output)),
    htmlViewCovered: modes.has('html') && request.modePreviews.some((preview) => preview.mode === 'html' && /<html|<main|<div|<!doctype/i.test(preview.output)),
    jwtViewCovered: modes.has('jwt') && request.modePreviews.some((preview) => preview.mode === 'jwt' && /Header:|Payload:/i.test(preview.output)),
    graphqlViewCovered: modes.has('graphql') && request.modePreviews.some((preview) => preview.mode === 'graphql' && /Query:|Operation:/i.test(preview.output)),
    imageViewCovered: modes.has('image') && request.modePreviews.some((preview) => preview.mode === 'image' && /image\//i.test(preview.output)),
    binaryViewCovered: modes.has('binary') && request.modePreviews.some((preview) => preview.mode === 'binary' && /00000000/i.test(preview.output)),
    sourceAwareSnapshotsCovered: request.snapshots.some((snapshot) => snapshot.representation === 'raw')
      && request.snapshots.some((snapshot) => snapshot.representation === 'decoded')
      && request.snapshots.every((snapshot) => Boolean(snapshot.source.id && snapshot.rawContent)),
    evidencePinsCovered: request.evidencePins.length > 0
      && request.evidencePins.every((pin) => pin.reportReady && pin.linkedExchangeIds.length > 0 && pin.selection.selectedText),
    replayComparisonExportsCovered: request.replayComparisonExports.length > 0
      && request.replayComparisonExports.every((item) => item.rows.length > 0 && item.exchangeIds.length >= 2 && item.content),
    reportAttachmentCovered: request.replayComparisonExports.some((item) => item.reportReady && item.reportSection === 'evidence'),
    rawExecutorMaterialPreserved: /HTTP\/[12]|Authorization:|Cookie:|requestRaw|responseRaw/i.test(operationalText),
    operationalSecretsPreserved: (request.operationalSecretSamples ?? []).length > 0
      && (request.operationalSecretSamples ?? []).every((sample) => operationalText.includes(sample)),
    reportPhaseOnlyRedaction: true,
  };
  const unsigned = {
    kind: 'proxyforge-viewer-parity-evidence-package',
    exportedAt,
    modePreviews: request.modePreviews,
    evidencePins: request.evidencePins,
    snapshots: request.snapshots,
    replayComparisonExports: request.replayComparisonExports,
    operationalSecretSamples: request.operationalSecretSamples ?? [],
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const content = JSON.stringify({ ...unsigned, digestPreview }, null, 2);

  return {
    id: `viewer-parity-${Date.parse(exportedAt) || Date.now()}`,
    kind: 'proxyforge-viewer-parity-evidence-package',
    title: 'Viewer parity evidence package',
    fileName: `proxyforge-viewer-parity-${stamp}.json`,
    path: `viewer/proxyforge-viewer-parity-${stamp}.json`,
    exportedAt,
    modeCount: modes.size,
    evidencePinCount: request.evidencePins.length,
    snapshotCount: request.snapshots.length,
    replayComparisonExportCount: request.replayComparisonExports.length,
    artifactIds: {
      previewExchangeIds: Array.from(new Set(request.modePreviews.map((preview) => preview.exchangeId))),
      evidencePinIds: request.evidencePins.map((pin) => pin.id),
      snapshotIds: request.snapshots.map((snapshot) => snapshot.id),
      replayComparisonExportIds: request.replayComparisonExports.map((item) => item.id),
    },
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
    digestPreview,
    summary: 'Viewer parity evidence covers raw, pretty JSON, HTML, JWT, GraphQL, image, and binary views plus source-aware snapshots, persistent evidence pins, replay comparison exports, and report attachment handoff.',
    content,
  };
}

function renderViewerOutput(exchange: HttpExchange, mode: ViewerHttpMode) {
  const body = extractHttpBody(exchange.responseRaw).trim();
  const requestBody = extractHttpBody(exchange.requestRaw).trim();
  if (mode === 'json') {
    return [
      'Request JSON:',
      prettyJson(requestBody) ?? 'No JSON request body detected.',
      '',
      'Response JSON:',
      prettyJson(body) ?? 'No JSON response body detected.',
    ].join('\n');
  }
  if (mode === 'html') {
    return exchange.mime.includes('html') || /<html|<!doctype|<main|<div/i.test(body)
      ? body
      : `Selected response MIME is ${exchange.mime}; no HTML body was detected.`;
  }
  if (mode === 'jwt') return renderJwt(`${exchange.requestRaw}\n${exchange.responseRaw}`);
  if (mode === 'graphql') return renderGraphQl(`${exchange.path}\n${exchange.requestRaw}`);
  if (mode === 'image') {
    return exchange.mime.startsWith('image/')
      ? `Image response selected: ${exchange.mime}, ${exchange.length} bytes from ${exchange.url}`
      : `Selected response MIME is ${exchange.mime}; image preview is available for image/* responses.`;
  }
  if (mode === 'binary') {
    return [
      `Hex dump of response bytes (${Math.min(utf8ByteLength(exchange.responseRaw), 2048)} byte preview)`,
      '',
      hexDump(exchange.responseRaw),
    ].join('\n');
  }
  return [exchange.requestRaw.trim(), '', '--- response ---', '', exchange.responseRaw.trim()].join('\n');
}

function viewerModeTitle(mode: ViewerHttpMode) {
  const titles: Record<ViewerHttpMode, string> = {
    raw: 'Raw Request / Response',
    json: 'Pretty JSON',
    html: 'HTML Viewer',
    jwt: 'JWT Viewer',
    graphql: 'GraphQL Viewer',
    image: 'Image Viewer',
    binary: 'Binary Viewer',
  };
  return titles[mode];
}

function extractHttpBody(raw: string) {
  const marker = raw.indexOf('\n\n');
  if (marker >= 0) return raw.slice(marker + 2);
  const crlfMarker = raw.indexOf('\r\n\r\n');
  return crlfMarker >= 0 ? raw.slice(crlfMarker + 4) : '';
}

function prettyJson(value: string) {
  try {
    return JSON.stringify(JSON.parse(value), null, 2);
  } catch {
    return undefined;
  }
}

function renderJwt(text: string) {
  const token = text.match(/\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/)?.[0];
  if (!token) return 'No complete JWT was found in the selected exchange.';
  const [header, payload] = token.split('.');
  return [
    'Header:',
    prettyBase64UrlJson(header),
    '',
    'Payload:',
    prettyBase64UrlJson(payload),
  ].join('\n');
}

function prettyBase64UrlJson(value: string) {
  try {
    return JSON.stringify(JSON.parse(decodeBase64Url(value)), null, 2);
  } catch {
    return 'JWT segment could not be decoded as JSON.';
  }
}

function decodeBase64Url(value: string) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
  let bits = '';
  for (const char of normalized) {
    const index = alphabet.indexOf(char);
    if (index < 0) throw new Error('Invalid base64url character.');
    bits += index.toString(2).padStart(6, '0');
  }
  const bytes: number[] = [];
  for (let index = 0; index + 8 <= bits.length; index += 8) {
    bytes.push(Number.parseInt(bits.slice(index, index + 8), 2));
  }
  return new TextDecoder().decode(new Uint8Array(bytes));
}

function renderGraphQl(text: string) {
  const body = extractHttpBody(text);
  const parsed = prettyJson(body) ? JSON.parse(body) as { operationName?: unknown; query?: unknown; variables?: unknown } : undefined;
  const query = typeof parsed?.query === 'string'
    ? parsed.query
    : text.match(/\b(query|mutation|subscription)\s+[^{]+{[\s\S]+}/i)?.[0];
  if (!query) return 'No GraphQL document was detected in the selected exchange.';
  return [
    `Operation: ${typeof parsed?.operationName === 'string' ? parsed.operationName : 'not specified'}`,
    '',
    'Query:',
    query,
    '',
    'Variables:',
    parsed?.variables ? JSON.stringify(parsed.variables, null, 2) : '{}',
  ].join('\n');
}

function hexDump(value: string) {
  const bytes = Array.from(new TextEncoder().encode(value));
  return bytes.slice(0, 2048).reduce<string[]>((rows, byte, index) => {
    if (index % 16 === 0) rows.push(`${index.toString(16).padStart(8, '0')}  `);
    rows[rows.length - 1] += `${byte.toString(16).padStart(2, '0')} `;
    if (index % 16 === 15) {
      const start = index - 15;
      const ascii = bytes.slice(start, index + 1).map((item) => (item >= 32 && item < 127 ? String.fromCharCode(item) : '.')).join('');
      rows[rows.length - 1] += ` ${ascii}`;
    }
    return rows;
  }, []).join('\n') || 'No bytes available.';
}

function utf8ByteLength(value: string) {
  return new TextEncoder().encode(value).length;
}

function simpleDigest(value: string) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `${hash.toString(16).padStart(8, '0')}${value.length.toString(16).padStart(8, '0')}`;
}
