import type {
  HttpExchange,
  Issue,
  MatchReplaceRule,
  ProxyAnnotationLane,
  ProxyCapturePresetHandoff,
  ProxyBrowserProxyChainDiversityPackage,
  ProxyBrowserProxyChainProfile,
  ProxyCrossToolHandoffPackage,
  ProxyCrossToolHandoffDestination,
  ProxyEdgeProfilePackage,
  ProxyReportHandoffAttachment,
  ProxyRepeaterHandoffRequest,
  ProxyScannerHandoffCandidate,
  ProxyHistoryFilterSetPackage,
  ProxyHistoryEvidenceAttachment,
  ProxyHistoryFilter,
  ProxyHistoryMetadata,
  ProxyHistorySavedFilterResult,
  ProxyHistoryViewModel,
  ProxyHttp2ExchangeMetadata,
  ProxyHttp2FidelityExchange,
  ProxyHttp2FidelityReport,
  ProxyHttp2MultiplexingReport,
  ProxyHttp2ConnectionSummary,
  ProxyInterceptRuleReview,
  ProxyInterceptRuleReviewRow,
  ProxyTrafficComparisonDelta,
  ProxyTrafficComparisonPackage,
  Severity,
} from './types';

export interface ProxyHistoryEngineRequest {
  exchanges: HttpExchange[];
  rules?: MatchReplaceRule[];
  filters?: Partial<ProxyHistoryFilter>;
  selectedExchangeIds?: string[];
  baseline?: {
    name?: string;
    exchangeIds?: string[];
    exchanges?: HttpExchange[];
    capturedAt?: string;
  };
  candidate?: {
    name?: string;
    exchangeIds?: string[];
    exchanges?: HttpExchange[];
    capturedAt?: string;
  };
  viewModel?: ProxyHistoryViewModel;
  ruleReview?: ProxyInterceptRuleReview;
  capturePreset?: ProxyCapturePresetHandoff;
  comparisonPackage?: ProxyTrafficComparisonPackage;
  http2FidelityReport?: ProxyHttp2FidelityReport;
  http2MultiplexingReport?: ProxyHttp2MultiplexingReport;
  filterSetPackage?: ProxyHistoryFilterSetPackage;
  crossToolHandoffPackage?: ProxyCrossToolHandoffPackage;
  savedFilters?: Array<{
    id?: string;
    label?: string;
    filters?: Partial<ProxyHistoryFilter>;
  }>;
  issueId?: string;
  now?: string;
}

export interface ProxyLinkedEvidencePackage {
  id?: string;
  kind?: string;
  content?: string;
  reportReady?: boolean;
  status?: string;
  requirements?: Record<string, boolean>;
  summary?: string;
}

export interface ProxyEdgeProfileRequest extends ProxyHistoryEngineRequest {
  historyEvidenceAttachment?: ProxyHistoryEvidenceAttachment;
  linkedPackages?: ProxyLinkedEvidencePackage[];
  operationalSecretSamples?: string[];
  minHosts?: number;
  minRoutes?: number;
  minPackageKinds?: number;
}

export interface ProxyBrowserProxyChainDiversityRequest {
  edgeProfilePackage: ProxyEdgeProfilePackage;
  profiles: ProxyBrowserProxyChainProfile[];
  operationalSecretSamples?: string[];
  generatedAt?: string;
}

const severityRank: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

function simpleDigest(value: string) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `${hash.toString(16).padStart(8, '0')}${value.length.toString(16).padStart(8, '0')}`;
}

function normalizeProxyHistoryFilters(filters?: Partial<ProxyHistoryFilter>): ProxyHistoryFilter {
  return {
    query: filters?.query?.trim() ?? '',
    method: filters?.method?.trim() || 'all',
    source: filters?.source ?? 'all',
    status: filters?.status?.trim() || 'all',
    risk: filters?.risk ?? 'all',
    mime: filters?.mime?.trim() ?? '',
    tag: filters?.tag?.trim() ?? '',
  };
}

function rawFirstLine(raw: string) {
  return raw.split(/\r?\n/, 1)[0]?.trim() || '';
}

function rawHeaderBlock(raw: string) {
  const headerBlock = raw.split(/\r?\n\r?\n/, 1)[0] ?? '';
  return headerBlock.split(/\r?\n/).filter(Boolean);
}

function isPseudoHeaderLine(line: string) {
  return /^:[A-Za-z0-9_-]+\s*:/.test(line);
}

function rawHeaderLines(raw: string) {
  const lines = rawHeaderBlock(raw);
  const startsWithPseudoHeaders = lines.some(isPseudoHeaderLine);
  return lines.slice(startsWithPseudoHeaders ? 0 : 1).filter((line) => line.includes(':') && !isPseudoHeaderLine(line));
}

function rawBody(raw: string) {
  return raw.split(/\r?\n\r?\n/).slice(1).join('\n\n');
}

function headerName(line: string) {
  if (isPseudoHeaderLine(line)) {
    const end = line.indexOf(':', 1);
    return end > 0 ? line.slice(0, end).toLowerCase() : line.toLowerCase();
  }
  const index = line.indexOf(':');
  return index > 0 ? line.slice(0, index).trim().toLowerCase() : '';
}

function parsePseudoHeaders(raw: string) {
  const entries: Record<string, string> = {};
  const order: string[] = [];
  for (const line of rawHeaderBlock(raw)) {
    if (!isPseudoHeaderLine(line)) continue;
    const end = line.indexOf(':', 1);
    if (end <= 0) continue;
    const name = line.slice(0, end).toLowerCase();
    const value = line.slice(end + 1).trim();
    entries[name] = value;
    order.push(name);
  }
  return { entries, order };
}

function parseRegularHeaderOrder(raw: string) {
  return rawHeaderLines(raw).map(headerName).filter(Boolean);
}

function parseTrailerNames(raw: string) {
  const blocks = raw.split(/\r?\n\r?\n/).slice(2);
  const trailerNames: string[] = [];
  for (const block of blocks) {
    for (const line of block.split(/\r?\n/)) {
      const normalized = line.trim();
      if (!normalized || /^[-= ]*trailers?[-= ]*:?\s*$/i.test(normalized)) continue;
      const name = headerName(normalized);
      if (name) trailerNames.push(name);
    }
  }
  return Array.from(new Set(trailerNames));
}

function parseStreamId(exchange: HttpExchange) {
  const haystack = `${exchange.notes} ${exchange.tags.join(' ')}\n${exchange.requestRaw}\n${exchange.responseRaw}`;
  const match = /(?:stream(?:-id)?|h2-stream)\s*[:=#-]?\s*(\d+)/i.exec(haystack);
  return match ? Number(match[1]) : undefined;
}

function parseAlpn(exchange: HttpExchange): ProxyHttp2ExchangeMetadata['alpn'] {
  const haystack = `${exchange.notes} ${exchange.tags.join(' ')}\n${exchange.requestRaw}\n${exchange.responseRaw}`.toLowerCase();
  if (/\balpn[:=]h2\b|\bh2\b|http\/2/.test(haystack)) return 'h2';
  if (/\bh2c\b|alpn[:=]h2c/.test(haystack)) return 'h2c';
  return 'unknown';
}

function httpProtocol(exchange: HttpExchange): ProxyHistoryMetadata['protocol'] {
  const raw = `${rawFirstLine(exchange.requestRaw)} ${rawFirstLine(exchange.responseRaw)}`.toUpperCase();
  if (exchange.method === 'CONNECT') return 'CONNECT';
  if (raw.includes('HTTP/2') || Object.keys(parsePseudoHeaders(exchange.requestRaw).entries).length || Object.keys(parsePseudoHeaders(exchange.responseRaw).entries).length) return 'HTTP/2';
  if (raw.includes('HTTP/1.1') || raw.includes('HTTP/1.0')) return 'HTTP/1.1';
  return 'unknown';
}

function buildHttp2ExchangeMetadata(exchange: HttpExchange, protocol = httpProtocol(exchange)): ProxyHttp2ExchangeMetadata | undefined {
  if (protocol !== 'HTTP/2') return undefined;
  const requestPseudo = parsePseudoHeaders(exchange.requestRaw);
  const responsePseudo = parsePseudoHeaders(exchange.responseRaw);
  const requestHeaderOrder = parseRegularHeaderOrder(exchange.requestRaw);
  const responseHeaderOrder = parseRegularHeaderOrder(exchange.responseRaw);
  const requestTrailerNames = parseTrailerNames(exchange.requestRaw);
  const responseTrailerNames = parseTrailerNames(exchange.responseRaw);
  const streamId = parseStreamId(exchange);
  const responseStatus = Number(responsePseudo.entries[':status'] ?? exchange.status);
  const fidelityChecks: string[] = [
    `request-pseudo:${Object.keys(requestPseudo.entries).join(',') || 'none'}`,
    `response-pseudo:${Object.keys(responsePseudo.entries).join(',') || (rawFirstLine(exchange.responseRaw).includes('HTTP/2') ? ':status-from-start-line' : 'none')}`,
    `headers:${requestHeaderOrder.length}/${responseHeaderOrder.length}`,
    `trailers:${requestTrailerNames.length}/${responseTrailerNames.length}`,
    `stream:${streamId ?? 'unknown'}`,
    `alpn:${parseAlpn(exchange)}`,
  ];
  const warnings: string[] = [];
  if (!requestPseudo.entries[':method'] && !/^.+\s+.+\s+HTTP\/2/i.test(rawFirstLine(exchange.requestRaw))) {
    warnings.push('HTTP/2 request is missing :method pseudo-header and an HTTP/2 request line fallback.');
  }
  if (!requestPseudo.entries[':authority'] && !requestHeaderOrder.includes('host')) {
    warnings.push('HTTP/2 request is missing :authority and Host fallback metadata.');
  }
  if (!requestPseudo.entries[':path'] && !exchange.path) {
    warnings.push('HTTP/2 request is missing :path metadata.');
  }
  if (!responsePseudo.entries[':status'] && !/^HTTP\/2\s+\d{3}/i.test(rawFirstLine(exchange.responseRaw))) {
    warnings.push('HTTP/2 response is missing :status and HTTP/2 response-line fallback.');
  }
  if (!streamId) warnings.push('HTTP/2 stream id was not captured.');
  if (parseAlpn(exchange) === 'unknown') warnings.push('HTTP/2 ALPN or h2c transport hint was not captured.');

  return {
    detected: true,
    alpn: parseAlpn(exchange),
    streamId,
    requestPseudoHeaders: requestPseudo.entries,
    responsePseudoHeaders: responsePseudo.entries,
    requestHeaderOrder,
    responseHeaderOrder,
    requestAuthority: requestPseudo.entries[':authority'] ?? exchange.host,
    requestScheme: requestPseudo.entries[':scheme'] ?? (exchange.url.startsWith('https://') ? 'https' : exchange.url.startsWith('http://') ? 'http' : undefined),
    requestPath: requestPseudo.entries[':path'] ?? exchange.path,
    responseStatus: Number.isFinite(responseStatus) ? responseStatus : undefined,
    requestTrailerNames,
    responseTrailerNames,
    fidelityChecks,
    warnings,
  };
}

function hasParameters(exchange: HttpExchange) {
  if (exchange.path.includes('?') || exchange.url.includes('?')) return true;
  if (/content-type:\s*application\/x-www-form-urlencoded/i.test(exchange.requestRaw)) return true;
  const body = rawBody(exchange.requestRaw).trim();
  if (!body) return false;
  return /"[^"]+"\s*:|[A-Za-z0-9_.-]+=/i.test(body);
}

function durationBucket(timing: number): ProxyHistoryMetadata['durationBucket'] {
  if (timing >= 2000 || timing === 0) return 'timeout';
  if (timing >= 500) return 'slow';
  if (timing <= 100) return 'fast';
  return 'normal';
}

function isModified(exchange: HttpExchange) {
  const marker = `${exchange.notes} ${exchange.tags.join(' ')}`.toLowerCase();
  return /modified|edited|rewritten|match-replace|intercept|replayed/.test(marker);
}

function annotationSummary(exchange: HttpExchange) {
  const tags = exchange.tags.length ? `tags:${exchange.tags.join(',')}` : 'no tags';
  return `${exchange.notes || 'No notes'} (${tags})`;
}

function exchangeToMetadata(exchange: HttpExchange): ProxyHistoryMetadata {
  const requestHeaderCount = rawHeaderLines(exchange.requestRaw).length;
  const responseHeaderCount = rawHeaderLines(exchange.responseRaw).length;
  const protocol = httpProtocol(exchange);
  const http2 = buildHttp2ExchangeMetadata(exchange, protocol);
  return {
    id: `proxy-meta-${exchange.id}`,
    exchangeId: exchange.id,
    method: exchange.method,
    host: exchange.host,
    path: exchange.path,
    status: exchange.status,
    source: exchange.source,
    risk: exchange.risk,
    requestLine: rawFirstLine(exchange.requestRaw) || `${exchange.method} ${exchange.path}`,
    responseLine: rawFirstLine(exchange.responseRaw) || `HTTP ${exchange.status}`,
    protocol,
    tls: exchange.url.startsWith('https://') || exchange.method === 'CONNECT',
    hasParameters: hasParameters(exchange),
    requestHeaderCount,
    responseHeaderCount,
    requestBytes: exchange.requestRaw.length,
    responseBytes: exchange.responseRaw.length,
    durationBucket: durationBucket(exchange.timing),
    statusClass: exchange.status ? `${Math.floor(exchange.status / 100)}xx` : 'none',
    annotationSummary: annotationSummary(exchange),
    fingerprint: simpleDigest(`${exchange.method} ${exchange.host}${exchange.path} ${exchange.status} ${exchange.mime} ${exchange.responseRaw.slice(0, 200)}`),
    scannerReady: severityRank[exchange.risk] >= severityRank.medium || exchange.status >= 400 || hasParameters(exchange),
    repeaterReady: exchange.method !== 'CONNECT' && exchange.requestRaw.trim().length > 0,
    modified: isModified(exchange),
    http2,
  };
}

function exchangeMatchesQuery(exchange: HttpExchange, query: string) {
  if (!query) return true;
  const tokens = query.toLowerCase().split(/\s+/).filter(Boolean);
  const haystack = [
    exchange.method,
    exchange.host,
    exchange.path,
    exchange.url,
    exchange.status.toString(),
    exchange.mime,
    exchange.risk,
    exchange.source,
    exchange.notes,
    exchange.tags.join(' '),
    exchange.requestRaw,
    exchange.responseRaw,
  ].join(' ').toLowerCase();
  return tokens.every((token) => haystack.includes(token));
}

function exchangeMatchesStatus(exchange: HttpExchange, status: string, metadata: ProxyHistoryMetadata) {
  if (!status || status === 'all') return true;
  if (status === 'errors') return exchange.status >= 400;
  if (status === 'has-params') return metadata.hasParameters;
  if (status === 'http2') return metadata.protocol === 'HTTP/2';
  if (status === 'modified') return metadata.modified;
  if (/^[1-5]xx$/.test(status)) return Math.floor(exchange.status / 100) === Number(status[0]);
  if (/^\d{3}$/.test(status)) return exchange.status === Number(status);
  return true;
}

function filterExchanges(exchanges: HttpExchange[], filters: ProxyHistoryFilter) {
  return exchanges.filter((exchange) => {
    const metadata = exchangeToMetadata(exchange);
    if (filters.method !== 'all' && exchange.method.toUpperCase() !== String(filters.method).toUpperCase()) return false;
    if (filters.source !== 'all' && exchange.source !== filters.source) return false;
    if (filters.risk !== 'all' && exchange.risk !== filters.risk) return false;
    if (filters.mime && !exchange.mime.toLowerCase().includes(filters.mime.toLowerCase())) return false;
    if (filters.tag && !exchange.tags.some((tag) => tag.toLowerCase().includes(filters.tag.toLowerCase()))) return false;
    if (!exchangeMatchesStatus(exchange, filters.status, metadata)) return false;
    return exchangeMatchesQuery(exchange, filters.query);
  });
}

function incrementFacet(facet: Record<string, number>, key: string) {
  facet[key] = (facet[key] ?? 0) + 1;
}

function buildFacets(exchanges: HttpExchange[]) {
  const methodFacets: Record<string, number> = {};
  const sourceFacets: Record<string, number> = {};
  const statusFacets: Record<string, number> = {};
  const riskFacets: Record<string, number> = {};
  for (const exchange of exchanges) {
    incrementFacet(methodFacets, exchange.method);
    incrementFacet(sourceFacets, exchange.source);
    incrementFacet(statusFacets, exchange.status ? `${Math.floor(exchange.status / 100)}xx` : 'none');
    incrementFacet(riskFacets, exchange.risk);
  }
  return { methodFacets, sourceFacets, statusFacets, riskFacets };
}

function countStrings(values: string[]) {
  return values.reduce<Record<string, number>>((counts, value) => {
    const key = value || 'unknown';
    counts[key] = (counts[key] ?? 0) + 1;
    return counts;
  }, {});
}

function laneFromMatches(id: string, label: string, severity: Severity, exchanges: HttpExchange[], predicate: (exchange: HttpExchange) => boolean): ProxyAnnotationLane {
  const matched = exchanges.filter(predicate);
  return {
    id,
    label,
    severity,
    exchangeIds: matched.map((exchange) => exchange.id),
    count: matched.length,
    summary: `${label}: ${matched.length} exchange${matched.length === 1 ? '' : 's'} ready for annotation review.`,
  };
}

function buildAnnotationLanes(exchanges: HttpExchange[]): ProxyAnnotationLane[] {
  return [
    laneFromMatches('lane-notes', 'Notes', 'info', exchanges, (exchange) => Boolean(exchange.notes.trim())),
    laneFromMatches('lane-auth', 'Auth Tokens', 'medium', exchanges, (exchange) => /authorization:|cookie:|session=|token/i.test(`${exchange.requestRaw}\n${exchange.responseRaw}`)),
    laneFromMatches('lane-high-risk', 'High Risk', 'high', exchanges, (exchange) => severityRank[exchange.risk] >= severityRank.high || exchange.status >= 500),
    laneFromMatches('lane-replay', 'Replay Ready', 'low', exchanges, (exchange) => exchange.method !== 'CONNECT' && exchange.requestRaw.trim().length > 0),
    laneFromMatches('lane-scanner', 'Scanner Promotion', 'medium', exchanges, (exchange) => severityRank[exchange.risk] >= severityRank.medium || exchange.status >= 400 || hasParameters(exchange)),
    laneFromMatches('lane-modified', 'Modified Messages', 'low', exchanges, isModified),
  ];
}

export function buildProxyHistoryViewModel(request: ProxyHistoryEngineRequest): ProxyHistoryViewModel {
  const filters = normalizeProxyHistoryFilters(request.filters);
  const filtered = filterExchanges(request.exchanges, filters);
  const rows = filtered.map(exchangeToMetadata);
  const hostCount = new Set(filtered.map((exchange) => exchange.host)).size;
  const http2Count = rows.filter((row) => row.protocol === 'HTTP/2').length;
  const modifiedCount = rows.filter((row) => row.modified).length;
  return {
    id: `proxy-history-view-${simpleDigest(JSON.stringify(filters) + filtered.map((exchange) => exchange.id).join('|')).slice(0, 12)}`,
    title: 'Proxy advanced HTTP history',
    summary: `${filtered.length}/${request.exchanges.length} HTTP history item(s) across ${hostCount} host(s); ${http2Count} HTTP/2 message(s), ${modifiedCount} modified/intercepted message(s), and ${rows.filter((row) => row.scannerReady).length} Scanner-ready candidate(s).`,
    totalCount: request.exchanges.length,
    filteredCount: filtered.length,
    hostCount,
    http2Count,
    modifiedCount,
    filters,
    rows,
    annotationLanes: buildAnnotationLanes(filtered),
    ...buildFacets(filtered),
  };
}

function filterSummary(filters: ProxyHistoryFilter) {
  return [
    filters.query ? `query "${filters.query}"` : '',
    filters.method !== 'all' ? `method ${filters.method}` : '',
    filters.source !== 'all' ? `source ${filters.source}` : '',
    filters.status !== 'all' ? `status ${filters.status}` : '',
    filters.risk !== 'all' ? `risk ${filters.risk}` : '',
    filters.mime ? `mime ${filters.mime}` : '',
    filters.tag ? `tag ${filters.tag}` : '',
  ].filter(Boolean).join(', ') || 'all Proxy history';
}

function uniqueStrings(values: string[]) {
  return Array.from(new Set(values.filter(Boolean)));
}

function secretSignals(exchange: HttpExchange) {
  const raw = `${exchange.requestRaw}\n${exchange.responseRaw}`;
  const signals: string[] = [];
  if (/^authorization\s*:/im.test(raw)) signals.push('authorization-header');
  if (/^cookie\s*:/im.test(raw)) signals.push('cookie-header');
  if (/^x-api-key\s*:/im.test(raw)) signals.push('x-api-key-header');
  if (/(?:bearer|session|token|secret|api[-_]?key)\s*[:= ]+[A-Za-z0-9._~+/=-]{6,}/i.test(raw)) signals.push('secret-like-material');
  return uniqueStrings(signals);
}

function proxyStatusClass(status?: number) {
  if (!status || status < 100) return 'unknown';
  return `${Math.floor(status / 100)}xx`;
}

function proxyLinkedPackageId(item: ProxyLinkedEvidencePackage, index: number) {
  return item.id ?? `proxy-linked-package-${index + 1}`;
}

function proxyLinkedPackageKind(item: ProxyLinkedEvidencePackage) {
  return item.kind ?? 'proxyforge-linked-evidence-package';
}

function proxyLinkedPackageReady(item: ProxyLinkedEvidencePackage) {
  const requirementValues = item.requirements ? Object.values(item.requirements) : [];
  return item.reportReady !== false
    && !/fail|failed|blocked|stale|mismatch/i.test(item.status ?? '')
    && requirementValues.every(Boolean);
}

function proxyLinkedPackageText(item: ProxyLinkedEvidencePackage) {
  return [
    item.id,
    item.kind,
    item.status,
    item.summary,
    item.content,
    item.requirements ? JSON.stringify(item.requirements) : '',
  ].filter(Boolean).join('\n');
}

function defaultSavedFilters(request: ProxyHistoryEngineRequest) {
  const normalized = normalizeProxyHistoryFilters(request.filters);
  const filters: NonNullable<ProxyHistoryEngineRequest['savedFilters']> = [
    { id: 'operator-visible-filter', label: 'Operator visible filter', filters: normalized },
    { id: 'auth-secret-review', label: 'Authentication and secret review', filters: { query: 'authorization cookie token', status: 'all' } },
    { id: 'scanner-ready-errors', label: 'Scanner-ready errors and parameters', filters: { status: 'errors', risk: 'all' } },
    { id: 'http2-fidelity', label: 'HTTP/2 fidelity review', filters: { status: 'http2' } },
    { id: 'modified-message-review', label: 'Modified message review', filters: { status: 'modified' } },
  ];
  const seen = new Set<string>();
  return filters.filter((preset) => {
    const key = JSON.stringify(normalizeProxyHistoryFilters(preset.filters));
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function intersection(left: string[], right: string[]) {
  const rightSet = new Set(right);
  return left.filter((value) => rightSet.has(value));
}

function buildSavedFilterResult(
  request: ProxyHistoryEngineRequest,
  preset: NonNullable<ProxyHistoryEngineRequest['savedFilters']>[number],
): ProxyHistorySavedFilterResult {
  const filters = normalizeProxyHistoryFilters(preset.filters);
  const view = buildProxyHistoryViewModel({ ...request, filters, selectedExchangeIds: [] });
  const matched = view.rows
    .map((row) => request.exchanges.find((exchange) => exchange.id === row.exchangeId))
    .filter((exchange): exchange is HttpExchange => Boolean(exchange));
  return {
    id: preset.id ?? `proxy-history-filter-${simpleDigest(JSON.stringify(filters)).slice(0, 10)}`,
    label: preset.label ?? filterSummary(filters),
    filters,
    filterSummary: filterSummary(filters),
    matchedExchangeIds: matched.map((exchange) => exchange.id),
    matchedCount: matched.length,
    unmatchedCount: Math.max(0, request.exchanges.length - matched.length),
    facets: {
      methods: view.methodFacets,
      sources: view.sourceFacets,
      statuses: view.statusFacets,
      risks: view.riskFacets,
    },
    annotationLaneCounts: Object.fromEntries(view.annotationLanes.map((lane) => [lane.id, lane.count])),
    sampleExchanges: matched.slice(0, 5).map((exchange) => ({
      exchangeId: exchange.id,
      method: exchange.method,
      host: exchange.host,
      path: exchange.path,
      status: exchange.status,
      risk: exchange.risk,
      requestRaw: exchange.requestRaw,
      responseRaw: exchange.responseRaw,
      secretSignals: secretSignals(exchange),
    })),
  };
}

function isProxyHistoryFilterSetPackage(value: unknown): value is ProxyHistoryFilterSetPackage {
  if (!value || typeof value !== 'object') return false;
  const candidate = value as Partial<ProxyHistoryFilterSetPackage>;
  return candidate.kind === 'proxyforge-proxy-history-filter-set-package'
    && Array.isArray(candidate.savedFilters)
    && typeof candidate.content === 'string';
}

export function buildProxyHistoryFilterSetPackage(request: ProxyHistoryEngineRequest): ProxyHistoryFilterSetPackage {
  const now = request.now ?? new Date().toISOString();
  const savedFilters = (request.savedFilters?.length ? request.savedFilters : defaultSavedFilters(request))
    .map((preset) => buildSavedFilterResult(request, preset));
  const allExchangeIds = request.exchanges.map((exchange) => exchange.id);
  const unionMatchedExchangeIds = uniqueStrings(savedFilters.flatMap((result) => result.matchedExchangeIds));
  const intersectionMatchedExchangeIds = savedFilters.length
    ? savedFilters.slice(1).reduce((current, result) => intersection(current, result.matchedExchangeIds), savedFilters[0].matchedExchangeIds)
    : [];
  const unionSet = new Set(unionMatchedExchangeIds);
  const unmatchedExchangeIds = allExchangeIds.filter((id) => !unionSet.has(id));
  const predicateCoverage = uniqueStrings(savedFilters.flatMap((result) => [
    result.filters.query ? 'query-token-search' : '',
    result.filters.method !== 'all' ? 'method-filter' : '',
    result.filters.source !== 'all' ? 'source-filter' : '',
    result.filters.status !== 'all' ? `status-filter:${result.filters.status}` : '',
    result.filters.risk !== 'all' ? 'risk-filter' : '',
    result.filters.mime ? 'mime-filter' : '',
    result.filters.tag ? 'tag-filter' : '',
  ]));
  const secretSignalCount = savedFilters.reduce(
    (total, result) => total + result.sampleExchanges.reduce((subtotal, sample) => subtotal + sample.secretSignals.length, 0),
    0,
  );
  const requirements = {
    savedPredicatesRoundTrip: savedFilters.every((result) => result.filterSummary.length > 0 && Object.keys(result.filters).length >= 7),
    advancedStatusPredicatesCovered: predicateCoverage.some((item) => /status-filter:(errors|has-params|http2|modified|[1-5]xx|\d{3})/.test(item)),
    annotationLanesCovered: savedFilters.some((result) => Object.values(result.annotationLaneCounts).some((count) => count > 0)),
    rawSamplesPreserved: savedFilters.some((result) => result.sampleExchanges.some((sample) => sample.requestRaw.trim() && sample.responseRaw.trim())),
    operationalSecretsPreserved: secretSignalCount > 0,
    reportPhaseOnlyRedaction: true,
  };
  const stamp = now.replace(/[:.]/g, '-');
  const content = JSON.stringify({
    kind: 'proxyforge-proxy-history-filter-set-package',
    createdAt: now,
    reportReady: true,
    totalExchangeCount: request.exchanges.length,
    savedFilterCount: savedFilters.length,
    unionMatchedExchangeIds,
    intersectionMatchedExchangeIds,
    unmatchedExchangeIds,
    predicateCoverage,
    secretSignalCount,
    savedFilters,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    redactionBoundary: 'Operational filter packages preserve full raw traffic and secrets. Redaction is applied only by report/submission exports.',
  }, null, 2);
  return {
    id: `proxy-history-filter-set-${simpleDigest(content).slice(0, 12)}`,
    kind: 'proxyforge-proxy-history-filter-set-package',
    title: 'Proxy history advanced filter set package',
    fileName: `proxyforge-proxy-history-filter-set-${stamp}.json`,
    path: `proxy/proxyforge-proxy-history-filter-set-${stamp}.json`,
    createdAt: now,
    totalExchangeCount: request.exchanges.length,
    savedFilterCount: savedFilters.length,
    unionMatchedExchangeIds,
    intersectionMatchedExchangeIds,
    unmatchedExchangeIds,
    predicateCoverage,
    secretSignalCount,
    savedFilters,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportReady: true,
    summary: `Proxy history filter set preserves ${savedFilters.length} saved predicate(s), ${unionMatchedExchangeIds.length}/${request.exchanges.length} matched exchange(s), ${predicateCoverage.length} predicate type(s), ${secretSignalCount} operational secret signal(s), and raw samples until report export.`,
    content,
  };
}

function buildHttp2FidelityExchange(exchange: HttpExchange): ProxyHttp2FidelityExchange | null {
  const metadata = exchangeToMetadata(exchange);
  if (!metadata.http2) return null;
  const requestPseudoCount = Object.keys(metadata.http2.requestPseudoHeaders).length;
  const responsePseudoCount = Object.keys(metadata.http2.responsePseudoHeaders).length;
  const trailerCount = metadata.http2.requestTrailerNames.length + metadata.http2.responseTrailerNames.length;
  return {
    exchangeId: exchange.id,
    method: exchange.method,
    host: exchange.host,
    path: exchange.path,
    status: exchange.status,
    protocol: metadata.protocol,
    alpn: metadata.http2.alpn,
    streamId: metadata.http2.streamId,
    requestPseudoHeaders: metadata.http2.requestPseudoHeaders,
    responsePseudoHeaders: metadata.http2.responsePseudoHeaders,
    requestTrailerNames: metadata.http2.requestTrailerNames,
    responseTrailerNames: metadata.http2.responseTrailerNames,
    fidelityChecks: metadata.http2.fidelityChecks,
    warnings: metadata.http2.warnings,
    summary: `${exchange.method} ${exchange.host}${exchange.path} captured as HTTP/2 with ${requestPseudoCount}/${responsePseudoCount} pseudo-header group(s), ${trailerCount} trailer header(s), ALPN ${metadata.http2.alpn}, and stream ${metadata.http2.streamId ?? 'unknown'}.`,
  };
}

export function buildProxyHttp2FidelityReport(request: ProxyHistoryEngineRequest): ProxyHttp2FidelityReport {
  const now = request.now ?? new Date().toISOString();
  const exchanges = selectedOrFilteredExchanges(request);
  const http2Rows = exchanges
    .map(buildHttp2FidelityExchange)
    .filter((item): item is ProxyHttp2FidelityExchange => Boolean(item));
  const pseudoHeaderExchangeCount = http2Rows.filter((row) => Object.keys(row.requestPseudoHeaders).length || Object.keys(row.responsePseudoHeaders).length).length;
  const trailerExchangeCount = http2Rows.filter((row) => row.requestTrailerNames.length || row.responseTrailerNames.length).length;
  const warningCount = http2Rows.reduce((total, row) => total + row.warnings.length, 0);
  const stamp = now.replace(/[:.]/g, '-');
  const content = JSON.stringify({
    kind: 'proxyforge-proxy-http2-fidelity-report',
    createdAt: now,
    reportReady: true,
    exchangeCount: exchanges.length,
    http2ExchangeCount: http2Rows.length,
    pseudoHeaderExchangeCount,
    trailerExchangeCount,
    warningCount,
    exchanges: http2Rows,
    guidance: [
      'Prefer pseudo-header metadata from real HTTP/2 captures over HTTP/1-style fallback lines.',
      'Use stream id and ALPN hints to distinguish multiplexed h2, cleartext h2c, and converted proxy traffic.',
      'Review warnings before using HTTP/2 traffic for Scanner, Repeater, or report proof.',
    ],
  }, null, 2);
  return {
    id: `proxy-http2-fidelity-${simpleDigest(content).slice(0, 12)}`,
    title: 'Proxy HTTP/2 fidelity report',
    fileName: `proxyforge-proxy-http2-fidelity-${stamp}.json`,
    path: `proxy/proxyforge-proxy-http2-fidelity-${stamp}.json`,
    createdAt: now,
    exchangeCount: exchanges.length,
    http2ExchangeCount: http2Rows.length,
    pseudoHeaderExchangeCount,
    trailerExchangeCount,
    warningCount,
    exchanges: http2Rows,
    reportReady: true,
    summary: `${http2Rows.length}/${exchanges.length} selected exchange(s) are HTTP/2-aware; ${pseudoHeaderExchangeCount} preserve pseudo-header metadata, ${trailerExchangeCount} preserve trailers, and ${warningCount} warning(s) need review.`,
    content,
  };
}

export function buildProxyHttp2MultiplexingReport(request: ProxyHistoryEngineRequest): ProxyHttp2MultiplexingReport {
  const now = request.now ?? new Date().toISOString();
  const exchanges = selectedOrFilteredExchanges(request);
  const http2Rows = exchanges
    .map((exchange) => {
      const metadata = exchangeToMetadata(exchange);
      return metadata.http2 ? { exchange, metadata: metadata.http2 } : null;
    })
    .filter((item): item is { exchange: HttpExchange; metadata: ProxyHttp2ExchangeMetadata } => Boolean(item));
  const grouped = new Map<string, Array<{ exchange: HttpExchange; metadata: ProxyHttp2ExchangeMetadata }>>();
  for (const row of http2Rows) {
    const authority = row.metadata.requestAuthority ?? row.exchange.host;
    const scheme = row.metadata.requestScheme ?? (row.exchange.url.startsWith('http://') ? 'http' : row.exchange.url.startsWith('https://') ? 'https' : undefined);
    const key = `${scheme ?? 'unknown'}://${authority}|${row.metadata.alpn}`;
    grouped.set(key, [...(grouped.get(key) ?? []), row]);
  }
  const connectionSummaries: ProxyHttp2ConnectionSummary[] = Array.from(grouped.entries())
    .map(([key, rows]) => {
      const first = rows[0];
      const streamIds = rows.flatMap((row) => row.metadata.streamId === undefined ? [] : [row.metadata.streamId]);
      const streamIdCounts = countStrings(streamIds.map(String));
      const reusedStreamIds = Object.entries(streamIdCounts)
        .filter(([, count]) => count > 1)
        .map(([streamId]) => Number(streamId))
        .filter(Number.isFinite);
      const headerOrderVariants = uniqueStrings(rows.map((row) => [
        row.metadata.requestHeaderOrder.join(',') || '(request headers absent)',
        row.metadata.responseHeaderOrder.join(',') || '(response headers absent)',
      ].join(' -> ')));
      const trailerExchangeCount = rows.filter((row) => row.metadata.requestTrailerNames.length || row.metadata.responseTrailerNames.length).length;
      const warningCount = rows.reduce((total, row) => total + row.metadata.warnings.length, 0);
      const multiplexed = rows.length > 1 && streamIds.length > 1 && new Set(streamIds).size > 1;
      const authority = first.metadata.requestAuthority ?? first.exchange.host;
      const scheme = first.metadata.requestScheme ?? (first.exchange.url.startsWith('http://') ? 'http' : first.exchange.url.startsWith('https://') ? 'https' : undefined);
      const statusCounts = countStrings(rows.map((row) => String(row.metadata.responseStatus ?? row.exchange.status ?? 'unknown')));
      return {
        id: `proxy-http2-connection-${simpleDigest(key).slice(0, 10)}`,
        authority,
        scheme,
        alpn: first.metadata.alpn,
        exchangeIds: rows.map((row) => row.exchange.id),
        streamIds: uniqueStrings(streamIds.map(String)).map(Number).filter(Number.isFinite).sort((left, right) => left - right),
        reusedStreamIds,
        methodCounts: countStrings(rows.map((row) => row.metadata.requestPseudoHeaders[':method'] ?? row.exchange.method)),
        statusCounts,
        headerOrderVariants,
        trailerExchangeCount,
        warningCount,
        multiplexed,
        summary: `${authority} ${first.metadata.alpn} groups ${rows.length} HTTP/2 exchange(s), ${streamIds.length} stream id observation(s), ${trailerExchangeCount} trailer-bearing exchange(s), and ${warningCount} warning(s).`,
      };
    })
    .sort((left, right) => Number(right.multiplexed) - Number(left.multiplexed) || right.exchangeIds.length - left.exchangeIds.length || left.authority.localeCompare(right.authority));
  const http2ExchangeCount = http2Rows.length;
  const streamIdObservationCount = http2Rows.filter((row) => row.metadata.streamId !== undefined).length;
  const streamIdCoverage = http2ExchangeCount ? Number((streamIdObservationCount / http2ExchangeCount).toFixed(4)) : 0;
  const h2cExchangeCount = http2Rows.filter((row) => row.metadata.alpn === 'h2c').length;
  const warningCount = connectionSummaries.reduce((total, connection) => total + connection.warningCount, 0);
  const requirements = {
    pseudoHeaderFidelity: http2Rows.some((row) => Object.keys(row.metadata.requestPseudoHeaders).length > 0 || Object.keys(row.metadata.responsePseudoHeaders).length > 0),
    streamIdCoverage: streamIdCoverage >= 0.75,
    multiplexedConnectionGrouping: connectionSummaries.some((connection) => connection.multiplexed),
    h2cOrAlpnCaptured: http2Rows.some((row) => row.metadata.alpn === 'h2' || row.metadata.alpn === 'h2c'),
    trailerMetadataPreserved: http2Rows.some((row) => row.metadata.requestTrailerNames.length || row.metadata.responseTrailerNames.length),
    warningReviewReady: warningCount >= 0,
  };
  const stamp = now.replace(/[:.]/g, '-');
  const content = JSON.stringify({
    kind: 'proxyforge-proxy-http2-multiplexing-report',
    createdAt: now,
    reportReady: true,
    exchangeCount: exchanges.length,
    http2ExchangeCount,
    connectionCount: connectionSummaries.length,
    multiplexedConnectionCount: connectionSummaries.filter((connection) => connection.multiplexed).length,
    h2cExchangeCount,
    streamIdCoverage,
    connectionSummaries,
    requirements,
    guidance: [
      'Group HTTP/2 captures by authority, scheme, ALPN, and stream id before using them as Repeater or Scanner evidence.',
      'Review reused stream ids, missing stream ids, and warning counts before relying on multiplexed browser traffic.',
      'Keep h2c and h2 evidence separate because browser, proxy-chain, and upstream behavior can diverge.',
    ],
  }, null, 2);
  return {
    id: `proxy-http2-multiplexing-${simpleDigest(content).slice(0, 12)}`,
    title: 'Proxy HTTP/2 multiplexing report',
    fileName: `proxyforge-proxy-http2-multiplexing-${stamp}.json`,
    path: `proxy/proxyforge-proxy-http2-multiplexing-${stamp}.json`,
    createdAt: now,
    exchangeCount: exchanges.length,
    http2ExchangeCount,
    connectionCount: connectionSummaries.length,
    multiplexedConnectionCount: connectionSummaries.filter((connection) => connection.multiplexed).length,
    h2cExchangeCount,
    streamIdCoverage,
    connectionSummaries,
    requirements,
    reportReady: true,
    summary: `Proxy HTTP/2 multiplexing report groups ${http2ExchangeCount}/${exchanges.length} HTTP/2 exchange(s) into ${connectionSummaries.length} authority/ALPN connection bucket(s), with ${connectionSummaries.filter((connection) => connection.multiplexed).length} multiplexed bucket(s), ${h2cExchangeCount} h2c exchange(s), and ${(streamIdCoverage * 100).toFixed(0)}% stream-id coverage.`,
    content,
  };
}

function ruleTextForExchange(rule: MatchReplaceRule, exchange: HttpExchange) {
  if (rule.direction === 'request') return exchange.requestRaw;
  if (rule.direction === 'response') return exchange.responseRaw;
  return `${exchange.requestRaw}\n${exchange.responseRaw}`;
}

function ruleMatches(rule: MatchReplaceRule, exchange: HttpExchange) {
  if (!rule.match) return false;
  const text = ruleTextForExchange(rule, exchange);
  if (!rule.isRegex) {
    return rule.caseSensitive ? text.includes(rule.match) : text.toLowerCase().includes(rule.match.toLowerCase());
  }
  try {
    return new RegExp(rule.match, rule.caseSensitive ? 'm' : 'im').test(text);
  } catch {
    return false;
  }
}

function ruleRisk(rule: MatchReplaceRule, affectedCount: number): Severity {
  const text = `${rule.match} ${rule.replace} ${rule.name}`.toLowerCase();
  if (!rule.enabled || !rule.match) return 'info';
  if (/authorization|cookie|session|token|api[-_]?key|bearer/.test(text)) return 'high';
  if (rule.direction === 'both' || affectedCount > 5) return 'medium';
  if (/origin|cors|host|x-forwarded-for|role|admin/.test(text)) return 'medium';
  return 'low';
}

export function buildProxyInterceptRuleReview(request: ProxyHistoryEngineRequest): ProxyInterceptRuleReview {
  const now = request.now ?? new Date().toISOString();
  const exchanges = request.exchanges ?? [];
  const rules = request.rules ?? [];
  const rows: ProxyInterceptRuleReviewRow[] = rules.map((rule) => {
    const affected = exchanges.filter((exchange) => rule.enabled && ruleMatches(rule, exchange));
    const risk = ruleRisk(rule, affected.length);
    return {
      ruleId: rule.id,
      name: rule.name || 'Untitled rule',
      direction: rule.direction,
      enabled: rule.enabled,
      mode: rule.isRegex ? 'regex' : 'literal',
      match: rule.match,
      replacementPreview: rule.replace.slice(0, 80) || '(remove match)',
      affectedExchangeIds: affected.map((exchange) => exchange.id),
      affectedCount: affected.length,
      risk,
      notes: rule.enabled
        ? `${affected.length} matching HTTP history item(s); ${rule.caseSensitive ? 'case-sensitive' : 'case-insensitive'} ${rule.isRegex ? 'regex' : 'literal'} review.`
        : 'Rule disabled; no live traffic mutation will occur.',
    };
  });
  const activeRuleCount = rules.filter((rule) => rule.enabled && rule.match).length;
  const riskyRuleCount = rows.filter((row) => severityRank[row.risk] >= severityRank.medium).length;
  const affectedExchangeCount = new Set(rows.flatMap((row) => row.affectedExchangeIds)).size;
  const recommendations = [
    riskyRuleCount ? 'Review authentication, cookie, role, CORS, and host/header rewrites before capture or replay.' : 'No risky rule rewrite pattern was detected.',
    activeRuleCount ? 'Keep active match/replace rules documented with the filtered history package.' : 'Enable only scoped rules before relying on rewrite behavior.',
    affectedExchangeCount ? 'Attach affected exchanges to Reports so message mutations remain explainable.' : 'Run traffic through Proxy or broaden filters to validate rules against real history.',
  ];
  const content = JSON.stringify({
    kind: 'proxyforge-proxy-intercept-rule-review',
    reviewedAt: now,
    reportReady: true,
    ruleCount: rules.length,
    activeRuleCount,
    riskyRuleCount,
    affectedExchangeCount,
    rules: rows,
    recommendations,
  }, null, 2);
  return {
    id: `proxy-rule-review-${simpleDigest(content).slice(0, 12)}`,
    title: 'Proxy intercept and match/replace rule review',
    reviewedAt: now,
    ruleCount: rules.length,
    activeRuleCount,
    riskyRuleCount,
    requestRuleCount: rules.filter((rule) => rule.direction === 'request' || rule.direction === 'both').length,
    responseRuleCount: rules.filter((rule) => rule.direction === 'response' || rule.direction === 'both').length,
    affectedExchangeCount,
    rules: rows,
    recommendations,
    reportReady: true,
    summary: `${activeRuleCount}/${rules.length} Proxy rule(s) active; ${riskyRuleCount} require reviewer attention and ${affectedExchangeCount} exchange(s) matched.`,
    content,
  };
}

function selectedOrFilteredExchanges(request: ProxyHistoryEngineRequest) {
  const selected = new Set(request.selectedExchangeIds ?? []);
  if (selected.size > 0) return request.exchanges.filter((exchange) => selected.has(exchange.id));
  return request.viewModel?.rows
    .map((row) => request.exchanges.find((exchange) => exchange.id === row.exchangeId))
    .filter((exchange): exchange is HttpExchange => Boolean(exchange))
    ?? filterExchanges(request.exchanges, normalizeProxyHistoryFilters(request.filters));
}

function isProxyCapturePresetHandoff(value: unknown): value is ProxyCapturePresetHandoff {
  if (!value || typeof value !== 'object') return false;
  const candidate = value as Partial<ProxyCapturePresetHandoff>;
  return Array.isArray(candidate.exchangeIds)
    && Array.isArray(candidate.includedSources)
    && typeof candidate.content === 'string';
}

function isProxyTrafficComparisonPackage(value: unknown): value is ProxyTrafficComparisonPackage {
  if (!value || typeof value !== 'object') return false;
  const candidate = value as Partial<ProxyTrafficComparisonPackage>;
  return Array.isArray(candidate.deltas)
    && typeof candidate.added === 'number'
    && typeof candidate.removed === 'number'
    && typeof candidate.changed === 'number'
    && typeof candidate.content === 'string';
}

function isProxyHttp2FidelityReport(value: unknown): value is ProxyHttp2FidelityReport {
  if (!value || typeof value !== 'object') return false;
  const candidate = value as Partial<ProxyHttp2FidelityReport>;
  return Array.isArray(candidate.exchanges)
    && typeof candidate.http2ExchangeCount === 'number'
    && typeof candidate.content === 'string';
}

function isProxyHttp2MultiplexingReport(value: unknown): value is ProxyHttp2MultiplexingReport {
  if (!value || typeof value !== 'object') return false;
  const candidate = value as Partial<ProxyHttp2MultiplexingReport>;
  return Array.isArray(candidate.connectionSummaries)
    && typeof candidate.multiplexedConnectionCount === 'number'
    && typeof candidate.content === 'string';
}

function isProxyCrossToolHandoffPackage(value: unknown): value is ProxyCrossToolHandoffPackage {
  if (!value || typeof value !== 'object') return false;
  const candidate = value as Partial<ProxyCrossToolHandoffPackage>;
  return candidate.kind === 'proxyforge-proxy-cross-tool-handoff-package'
    && Array.isArray(candidate.repeaterRequests)
    && Array.isArray(candidate.scannerCandidates)
    && Array.isArray(candidate.reportAttachments)
    && typeof candidate.content === 'string';
}

export function buildProxyCapturePresetHandoff(request: ProxyHistoryEngineRequest): ProxyCapturePresetHandoff {
  const now = request.now ?? new Date().toISOString();
  const viewModel = request.viewModel ?? buildProxyHistoryViewModel(request);
  const exchanges = selectedOrFilteredExchanges({ ...request, viewModel }).slice(0, 200);
  const includedSources = Array.from(new Set(exchanges.map((exchange) => exchange.source)));
  const filterSummary = [
    viewModel.filters.query ? `query "${viewModel.filters.query}"` : '',
    viewModel.filters.method !== 'all' ? `method ${viewModel.filters.method}` : '',
    viewModel.filters.source !== 'all' ? `source ${viewModel.filters.source}` : '',
    viewModel.filters.status !== 'all' ? `status ${viewModel.filters.status}` : '',
    viewModel.filters.risk !== 'all' ? `risk ${viewModel.filters.risk}` : '',
    viewModel.filters.mime ? `mime ${viewModel.filters.mime}` : '',
    viewModel.filters.tag ? `tag ${viewModel.filters.tag}` : '',
  ].filter(Boolean).join(', ') || 'all visible Proxy history';
  const stamp = now.replace(/[:.]/g, '-');
  const content = JSON.stringify({
    kind: 'proxyforge-proxy-capture-preset-handoff',
    createdAt: now,
    reportReady: true,
    targetTool: 'logger',
    presetName: 'Proxy Advanced History',
    filterSummary,
    includedSources,
    exchangeIds: exchanges.map((exchange) => exchange.id),
    captureControls: ['proxy', 'repeater', 'scanner'].map((tool) => ({ tool, enabled: includedSources.includes(tool as HttpExchange['source']) || tool === 'proxy' })),
    viewSummary: viewModel.summary,
  }, null, 2);
  return {
    id: `proxy-capture-handoff-${simpleDigest(content).slice(0, 12)}`,
    title: 'Proxy capture preset handoff',
    fileName: `proxyforge-proxy-capture-preset-${stamp}.json`,
    path: `proxy/proxyforge-proxy-capture-preset-${stamp}.json`,
    createdAt: now,
    presetName: 'Proxy Advanced History',
    filterSummary,
    exchangeIds: exchanges.map((exchange) => exchange.id),
    includedSources,
    reportReady: true,
    summary: `Logger capture preset handoff covers ${exchanges.length} Proxy history exchange(s) from ${includedSources.join(', ') || 'no source'} with ${filterSummary}.`,
    content,
  };
}

function exchangeRouteKey(exchange: HttpExchange) {
  return `${exchange.method.toUpperCase()} ${exchange.host}${exchange.path}`;
}

function subsetExchanges(all: HttpExchange[], selector?: ProxyHistoryEngineRequest['baseline']) {
  if (selector?.exchanges?.length) return selector.exchanges;
  if (selector?.exchangeIds?.length) {
    const selected = new Set(selector.exchangeIds);
    return all.filter((exchange) => selected.has(exchange.id));
  }
  return all;
}

export function buildProxyTrafficComparisonPackage(request: ProxyHistoryEngineRequest): ProxyTrafficComparisonPackage {
  const now = request.now ?? new Date().toISOString();
  const all = request.exchanges ?? [];
  const baseline = subsetExchanges(all, request.baseline);
  const candidate = subsetExchanges(selectedOrFilteredExchanges(request).length ? selectedOrFilteredExchanges(request) : all, request.candidate);
  const baselineByRoute = new Map(baseline.map((exchange) => [exchangeRouteKey(exchange), exchange]));
  const candidateByRoute = new Map(candidate.map((exchange) => [exchangeRouteKey(exchange), exchange]));
  const routes = Array.from(new Set([...baselineByRoute.keys(), ...candidateByRoute.keys()])).sort();
  const deltas: ProxyTrafficComparisonDelta[] = routes.map((route) => {
    const before = baselineByRoute.get(route);
    const after = candidateByRoute.get(route);
    const representative = after ?? before;
    const changed = Boolean(before && after && (before.status !== after.status || before.length !== after.length || before.mime !== after.mime || before.risk !== after.risk));
    const state: ProxyTrafficComparisonDelta['state'] = !before ? 'added' : !after ? 'removed' : changed ? 'changed' : 'unchanged';
    return {
      id: `proxy-delta-${simpleDigest(route).slice(0, 10)}`,
      route,
      method: representative?.method ?? route.split(' ')[0],
      host: representative?.host ?? route.split(' ')[1]?.split('/')[0] ?? 'unknown',
      path: representative?.path ?? '/',
      state,
      baselineStatus: before?.status,
      candidateStatus: after?.status,
      baselineLength: before?.length,
      candidateLength: after?.length,
      risk: after?.risk ?? before?.risk ?? 'info',
      summary: state === 'changed'
        ? `Changed from ${before?.status}/${before?.length} to ${after?.status}/${after?.length}.`
        : state === 'added'
          ? `Added candidate route ${route}.`
          : state === 'removed'
            ? `Removed baseline route ${route}.`
            : `Unchanged route ${route}.`,
    };
  });
  const added = deltas.filter((delta) => delta.state === 'added').length;
  const removed = deltas.filter((delta) => delta.state === 'removed').length;
  const changed = deltas.filter((delta) => delta.state === 'changed').length;
  const statusDrift = deltas.filter((delta) => delta.baselineStatus !== undefined && delta.candidateStatus !== undefined && delta.baselineStatus !== delta.candidateStatus).length;
  const stamp = now.replace(/[:.]/g, '-');
  const digestPreview = simpleDigest(JSON.stringify(deltas));
  const content = JSON.stringify({
    kind: 'proxyforge-proxy-traffic-comparison',
    createdAt: now,
    reportReady: true,
    baselineName: request.baseline?.name ?? 'Proxy baseline',
    candidateName: request.candidate?.name ?? 'Filtered Proxy history',
    added,
    removed,
    changed,
    statusDrift,
    digestPreview,
    deltas,
  }, null, 2);
  return {
    id: `proxy-traffic-comparison-${digestPreview.slice(0, 12)}`,
    title: 'Proxy traffic comparison package',
    fileName: `proxyforge-proxy-traffic-comparison-${stamp}.json`,
    path: `proxy/proxyforge-proxy-traffic-comparison-${stamp}.json`,
    createdAt: now,
    baselineName: request.baseline?.name ?? 'Proxy baseline',
    candidateName: request.candidate?.name ?? 'Filtered Proxy history',
    added,
    removed,
    changed,
    statusDrift,
    digestPreview,
    deltas,
    reportReady: true,
    summary: `Proxy traffic comparison found ${added} added, ${removed} removed, ${changed} changed route(s), and ${statusDrift} status drift(s).`,
    content,
  };
}

function repeaterGroupForExchange(exchange: HttpExchange) {
  try {
    const parsed = new URL(exchange.url);
    return parsed.host || exchange.host || 'Proxy History';
  } catch {
    return exchange.host || 'Proxy History';
  }
}

function transportHintsForExchange(exchange: HttpExchange, metadata: ProxyHistoryMetadata) {
  return uniqueStrings([
    metadata.protocol,
    metadata.tls ? 'tls' : 'cleartext',
    metadata.http2?.alpn ? `alpn:${metadata.http2.alpn}` : '',
    metadata.http2?.streamId !== undefined ? `stream:${metadata.http2.streamId}` : '',
    metadata.durationBucket === 'timeout' ? 'timeout-review' : '',
    isModified(exchange) ? 'modified-message' : '',
  ]);
}

function insertionPointsForExchange(exchange: HttpExchange) {
  const points: string[] = [];
  try {
    const parsed = new URL(exchange.url);
    for (const key of parsed.searchParams.keys()) points.push(`query:${key}`);
    for (const segment of parsed.pathname.split('/').filter(Boolean)) {
      if (/[0-9_-]{2,}/i.test(segment)) points.push(`path:${segment}`);
    }
  } catch {
    // Raw-only imports still provide body/header insertion points below.
  }
  for (const line of rawHeaderLines(exchange.requestRaw)) {
    const name = headerName(line);
    if (/authorization|cookie|x-api-key|x-forwarded|origin|referer/i.test(name)) points.push(`header:${name}`);
  }
  const body = rawBody(exchange.requestRaw);
  if (/content-type:\s*application\/json/i.test(exchange.requestRaw)) {
    for (const match of body.matchAll(/"([^"]+)"\s*:/g)) points.push(`json:${match[1]}`);
  } else if (/content-type:\s*application\/x-www-form-urlencoded/i.test(exchange.requestRaw) || /[A-Za-z0-9_.-]+=/i.test(body)) {
    for (const match of body.matchAll(/(?:^|[&\s])([A-Za-z0-9_.-]+)=/g)) points.push(`body:${match[1]}`);
  }
  return uniqueStrings(points).slice(0, 20);
}

function scannerCheckHints(exchange: HttpExchange, metadata: ProxyHistoryMetadata) {
  const raw = `${exchange.requestRaw}\n${exchange.responseRaw}`.toLowerCase();
  const hints: string[] = [];
  if (metadata.hasParameters) hints.push('parameter-audit');
  if (exchange.status === 401 || exchange.status === 403 || /authorization|cookie|role|permission|missing_permission/.test(raw)) hints.push('authz-diff');
  if (/bearer\s+[a-z0-9._~+/=-]+|jwt|eyj[a-z0-9_-]+\./i.test(raw)) hints.push('jwt-claims');
  if (/graphql|__schema|query\s*[{(]/.test(raw)) hints.push('graphql-introspection');
  if (/access-control-allow-origin|origin:/.test(raw)) hints.push('cors-origin');
  if (/cache-control|etag|vary:|x-cache/.test(raw)) hints.push('cache-key');
  if (/options|allow:/.test(raw) || exchange.method === 'OPTIONS') hints.push('method-options');
  if (exchange.mime.includes('html') || /strict-transport-security|content-security-policy|x-frame-options/.test(raw)) hints.push('security-headers');
  return uniqueStrings(hints.length ? hints : ['passive-review']);
}

function scannerReadyReason(exchange: HttpExchange, metadata: ProxyHistoryMetadata) {
  const reasons = [
    severityRank[exchange.risk] >= severityRank.medium ? `risk:${exchange.risk}` : '',
    exchange.status >= 400 ? `status:${exchange.status}` : '',
    metadata.hasParameters ? 'has-insertion-points' : '',
    secretSignals(exchange).length ? 'auth-material-present' : '',
  ].filter(Boolean);
  return reasons.join(', ') || 'manual triage candidate';
}

export function buildProxyCrossToolHandoffPackage(request: ProxyHistoryEngineRequest): ProxyCrossToolHandoffPackage {
  const now = request.now ?? new Date().toISOString();
  const viewModel = request.viewModel ?? buildProxyHistoryViewModel(request);
  const selected = selectedOrFilteredExchanges({ ...request, viewModel }).slice(0, 200);
  const rowsByExchangeId = new Map(viewModel.rows.map((row) => [row.exchangeId, row]));
  const issue = buildProxyScannerPromotionIssue({ ...request, viewModel });
  const repeaterRequests: ProxyRepeaterHandoffRequest[] = selected
    .filter((exchange) => exchange.method !== 'CONNECT' && exchange.requestRaw.trim())
    .map((exchange) => {
      const metadata = rowsByExchangeId.get(exchange.id) ?? exchangeToMetadata(exchange);
      return {
        exchangeId: exchange.id,
        tabName: `${exchange.method} ${exchange.path}`,
        group: repeaterGroupForExchange(exchange),
        targetUrl: exchange.url,
        rawRequest: exchange.requestRaw,
        sourceFingerprint: metadata.fingerprint,
        transportHints: transportHintsForExchange(exchange, metadata),
        secretSignals: secretSignals(exchange),
      };
    });
  const scannerCandidates: ProxyScannerHandoffCandidate[] = selected
    .map((exchange) => {
      const metadata = rowsByExchangeId.get(exchange.id) ?? exchangeToMetadata(exchange);
      return { exchange, metadata, insertionPoints: insertionPointsForExchange(exchange) };
    })
    .filter(({ exchange, metadata, insertionPoints }) => metadata.scannerReady || insertionPoints.length > 0 || severityRank[exchange.risk] >= severityRank.medium)
    .map(({ exchange, metadata, insertionPoints }) => ({
      exchangeId: exchange.id,
      issueId: issue.id,
      method: exchange.method,
      host: exchange.host,
      path: exchange.path,
      status: exchange.status,
      risk: exchange.risk,
      insertionPoints,
      checkHints: scannerCheckHints(exchange, metadata),
      rawRequest: exchange.requestRaw,
      rawResponse: exchange.responseRaw,
      scannerReadyReason: scannerReadyReason(exchange, metadata),
    }));
  const reportAttachments: ProxyReportHandoffAttachment[] = selected.map((exchange) => ({
    exchangeId: exchange.id,
    title: `${exchange.method} ${exchange.host}${exchange.path}`,
    fileName: `proxy-history-${exchange.id}.json`,
    requestFingerprint: simpleDigest(exchange.requestRaw),
    responseFingerprint: simpleDigest(exchange.responseRaw),
    reportReady: true,
    redactionPhase: 'report-export-only',
  }));
  const destinations: ProxyCrossToolHandoffDestination[] = uniqueStrings([
    repeaterRequests.length ? 'repeater' : '',
    scannerCandidates.length ? 'scanner' : '',
    reportAttachments.length ? 'reports' : '',
  ]) as ProxyCrossToolHandoffDestination[];
  const requirements = {
    stableExchangeIds: selected.length > 0 && selected.every((exchange) => Boolean(exchange.id)),
    repeaterRawRequestsPreserved: repeaterRequests.length > 0 && repeaterRequests.every((item) => item.rawRequest.trim().length > 0),
    scannerCandidatesLinked: scannerCandidates.length > 0 && scannerCandidates.every((item) => item.issueId === issue.id && Boolean(item.rawRequest.trim()) && Boolean(item.rawResponse.trim())),
    reportAttachmentsLinked: reportAttachments.length === selected.length && reportAttachments.every((item) => item.reportReady && item.redactionPhase === 'report-export-only'),
    crossToolAuditTrail: destinations.includes('repeater') && destinations.includes('scanner') && destinations.includes('reports'),
    operationalSecretsPreserved: repeaterRequests.some((item) => item.secretSignals.length > 0) || scannerCandidates.some((item) => secretSignals({
      id: item.exchangeId,
      method: item.method,
      host: item.host,
      path: item.path,
      url: '',
      status: item.status,
      length: 0,
      mime: '',
      risk: item.risk,
      timing: 0,
      notes: '',
      source: 'proxy',
      time: '',
      requestRaw: item.rawRequest,
      responseRaw: item.rawResponse,
      tags: [],
    }).length > 0),
    reportPhaseOnlyRedaction: true,
  };
  const stamp = now.replace(/[:.]/g, '-');
  const content = JSON.stringify({
    kind: 'proxyforge-proxy-cross-tool-handoff-package',
    createdAt: now,
    reportReady: true,
    exchangeIds: selected.map((exchange) => exchange.id),
    destinations,
    issue,
    repeaterRequests,
    scannerCandidates,
    reportAttachments,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    redactionBoundary: 'Proxy cross-tool handoff packages preserve raw operational requests, responses, cookies, tokens, and keys. Redaction occurs only during report/submission export.',
  }, null, 2);
  return {
    id: `proxy-cross-tool-handoff-${simpleDigest(content).slice(0, 12)}`,
    kind: 'proxyforge-proxy-cross-tool-handoff-package',
    title: 'Proxy cross-tool handoff package',
    fileName: `proxyforge-proxy-cross-tool-handoff-${stamp}.json`,
    path: `proxy/proxyforge-proxy-cross-tool-handoff-${stamp}.json`,
    createdAt: now,
    exchangeIds: selected.map((exchange) => exchange.id),
    destinations,
    repeaterRequests,
    scannerCandidates,
    reportAttachments,
    issueId: issue.id,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportReady: true,
    summary: `Proxy cross-tool handoff stages ${repeaterRequests.length} Repeater request(s), ${scannerCandidates.length} Scanner candidate(s), and ${reportAttachments.length} Reports attachment(s) from ${selected.length} Proxy history exchange(s) while preserving full-fidelity operational material.`,
    content,
  };
}

export function buildProxyHistoryEvidenceAttachment(request: ProxyHistoryEngineRequest): ProxyHistoryEvidenceAttachment {
  const now = request.now ?? new Date().toISOString();
  const viewModel = request.viewModel ?? buildProxyHistoryViewModel(request);
  const filterSetPackage = isProxyHistoryFilterSetPackage(request.filterSetPackage)
    ? request.filterSetPackage
    : buildProxyHistoryFilterSetPackage({ ...request, viewModel });
  const ruleReview = request.ruleReview ?? buildProxyInterceptRuleReview(request);
  const capturePreset = isProxyCapturePresetHandoff(request.capturePreset)
    ? request.capturePreset
    : buildProxyCapturePresetHandoff({ ...request, viewModel });
  const comparisonPackage = isProxyTrafficComparisonPackage(request.comparisonPackage)
    ? request.comparisonPackage
    : buildProxyTrafficComparisonPackage({ ...request, viewModel });
  const http2FidelityReport = isProxyHttp2FidelityReport(request.http2FidelityReport)
    ? request.http2FidelityReport
    : buildProxyHttp2FidelityReport({ ...request, viewModel });
  const http2MultiplexingReport = isProxyHttp2MultiplexingReport(request.http2MultiplexingReport)
    ? request.http2MultiplexingReport
    : buildProxyHttp2MultiplexingReport({ ...request, viewModel });
  const crossToolHandoffPackage = isProxyCrossToolHandoffPackage(request.crossToolHandoffPackage)
    ? request.crossToolHandoffPackage
    : buildProxyCrossToolHandoffPackage({ ...request, viewModel });
  const selected = selectedOrFilteredExchanges({ ...request, viewModel }).slice(0, 200);
  const stamp = now.replace(/[:.]/g, '-');
  const content = JSON.stringify({
    kind: 'proxyforge-proxy-history-evidence',
    createdAt: now,
    reportReady: true,
    issueId: request.issueId,
    viewModel,
    filterSetPackage,
    ruleReview,
    capturePreset,
    trafficComparison: comparisonPackage,
    http2FidelityReport,
    http2MultiplexingReport,
    crossToolHandoffPackage,
    exchangeIds: selected.map((exchange) => exchange.id),
    evidenceMetadata: 'report-ready Proxy history, saved filter-set, HTTP/2 fidelity and multiplexing, intercept rule, annotation, Repeater/Scanner/Reports cross-tool handoff, and traffic comparison evidence',
  }, null, 2);
  return {
    id: `proxy-history-evidence-${simpleDigest(content).slice(0, 12)}`,
    title: 'Proxy History Evidence',
    fileName: `proxyforge-proxy-history-evidence-${stamp}.json`,
    path: `reports/proxyforge-proxy-history-evidence-${stamp}.json`,
    createdAt: now,
    viewModelId: viewModel.id,
    filterSetPackageId: filterSetPackage.id,
    ruleReviewId: ruleReview.id,
    capturePresetId: capturePreset.id,
    comparisonPackageId: comparisonPackage.id,
    http2FidelityReportId: http2FidelityReport.id,
    http2MultiplexingReportId: http2MultiplexingReport.id,
    crossToolHandoffPackageId: crossToolHandoffPackage.id,
    issueId: request.issueId,
    exchangeIds: selected.map((exchange) => exchange.id),
    reportReady: true,
    summary: `Proxy History Evidence covers ${viewModel.filteredCount} filtered item(s), ${filterSetPackage.savedFilterCount} saved filter predicate(s), ${http2FidelityReport.http2ExchangeCount} HTTP/2 fidelity item(s), ${http2MultiplexingReport.multiplexedConnectionCount} multiplexed HTTP/2 bucket(s), ${ruleReview.activeRuleCount} active intercept rule(s), ${capturePreset.exchangeIds.length} capture handoff item(s), ${crossToolHandoffPackage.destinations.length} cross-tool destination(s), and ${comparisonPackage.changed + comparisonPackage.added + comparisonPackage.removed} traffic comparison delta(s).`,
    content,
  };
}

export function buildProxyEdgeProfilePackage(request: ProxyEdgeProfileRequest): ProxyEdgeProfilePackage {
  const generatedAt = request.now ?? new Date().toISOString();
  const stamp = generatedAt.replace(/[:.]/g, '-');
  const viewModel = request.viewModel ?? buildProxyHistoryViewModel(request);
  const filterSetPackage = isProxyHistoryFilterSetPackage(request.filterSetPackage)
    ? request.filterSetPackage
    : buildProxyHistoryFilterSetPackage({ ...request, viewModel });
  const ruleReview = request.ruleReview ?? buildProxyInterceptRuleReview(request);
  const capturePreset = isProxyCapturePresetHandoff(request.capturePreset)
    ? request.capturePreset
    : buildProxyCapturePresetHandoff({ ...request, viewModel });
  const comparisonPackage = isProxyTrafficComparisonPackage(request.comparisonPackage)
    ? request.comparisonPackage
    : buildProxyTrafficComparisonPackage({ ...request, viewModel });
  const http2FidelityReport = isProxyHttp2FidelityReport(request.http2FidelityReport)
    ? request.http2FidelityReport
    : buildProxyHttp2FidelityReport({ ...request, viewModel });
  const http2MultiplexingReport = isProxyHttp2MultiplexingReport(request.http2MultiplexingReport)
    ? request.http2MultiplexingReport
    : buildProxyHttp2MultiplexingReport({ ...request, viewModel });
  const crossToolHandoffPackage = isProxyCrossToolHandoffPackage(request.crossToolHandoffPackage)
    ? request.crossToolHandoffPackage
    : buildProxyCrossToolHandoffPackage({ ...request, viewModel });
  const historyEvidenceAttachment = request.historyEvidenceAttachment
    ?? buildProxyHistoryEvidenceAttachment({
      ...request,
      viewModel,
      filterSetPackage,
      ruleReview,
      capturePreset,
      comparisonPackage,
      http2FidelityReport,
      http2MultiplexingReport,
      crossToolHandoffPackage,
    });
  const coreLinkedPackages: ProxyLinkedEvidencePackage[] = [
    {
      id: filterSetPackage.id,
      kind: filterSetPackage.kind,
      content: filterSetPackage.content,
      reportReady: filterSetPackage.reportReady,
      requirements: filterSetPackage.requirements,
      summary: filterSetPackage.summary,
    },
    {
      id: ruleReview.id,
      kind: 'proxyforge-proxy-intercept-rule-review',
      content: ruleReview.content,
      reportReady: ruleReview.reportReady,
      summary: ruleReview.summary,
    },
    {
      id: capturePreset.id,
      kind: 'proxyforge-proxy-capture-preset-handoff',
      content: capturePreset.content,
      reportReady: capturePreset.reportReady,
      summary: capturePreset.summary,
    },
    {
      id: comparisonPackage.id,
      kind: 'proxyforge-proxy-traffic-comparison',
      content: comparisonPackage.content,
      reportReady: comparisonPackage.reportReady,
      summary: comparisonPackage.summary,
    },
    {
      id: http2FidelityReport.id,
      kind: 'proxyforge-proxy-http2-fidelity-report',
      content: http2FidelityReport.content,
      reportReady: http2FidelityReport.reportReady,
      summary: http2FidelityReport.summary,
    },
    {
      id: http2MultiplexingReport.id,
      kind: 'proxyforge-proxy-http2-multiplexing-report',
      content: http2MultiplexingReport.content,
      reportReady: http2MultiplexingReport.reportReady,
      requirements: http2MultiplexingReport.requirements,
      summary: http2MultiplexingReport.summary,
    },
    {
      id: crossToolHandoffPackage.id,
      kind: crossToolHandoffPackage.kind,
      content: crossToolHandoffPackage.content,
      reportReady: crossToolHandoffPackage.reportReady,
      requirements: crossToolHandoffPackage.requirements,
      summary: crossToolHandoffPackage.summary,
    },
    {
      id: historyEvidenceAttachment.id,
      kind: 'proxyforge-proxy-history-evidence',
      content: historyEvidenceAttachment.content,
      reportReady: historyEvidenceAttachment.reportReady,
      summary: historyEvidenceAttachment.summary,
    },
  ];
  const linkedPackages = [...coreLinkedPackages, ...(request.linkedPackages ?? [])];
  const linkedPackageDigests = linkedPackages.map((item, index) => ({
    id: proxyLinkedPackageId(item, index),
    kind: proxyLinkedPackageKind(item),
    digest: simpleDigest(proxyLinkedPackageText(item)),
    reportReady: proxyLinkedPackageReady(item),
  }));
  const linkedPackageKinds = uniqueStrings(linkedPackageDigests.map((item) => item.kind));
  const stalePackageIds = linkedPackageDigests.filter((item) => !item.reportReady).map((item) => item.id);
  const rows = viewModel.rows;
  const hostCount = viewModel.hostCount;
  const routeCount = uniqueStrings(rows.map((row) => `${row.method} ${row.host}${row.path}`)).length;
  const linkedText = linkedPackages.map(proxyLinkedPackageText).join('\n');
  const rawExchangeText = request.exchanges.map((exchange) => `${exchange.requestRaw}\n${exchange.responseRaw}`).join('\n');
  const rawMaterial = [
    JSON.stringify(viewModel),
    rawExchangeText,
    linkedText,
    ...(request.operationalSecretSamples ?? []),
  ].join('\n');
  const protocolValues = uniqueStrings(rows.map((row) => row.protocol));
  const protocolCoverage = [
    ...protocolValues,
    /websocket|ws:|Sec-WebSocket|proxyforge-websocket/i.test(linkedText) ? 'WebSocket' : '',
  ].filter(Boolean) as ProxyEdgeProfilePackage['protocolCoverage'];
  const methodCoverage = uniqueStrings(rows.map((row) => row.method));
  const statusClasses = uniqueStrings(rows.map((row) => proxyStatusClass(row.status)).filter((value) => value !== 'unknown'));
  const packageRefreshProof = {
    refreshedAt: generatedAt,
    linkedPackageKinds,
    linkedPackageDigests,
    stalePackageIds,
    freshDigest: simpleDigest(linkedPackageDigests.map((item) => `${item.id}:${item.kind}:${item.digest}:${item.reportReady}`).join('|')),
  };
  const operationalSecretSamples = (request.operationalSecretSamples ?? []).map((sample) => sample.trim()).filter(Boolean);
  const minHosts = request.minHosts ?? 3;
  const minRoutes = request.minRoutes ?? 4;
  const minPackageKinds = request.minPackageKinds ?? 11;
  const requiredCoreKinds = [
    'proxyforge-proxy-history-filter-set-package',
    'proxyforge-proxy-intercept-rule-review',
    'proxyforge-proxy-capture-preset-handoff',
    'proxyforge-proxy-traffic-comparison',
    'proxyforge-proxy-http2-fidelity-report',
    'proxyforge-proxy-http2-multiplexing-report',
    'proxyforge-proxy-cross-tool-handoff-package',
    'proxyforge-proxy-history-evidence',
  ];
  const requirements = {
    httpListenerCaptureCovered: linkedPackageKinds.includes('proxyforge-proxy-http-listener-capture-package')
      || rows.filter((row) => row.source === 'proxy').length >= 2,
    connectTunnelCovered: methodCoverage.includes('CONNECT')
      || /CONNECT tunnel|proxyforge-proxy-connect|tunnel byte|Proxy-Authorization/i.test(linkedText),
    httpsMitmCovered: rows.some((row) => row.tls)
      && /mitm|project CA|certificate|proxyforge-https-mitm/i.test(linkedText),
    interceptControlsCovered: ruleReview.activeRuleCount > 0
      && /proxyforge-proxy-intercept|intercept|drop-before-upstream|drop-before-client|request hold|response hold/i.test(linkedText),
    matchReplaceCovered: (request.rules ?? []).some((rule) => rule.direction === 'request' && rule.enabled)
      && (request.rules ?? []).some((rule) => rule.direction === 'response' && rule.enabled)
      && /match-replace|rule-library|proxyforge-proxy-match-replace/i.test(linkedText),
    http2FidelityCovered: http2FidelityReport.http2ExchangeCount >= 2
      && Object.values(http2MultiplexingReport.requirements).every(Boolean),
    crossToolHandoffCovered: ['repeater', 'scanner', 'reports'].every((destination) => crossToolHandoffPackage.destinations.includes(destination as ProxyCrossToolHandoffDestination))
      && Object.values(crossToolHandoffPackage.requirements).every(Boolean),
    websocketEdgeCovered: linkedPackageKinds.includes('proxyforge-websocket-capture-evidence-package')
      && linkedPackageKinds.includes('proxyforge-websocket-intercept-rewrite-replay-evidence-package')
      && linkedPackageKinds.includes('proxyforge-websocket-state-transcript-evidence-package'),
    browserProxyChainCovered: hostCount >= minHosts
      && routeCount >= minRoutes
      && /browser-routing|Chromium|proxy-chain|upstream proxy|Proxy-Authorization|proxyforge-browser-routing/i.test(linkedText),
    packageRefreshCovered: requiredCoreKinds.every((kind) => linkedPackageKinds.includes(kind))
      && linkedPackageKinds.length >= minPackageKinds
      && stalePackageIds.length === 0,
    rawExecutorMaterialPreserved: /HTTP\/[12]|CONNECT|Authorization:|Cookie:|Proxy-Authorization:|Sec-WebSocket|rawRequest|rawResponse|Bearer/i.test(rawMaterial),
    operationalSecretsPreserved: operationalSecretSamples.length > 0
      && operationalSecretSamples.every((sample) => rawMaterial.includes(sample)),
    reportPhaseOnlyRedaction: /redact-only-during-report-export|report-export-only|submission\/report artifacts redact/i.test(rawMaterial),
  };
  const digestPreview = simpleDigest(JSON.stringify({
    generatedAt,
    hostCount,
    routeCount,
    statusClasses,
    protocolCoverage,
    methodCoverage,
    packageRefreshProof,
    requirements,
  }));
  const content = JSON.stringify({
    kind: 'proxyforge-proxy-edge-profile-package',
    generatedAt,
    hostCount,
    routeCount,
    statusClasses,
    protocolCoverage,
    methodCoverage,
    linkedPackageIds: linkedPackageDigests.map((item) => item.id),
    packageRefreshProof,
    requirements,
    operationalSecretSamples,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    digestPreview,
  }, null, 2);

  return {
    id: `proxy-edge-profile-${digestPreview.slice(0, 12)}`,
    kind: 'proxyforge-proxy-edge-profile-package',
    title: 'Proxy/HTTPS edge production profile',
    fileName: `proxyforge-proxy-edge-profile-${stamp}.json`,
    path: `proxy/proxyforge-proxy-edge-profile-${stamp}.json`,
    generatedAt,
    hostCount,
    routeCount,
    statusClasses,
    protocolCoverage,
    methodCoverage,
    linkedPackageIds: linkedPackageDigests.map((item) => item.id),
    packageRefreshProof,
    requirements,
    operationalSecretSamples,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
    summary: `Proxy/HTTPS edge profile links ${hostCount} host(s), ${routeCount} route(s), ${protocolCoverage.join('/')} protocol coverage, ${linkedPackageDigests.length} package digest(s), listener/CONNECT/MITM/intercept/match-replace/HTTP2/WebSocket/browser-proxy proof, and report-export-only redaction.`,
    content,
  };
}

export function buildProxyBrowserProxyChainDiversityPackage(
  request: ProxyBrowserProxyChainDiversityRequest,
): ProxyBrowserProxyChainDiversityPackage {
  const generatedAt = request.generatedAt ?? new Date().toISOString();
  const stamp = generatedAt.replace(/[:.]/g, '-');
  const profiles = request.profiles;
  const browserFamilies = uniqueStrings(profiles.map((profile) => profile.browserFamily));
  const platforms = uniqueStrings(profiles.map((profile) => profile.platform));
  const proxyModes = uniqueStrings(profiles.map((profile) => profile.proxyMode));
  const certificateModes = uniqueStrings(profiles.map((profile) => profile.certificateMode));
  const hostCount = profiles.reduce((total, profile) => total + profile.hostCount, 0);
  const routeCount = profiles.reduce((total, profile) => total + profile.routeCount, 0);
  const rawMaterial = [
    JSON.stringify(request.edgeProfilePackage),
    JSON.stringify(profiles),
    ...(request.operationalSecretSamples ?? []),
  ].join('\n');
  const linkedPackageDigests = [
    {
      id: request.edgeProfilePackage.id,
      kind: request.edgeProfilePackage.kind,
      digest: simpleDigest(request.edgeProfilePackage.content),
      reportReady: request.edgeProfilePackage.reportReady,
    },
    ...profiles.map((profile) => ({
      id: profile.id,
      kind: 'proxy-browser-proxy-chain-profile',
      digest: simpleDigest(JSON.stringify(profile)),
      reportReady: [
        profile.isolatedProfile,
        profile.cookieStoreCovered,
        profile.capturedHttp,
        profile.capturedHttpsMitm,
        profile.rawRequestSample.length > 0,
        profile.rawResponseSample.length > 0,
      ].every(Boolean),
    })),
  ];
  const stalePackageIds = linkedPackageDigests.filter((item) => !item.reportReady).map((item) => item.id);
  const packageRefreshProof = {
    refreshedAt: generatedAt,
    linkedPackageKinds: uniqueStrings(linkedPackageDigests.map((item) => item.kind)),
    linkedPackageDigests,
    stalePackageIds,
    freshDigest: simpleDigest(linkedPackageDigests.map((item) => `${item.id}:${item.digest}:${item.reportReady}`).join('|')),
  };
  const operationalSecretSamples = (request.operationalSecretSamples ?? []).map((sample) => sample.trim()).filter(Boolean);
  const requirements = {
    multiBrowserFamilyCovered: ['chromium', 'chrome', 'edge', 'firefox'].every((family) => browserFamilies.includes(family)),
    linuxWindowsProfileCoverage: platforms.includes('linux') && platforms.includes('windows'),
    proxyChainModeDiversityCovered: ['upstream-auth', 'connect-chain'].every((mode) => proxyModes.includes(mode))
      && proxyModes.length >= 4,
    httpsMitmTrustModesCovered: profiles.every((profile) => profile.capturedHttpsMitm)
      && certificateModes.includes('project-ca')
      && certificateModes.includes('trusted-ca')
      && certificateModes.some((mode) => mode === 'manual-import' || mode === 'pinned-nonblocking'),
    connectHttp2WebSocketCovered: profiles.some((profile) => profile.capturedConnect)
      && profiles.some((profile) => profile.capturedHttp2)
      && profiles.some((profile) => profile.capturedWebSocket)
      && profiles.some((profile) => profile.protocolCoverage.includes('CONNECT'))
      && profiles.some((profile) => profile.protocolCoverage.includes('WebSocket')),
    isolatedProfileAndCookieStoresCovered: profiles.every((profile) => profile.isolatedProfile && profile.cookieStoreCovered),
    upstreamCredentialPreservationCovered: profiles.some((profile) => (
      Boolean(profile.upstreamProxyAuthorization)
      && rawMaterial.includes(profile.upstreamProxyAuthorization ?? '')
    )),
    edgeProfileLinked: request.edgeProfilePackage.kind === 'proxyforge-proxy-edge-profile-package'
      && request.edgeProfilePackage.reportReady
      && Object.values(request.edgeProfilePackage.requirements).every(Boolean),
    packageRefreshCovered: stalePackageIds.length === 0
      && packageRefreshProof.linkedPackageKinds.includes('proxyforge-proxy-edge-profile-package')
      && packageRefreshProof.linkedPackageDigests.length >= profiles.length + 1,
    rawExecutorMaterialPreserved: /HTTP\/[12]|CONNECT|Authorization:|Cookie:|Proxy-Authorization:|Sec-WebSocket|rawRequestSample|rawResponseSample/i.test(rawMaterial),
    operationalSecretsPreserved: operationalSecretSamples.length > 0
      && operationalSecretSamples.every((sample) => rawMaterial.includes(sample)),
    reportPhaseOnlyRedaction: /redact-only-during-report-export|report-export-only/i.test(rawMaterial),
  };
  const unsigned = {
    kind: 'proxyforge-proxy-browser-proxy-chain-diversity-package',
    generatedAt,
    linkedEdgeProfileId: request.edgeProfilePackage.id,
    profiles,
    browserFamilies,
    platforms,
    proxyModes,
    certificateModes,
    hostCount,
    routeCount,
    packageRefreshProof,
    operationalSecretSamples,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const content = JSON.stringify({ ...unsigned, digestPreview }, null, 2);

  return {
    id: `proxy-browser-proxy-chain-diversity-${digestPreview.slice(0, 12)}`,
    kind: 'proxyforge-proxy-browser-proxy-chain-diversity-package',
    title: 'Proxy browser and proxy-chain diversity package',
    fileName: `proxyforge-proxy-browser-proxy-chain-diversity-${stamp}.json`,
    path: `proxy/proxyforge-proxy-browser-proxy-chain-diversity-${stamp}.json`,
    generatedAt,
    profileCount: profiles.length,
    browserFamilies,
    platforms,
    proxyModes,
    certificateModes,
    hostCount,
    routeCount,
    requirements,
    linkedEdgeProfileId: request.edgeProfilePackage.id,
    profiles,
    packageRefreshProof,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
    summary: `Proxy browser/proxy-chain diversity links ${profiles.length} profile(s), ${browserFamilies.join('/')} browser families, ${platforms.join('/')} platforms, ${proxyModes.join('/')} proxy modes, ${certificateModes.join('/')} certificate modes, full-fidelity upstream credentials, and report-export-only redaction.`,
    content,
  };
}

export function buildProxyScannerPromotionIssue(request: ProxyHistoryEngineRequest): Issue {
  const viewModel = request.viewModel ?? buildProxyHistoryViewModel(request);
  const rows = viewModel.rows.filter((row) => row.scannerReady);
  const primary = rows[0] ?? viewModel.rows[0];
  const risk = rows.reduce<Severity>((highest, row) => (severityRank[row.risk] > severityRank[highest] ? row.risk : highest), primary?.risk ?? 'info');
  return {
    id: `proxy-history-promotion-${simpleDigest(viewModel.summary).slice(0, 12)}`,
    title: 'Proxy history candidates ready for scanner review',
    severity: severityRank[risk] >= severityRank.medium ? risk : 'info',
    host: primary?.host ?? 'proxy-history',
    path: primary?.path ?? '/proxy-history',
    confidence: rows.length ? 'firm' : 'tentative',
    status: 'triaged',
    detail: `${viewModel.summary} Annotation lanes and HTTP/2-aware metadata identified ${rows.length} Scanner-ready request/response candidate(s) for active or passive review with report-ready Proxy history context.`,
    remediation: 'Review the promoted Proxy history candidates, keep scope gates active, replay interesting requests in Repeater, then run Scanner checks only against authorized hosts.',
    triageNote: 'Promoted from report-ready Proxy advanced HTTP history filtering and annotation lanes.',
    lastTriagedAt: request.now ?? new Date().toISOString(),
  };
}

export const buildProxyHistoryIssuePromotion = buildProxyScannerPromotionIssue;
