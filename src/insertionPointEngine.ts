import type { CrawlInsertionPoint, CrawlInsertionPointType, HttpExchange, Severity } from './types';

export interface ExtractInsertionPointOptions {
  includePathSegments?: boolean;
  includeHeaders?: boolean;
  maxPointsPerExchange?: number;
}

export interface ExtractedInsertionPoint extends CrawlInsertionPoint {
  exchangeId: string;
  location: CrawlInsertionPointType;
  parameter: string;
  route: string;
  valuePreview: string;
  originalValue?: unknown;
  confidence: 'high' | 'medium' | 'low';
  risk: Severity;
  notes: string;
}

export interface InsertionPointInventoryRequest {
  exchanges: HttpExchange[];
  selectedExchangeId?: string;
  scopeAllowlist?: string[];
  now?: string;
  operationalSecretSamples?: string[];
  options?: ExtractInsertionPointOptions;
}

export interface InsertionPointInventoryPackage {
  id: string;
  kind: 'proxyforge-insertion-point-inventory-package';
  title: string;
  fileName: string;
  path: string;
  createdAt: string;
  exchangeCount: number;
  insertionPointCount: number;
  coverage: Array<{ type: CrawlInsertionPointType; count: number }>;
  targetUrls: string[];
  points: ExtractedInsertionPoint[];
  requirements: {
    queryParametersCovered: boolean;
    pathParametersCovered: boolean;
    headerParametersCovered: boolean;
    cookieParametersCovered: boolean;
    formParametersCovered: boolean;
    jsonParametersCovered: boolean;
    xmlParametersCovered: boolean;
    multipartParametersCovered: boolean;
    graphqlParametersCovered: boolean;
    scannerReadyCorpus: boolean;
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

interface ParsedRawHttp {
  startLine: string;
  method: string;
  target: string;
  headers: Array<{ name: string; value: string }>;
  body: string;
}

const allInsertionPointTypes: CrawlInsertionPointType[] = [
  'query',
  'path',
  'header',
  'cookie',
  'form',
  'json',
  'xml',
  'multipart',
  'graphql',
];

const ignoredHeaderNames = new Set([
  'host',
  'content-length',
  'connection',
  'proxy-connection',
  'transfer-encoding',
  'accept',
  'accept-encoding',
  'accept-language',
  'user-agent',
  'sec-fetch-site',
  'sec-fetch-mode',
  'sec-fetch-dest',
  'sec-ch-ua',
  'sec-ch-ua-mobile',
  'sec-ch-ua-platform',
]);

export function extractInsertionPointsFromExchanges(
  exchanges: HttpExchange[],
  options: ExtractInsertionPointOptions = {},
): ExtractedInsertionPoint[] {
  const maxPointsPerExchange = clampInteger(options.maxPointsPerExchange ?? 100, 1, 500);
  return dedupePoints(
    exchanges.flatMap((exchange) => extractInsertionPointsFromExchange(exchange, {
      ...options,
      maxPointsPerExchange,
    })),
  );
}

export function extractInsertionPointsFromExchange(
  exchange: HttpExchange,
  options: ExtractInsertionPointOptions = {},
): ExtractedInsertionPoint[] {
  const parsed = parseRawHttp(exchange.requestRaw);
  const url = resolveExchangeUrl(exchange, parsed);
  const points: ExtractedInsertionPoint[] = [];
  const add = pointAdder(points, exchange, parsed, url);
  const maxPoints = clampInteger(options.maxPointsPerExchange ?? 100, 1, 500);

  addQueryPoints(url, add);
  if (options.includePathSegments !== false) addPathPoints(url, add);
  if (options.includeHeaders !== false) addHeaderPoints(parsed, add);
  addCookiePoints(parsed, add);
  addBodyPoints(parsed, url, add);

  return dedupePoints(points).slice(0, maxPoints);
}

export function buildInsertionPointInventoryPackage(
  request: InsertionPointInventoryRequest,
): InsertionPointInventoryPackage {
  const createdAt = request.now ?? new Date().toISOString();
  const selected = request.selectedExchangeId
    ? request.exchanges.filter((exchange) => exchange.id === request.selectedExchangeId)
    : request.exchanges;
  const exchanges = selected.length ? selected : request.exchanges;
  const points = extractInsertionPointsFromExchanges(exchanges, request.options);
  const coverage = allInsertionPointTypes.map((type) => ({
    type,
    count: points.filter((point) => point.type === type).length,
  }));
  const rawMaterial = [
    ...exchanges.flatMap((exchange) => [exchange.requestRaw, exchange.responseRaw, exchange.notes, exchange.url]),
    JSON.stringify(points),
  ].join('\n');
  const requirements = {
    queryParametersCovered: hasType(points, 'query'),
    pathParametersCovered: hasType(points, 'path'),
    headerParametersCovered: hasType(points, 'header'),
    cookieParametersCovered: hasType(points, 'cookie'),
    formParametersCovered: hasType(points, 'form'),
    jsonParametersCovered: hasType(points, 'json'),
    xmlParametersCovered: hasType(points, 'xml'),
    multipartParametersCovered: hasType(points, 'multipart'),
    graphqlParametersCovered: hasType(points, 'graphql'),
    scannerReadyCorpus: points.length > 0
      && coverage.filter((row) => row.count > 0).length >= 6
      && points.every((point) => point.exchangeId && point.method && point.url && point.evidence),
    rawExecutorMaterialPreserved: /HTTP\/[12]|Authorization:|Cookie:|Set-Cookie:|Content-Type:/i.test(rawMaterial),
    operationalSecretsPreserved: (request.operationalSecretSamples ?? []).length > 0
      && (request.operationalSecretSamples ?? []).every((sample) => rawMaterial.includes(sample)),
    reportPhaseOnlyRedaction: true,
  };
  const targetUrls = Array.from(new Set(exchanges.map((exchange) => exchange.url).filter(Boolean)));
  const unsigned = {
    kind: 'proxyforge-insertion-point-inventory-package',
    createdAt,
    exchangeCount: exchanges.length,
    targetUrls,
    coverage,
    points,
    rawExchanges: exchanges.map((exchange) => ({
      id: exchange.id,
      url: exchange.url,
      method: exchange.method,
      requestRaw: exchange.requestRaw,
      responseRaw: exchange.responseRaw,
    })),
    scopeAllowlist: request.scopeAllowlist ?? [],
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
  };
  const content = JSON.stringify(unsigned, null, 2);
  const digestPreview = simpleDigest(content);
  const stamp = createdAt.replace(/[:.]/g, '-');
  return {
    id: `insertion-point-inventory-${digestPreview.slice(0, 12)}`,
    kind: 'proxyforge-insertion-point-inventory-package',
    title: 'Insertion point inventory package',
    fileName: `proxyforge-insertion-point-inventory-${stamp}.json`,
    path: `scanner/proxyforge-insertion-point-inventory-${stamp}.json`,
    createdAt,
    exchangeCount: exchanges.length,
    insertionPointCount: points.length,
    coverage,
    targetUrls,
    points,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
    digestPreview,
    summary: `Insertion point inventory extracted ${points.length} scanner-ready point(s) across ${coverage.filter((row) => row.count > 0).length} parameter class(es) from ${exchanges.length} exchange(s).`,
    content: JSON.stringify({ ...unsigned, digestPreview }, null, 2),
  };
}

function addQueryPoints(url: URL, add: AddPoint) {
  for (const [name, value] of url.searchParams.entries()) {
    add('query', name, `Query parameter "${name}" from ${url.pathname}${url.search}`, value, 'high');
  }
}

function addPathPoints(url: URL, add: AddPoint) {
  const segments = url.pathname.split('/').filter(Boolean);
  segments.forEach((segment, index) => {
    if (!isDynamicPathSegment(segment)) return;
    add('path', `segment-${index + 1}`, `Dynamic-looking path segment "${segment}" at position ${index + 1}`, segment, 'medium');
  });
}

function addHeaderPoints(parsed: ParsedRawHttp, add: AddPoint) {
  for (const header of parsed.headers) {
    const name = header.name.trim();
    const normalized = name.toLowerCase();
    if (normalized === 'cookie') continue;
    if (ignoredHeaderNames.has(normalized)) continue;
    if (!isInterestingHeader(normalized)) continue;
    add('header', name, `Request header "${name}"`, header.value, 'medium');
  }
}

function addCookiePoints(parsed: ParsedRawHttp, add: AddPoint) {
  for (const header of parsed.headers.filter((item) => item.name.toLowerCase() === 'cookie')) {
    for (const cookie of header.value.split(';')) {
      const [rawName, ...rawValue] = cookie.split('=');
      const name = rawName.trim();
      if (!name) continue;
      add('cookie', name, `Cookie "${name}"`, rawValue.join('=').trim(), 'high');
    }
  }
}

function addBodyPoints(parsed: ParsedRawHttp, url: URL, add: AddPoint) {
  const body = parsed.body.trim();
  if (!body) return;
  const contentType = headerValue(parsed.headers, 'content-type').toLowerCase();
  let specificBodyPointCount = 0;

  if (contentType.includes('multipart/form-data')) {
    specificBodyPointCount += addMultipartPoints(body, contentType, add);
  }

  if (contentType.includes('application/x-www-form-urlencoded')) {
    const form = new URLSearchParams(body);
    for (const [name, value] of form.entries()) {
      add('form', name, `URL-encoded form field "${name}"`, value, 'high');
      specificBodyPointCount += 1;
    }
  }

  const json = parseJsonBody(body, contentType);
  if (json.ok) {
    for (const leaf of collectJsonLeaves(json.value)) {
      add('json', leaf.path, `JSON body field "${leaf.path}"`, leaf.value, 'high');
      specificBodyPointCount += 1;
    }
    specificBodyPointCount += addGraphqlPointsFromJson(json.value, url, add);
  } else if (looksLikeGraphqlBody(body, contentType, url)) {
    add('graphql', 'operation', 'GraphQL operation body', body, 'medium');
    specificBodyPointCount += 1;
  }

  if (contentType.includes('xml') || /^<\?xml|^<[A-Za-z_][\w:.-]*(?:\s|>)/.test(body)) {
    specificBodyPointCount += addXmlPoints(body, add);
  }

  if (specificBodyPointCount === 0) {
    add('body', 'request-body', `Raw request body (${contentType || 'unknown content type'})`, body, 'low');
  }
}

function addMultipartPoints(body: string, contentType: string, add: AddPoint) {
  const boundary = contentType.match(/boundary="?([^";]+)"?/i)?.[1];
  if (!boundary) return 0;
  let count = 0;
  for (const rawPart of body.split(`--${boundary}`)) {
    const part = rawPart.trim();
    if (!part || part === '--') continue;
    const parsed = parsePart(part);
    const disposition = headerValue(parsed.headers, 'content-disposition');
    const name = disposition.match(/\bname="([^"]+)"/i)?.[1];
    if (!name) continue;
    const filename = disposition.match(/\bfilename="([^"]*)"/i)?.[1];
    add('multipart', name, filename ? `Multipart file field "${name}" filename "${filename}"` : `Multipart field "${name}"`, parsed.body.trim(), 'high');
    count += 1;
  }
  return count;
}

function addGraphqlPointsFromJson(value: unknown, url: URL, add: AddPoint) {
  if (!isRecord(value)) return 0;
  const pathHintsGraphql = /graphql/i.test(url.pathname);
  let count = 0;
  if (typeof value.query === 'string' && (pathHintsGraphql || /\b(query|mutation|subscription)\b|__schema/i.test(value.query))) {
    add('graphql', 'query', 'GraphQL query document', value.query, 'high');
    count += 1;
  }
  if (typeof value.operationName === 'string') {
    add('graphql', 'operationName', 'GraphQL operation name', value.operationName, 'high');
    count += 1;
  }
  if (isRecord(value.variables)) {
    for (const leaf of collectJsonLeaves(value.variables, ['variables'])) {
      add('graphql', leaf.path, `GraphQL variable "${leaf.path}"`, leaf.value, 'high');
      count += 1;
    }
  }
  return count;
}

function addXmlPoints(body: string, add: AddPoint) {
  let count = 0;
  const attributePattern = /<([A-Za-z_][\w:.-]*)([^<>]*?)>/g;
  let attrMatch: RegExpExecArray | null;
  while ((attrMatch = attributePattern.exec(body)) !== null) {
    const tag = attrMatch[1];
    const attrs = attrMatch[2] ?? '';
    const attrPattern = /([A-Za-z_][\w:.-]*)\s*=\s*"([^"]*)"/g;
    let match: RegExpExecArray | null;
    while ((match = attrPattern.exec(attrs)) !== null) {
      add('xml', `${tag}@${match[1]}`, `XML attribute "${match[1]}" on <${tag}>`, match[2], 'medium');
      count += 1;
    }
  }

  const textPattern = /<([A-Za-z_][\w:.-]*)(?:\s[^<>]*?)?>([^<>]{1,500})<\/\1>/g;
  let textMatch: RegExpExecArray | null;
  while ((textMatch = textPattern.exec(body)) !== null) {
    const value = textMatch[2].trim();
    if (!value) continue;
    add('xml', textMatch[1], `XML text node <${textMatch[1]}>`, value, 'medium');
    count += 1;
  }
  return count;
}

type AddPoint = (
  type: CrawlInsertionPointType,
  name: string,
  evidence: string,
  originalValue: unknown,
  confidence: ExtractedInsertionPoint['confidence'],
) => void;

function pointAdder(points: ExtractedInsertionPoint[], exchange: HttpExchange, parsed: ParsedRawHttp, url: URL): AddPoint {
  return (type, name, evidence, originalValue, confidence) => {
    const valuePreview = previewValue(originalValue);
    const routeId = `route-${simpleDigest(`${exchange.method}|${url.host}|${url.pathname}`).slice(0, 12)}`;
    const route = `${exchange.method.toUpperCase()} ${url.pathname}${url.search}`;
    points.push({
      id: `ip-${simpleDigest(`${exchange.id}|${type}|${name}|${evidence}|${valuePreview}`).slice(0, 16)}`,
      routeId,
      exchangeId: exchange.id,
      type,
      location: type,
      parameter: name,
      name,
      method: parsed.method || exchange.method,
      url: url.toString(),
      route,
      evidence,
      valuePreview,
      originalValue,
      confidence,
      risk: riskForPoint(type, name, evidence),
      notes: `${type} insertion point from ${exchange.id}; raw executor material is preserved until report/export redaction.`,
    });
  };
}

function parseRawHttp(raw: string): ParsedRawHttp {
  const normalized = raw.replace(/\r\n/g, '\n');
  const separator = normalized.indexOf('\n\n');
  const head = separator >= 0 ? normalized.slice(0, separator) : normalized;
  const body = separator >= 0 ? normalized.slice(separator + 2) : '';
  const lines = head.split('\n');
  const startLine = lines.shift()?.trim() ?? '';
  const headers: Array<{ name: string; value: string }> = [];
  for (const line of lines) {
    if (/^\s/.test(line) && headers.length) {
      headers[headers.length - 1].value = `${headers[headers.length - 1].value} ${line.trim()}`;
      continue;
    }
    const index = line.indexOf(':');
    if (index <= 0) continue;
    headers.push({ name: line.slice(0, index).trim(), value: line.slice(index + 1).trim() });
  }
  const startMatch = startLine.match(/^([A-Z]+)\s+(\S+)/i);
  return {
    startLine,
    method: startMatch?.[1]?.toUpperCase() ?? 'GET',
    target: startMatch?.[2] ?? '/',
    headers,
    body,
  };
}

function parsePart(raw: string): ParsedRawHttp {
  const normalized = raw.replace(/\r\n/g, '\n');
  const separator = normalized.indexOf('\n\n');
  const head = separator >= 0 ? normalized.slice(0, separator) : normalized;
  const body = separator >= 0 ? normalized.slice(separator + 2) : '';
  const headers = head.split('\n').flatMap((line) => {
    const index = line.indexOf(':');
    return index > 0 ? [{ name: line.slice(0, index).trim(), value: line.slice(index + 1).trim() }] : [];
  });
  return { startLine: '', method: '', target: '', headers, body };
}

function resolveExchangeUrl(exchange: HttpExchange, parsed: ParsedRawHttp): URL {
  try {
    return new URL(exchange.url);
  } catch {
    const host = headerValue(parsed.headers, 'host') || exchange.host || 'target.invalid';
    const target = parsed.target || exchange.path || '/';
    if (/^https?:\/\//i.test(target)) return new URL(target);
    return new URL(target.startsWith('/') ? target : `/${target}`, `https://${host}`);
  }
}

function headerValue(headers: Array<{ name: string; value: string }>, target: string) {
  const normalized = target.toLowerCase();
  return headers.find((header) => header.name.toLowerCase() === normalized)?.value ?? '';
}

function parseJsonBody(body: string, contentType: string): { ok: true; value: unknown } | { ok: false } {
  if (!contentType.includes('json') && !/^\s*[\[{]/.test(body)) return { ok: false };
  try {
    return { ok: true, value: JSON.parse(body) };
  } catch {
    return { ok: false };
  }
}

function collectJsonLeaves(value: unknown, basePath: string[] = []): Array<{ path: string; value: unknown }> {
  if (Array.isArray(value)) {
    return value.flatMap((item, index) => collectJsonLeaves(item, [...basePath, `[${index}]`]));
  }
  if (isRecord(value)) {
    const leaves = Object.entries(value).flatMap(([key, item]) => collectJsonLeaves(item, [...basePath, key]));
    return leaves.length ? leaves : [{ path: basePath.join('.') || '$', value }];
  }
  return [{ path: basePath.join('.').replace(/\.\[/g, '[') || '$', value }];
}

function looksLikeGraphqlBody(body: string, contentType: string, url: URL) {
  return contentType.includes('graphql')
    || /graphql/i.test(url.pathname)
    || /\b(query|mutation|subscription)\s+[A-Za-z0-9_]*\s*\{|\b__schema\b/.test(body);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isDynamicPathSegment(segment: string) {
  if (!segment || segment.length > 96) return false;
  return /\d/.test(segment)
    || /^[0-9a-f]{8,}$/i.test(segment)
    || /^(ord|order|usr|user|acct|acc|rf|sid|sess|token|jwt|id)[_-]?[A-Za-z0-9_-]+$/i.test(segment);
}

function isInterestingHeader(name: string) {
  return name === 'authorization'
    || name === 'idempotency-key'
    || name === 'x-api-key'
    || name === 'x-csrf-token'
    || name === 'x-requested-with'
    || name === 'origin'
    || name.startsWith('x-');
}

function riskForPoint(type: CrawlInsertionPointType, name: string, evidence: string): Severity {
  const haystack = `${type} ${name} ${evidence}`.toLowerCase();
  if (/authorization|cookie|csrf|api-key|token|graphql|amount|role|admin|idempotency/.test(haystack)) return 'high';
  if (/json|xml|multipart|path|redirect|url|file|cmd|query/.test(haystack)) return 'medium';
  return 'info';
}

function previewValue(value: unknown) {
  if (typeof value === 'string') return value.slice(0, 240);
  if (value === undefined) return '';
  try {
    return JSON.stringify(value).slice(0, 240);
  } catch {
    return String(value).slice(0, 240);
  }
}

function dedupePoints(points: ExtractedInsertionPoint[]) {
  const seen = new Set<string>();
  const deduped: ExtractedInsertionPoint[] = [];
  for (const point of points) {
    const key = `${point.exchangeId}|${point.type}|${point.name}|${point.url}`.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(point);
  }
  return deduped;
}

function hasType(points: ExtractedInsertionPoint[], type: CrawlInsertionPointType) {
  return points.some((point) => point.type === type);
}

function clampInteger(value: number, min: number, max: number) {
  if (!Number.isFinite(value)) return min;
  return Math.min(max, Math.max(min, Math.trunc(value)));
}

function simpleDigest(value: string) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `${hash.toString(16).padStart(8, '0')}${value.length.toString(16).padStart(8, '0')}`;
}
