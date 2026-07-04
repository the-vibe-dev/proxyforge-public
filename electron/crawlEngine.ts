import http from 'node:http';
import https from 'node:https';
import { performance } from 'node:perf_hooks';

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

interface HttpExchange {
  id: string;
  method: string;
  host: string;
  path: string;
  url: string;
  status: number;
  length: number;
  mime: string;
  risk: Severity;
  timing: number;
  notes: string;
  source: 'proxy' | 'repeater' | 'scanner' | 'crawler' | 'demo';
  time: string;
  requestRaw: string;
  responseRaw: string;
  tags: string[];
}

export type CrawlRouteSource = 'seed' | 'link' | 'script' | 'form' | 'redirect';
export type CrawlInsertionPointType =
  | 'query'
  | 'form'
  | 'path'
  | 'cookie'
  | 'header'
  | 'body'
  | 'json'
  | 'xml'
  | 'multipart'
  | 'graphql';

export interface CrawlRequest {
  startUrl: string;
  scopeAllowlist: string[];
  maxDepth: number;
  maxPages: number;
  throttleMs: number;
  userAgent: string;
  includeForms: boolean;
  headers?: Record<string, string>;
}

export type CrawlerTlsMode = 'strict' | 'relaxed';

export interface CrawlInsertionPoint {
  id: string;
  routeId: string;
  type: CrawlInsertionPointType;
  name: string;
  method: string;
  url: string;
  evidence: string;
}

export interface CrawlRoute {
  id: string;
  method: string;
  url: string;
  host: string;
  path: string;
  status: number;
  mime: string;
  depth: number;
  source: CrawlRouteSource;
  parentUrl?: string;
  title: string;
  discoveredAt: string;
  insertionPoints: string[];
}

export interface CrawlSummary {
  id: string;
  startUrl: string;
  startedAt: string;
  completedAt: string;
  totalRequests: number;
  blocked: boolean;
  message: string;
  routes: CrawlRoute[];
  insertionPoints: CrawlInsertionPoint[];
  exchanges: HttpExchange[];
}

interface QueueItem {
  url: URL;
  depth: number;
  source: CrawlRouteSource;
  parentUrl?: string;
}

interface FetchedPage {
  status: number;
  mime: string;
  body: string;
  title: string;
  timing: number;
  responseRaw: string;
  exchange: HttpExchange;
  redirectUrl?: URL;
}

const MAX_CRAWLER_RESPONSE_BYTES = 1024 * 1024;

export class CrawlEngine {
  constructor(private readonly options: { upstreamTlsMode?: () => CrawlerTlsMode } = {}) {}

  async runCrawl(request: CrawlRequest): Promise<CrawlSummary> {
    const startedAt = new Date();
    const normalized = normalizeCrawlRequest(request);
    const routes: CrawlRoute[] = [];
    const insertionPoints: CrawlInsertionPoint[] = [];
    const exchanges: HttpExchange[] = [];
    let start: URL;

    try {
      start = new URL(normalized.startUrl);
    } catch {
      return crawlSummary(normalized, startedAt, true, 'Crawler blocked: start URL is invalid', routes, insertionPoints, exchanges);
    }

    if (!isAllowedHost(start.hostname, normalized.scopeAllowlist)) {
      return crawlSummary(normalized, startedAt, true, `Crawler blocked by project scope: ${start.hostname}`, routes, insertionPoints, exchanges);
    }

    const queue: QueueItem[] = [{ url: start, depth: 0, source: 'seed' }];
    const visited = new Set<string>();
    const routeKeys = new Set<string>();

    while (queue.length > 0 && exchanges.length < normalized.maxPages) {
      const item = queue.shift();
      if (!item) break;
      if (!isHttpUrl(item.url) || !isAllowedHost(item.url.hostname, normalized.scopeAllowlist)) continue;

      const visitKey = canonicalUrlKey(item.url);
      if (visited.has(visitKey)) continue;
      visited.add(visitKey);

      let fetched: FetchedPage;
      try {
        fetched = await fetchPage(item.url, normalized.userAgent, normalized.headers ?? {}, this.upstreamTlsMode() === 'strict');
      } catch (error) {
        fetched = makeFailedPage(item.url, normalized.userAgent, normalized.headers ?? {}, error);
      }

      exchanges.push(fetched.exchange);
      const route = makeRoute(item, fetched);
      addRoute(route, routes, routeKeys);
      addUrlInsertionPoints(route, insertionPoints);

      if (fetched.redirectUrl && item.depth + 1 <= normalized.maxDepth) {
        queue.push({ url: fetched.redirectUrl, depth: item.depth + 1, source: 'redirect', parentUrl: item.url.toString() });
      }

      if (fetched.mime.includes('html')) {
        if (normalized.includeForms) {
          for (const form of extractForms(fetched.body, item.url)) {
            const formRoute = makeFormRoute(form, item.depth, item.url.toString());
            addRoute(formRoute, routes, routeKeys);
            addFormInsertionPoints(formRoute, form.inputs, insertionPoints);
          }
        }

        if (item.depth + 1 <= normalized.maxDepth) {
          for (const discovered of extractResourceUrls(fetched.body, item.url)) {
            if (queue.length + exchanges.length >= normalized.maxPages) break;
            if (!isAllowedHost(discovered.url.hostname, normalized.scopeAllowlist)) continue;
            if (visited.has(canonicalUrlKey(discovered.url))) continue;
            queue.push({
              url: discovered.url,
              depth: item.depth + 1,
              source: discovered.source,
              parentUrl: item.url.toString(),
            });
          }
        }
      }

      if (normalized.throttleMs > 0 && queue.length > 0 && exchanges.length < normalized.maxPages) {
        await delay(normalized.throttleMs);
      }
    }

    const message = `Crawler discovered ${routes.length} route${routes.length === 1 ? '' : 's'}, ${insertionPoints.length} insertion point${insertionPoints.length === 1 ? '' : 's'}, and fetched ${exchanges.length} page${exchanges.length === 1 ? '' : 's'}`;
    return crawlSummary(normalized, startedAt, false, message, routes, insertionPoints, exchanges);
  }

  private upstreamTlsMode(): CrawlerTlsMode {
    return this.options.upstreamTlsMode?.() === 'relaxed' ? 'relaxed' : 'strict';
  }
}

function normalizeCrawlRequest(request: CrawlRequest): CrawlRequest {
  return {
    startUrl: request.startUrl,
    scopeAllowlist: request.scopeAllowlist.filter(Boolean),
    maxDepth: clampInteger(request.maxDepth, 0, 4),
    maxPages: clampInteger(request.maxPages, 1, 100),
    throttleMs: clampInteger(request.throttleMs, 0, 5000),
    userAgent: request.userAgent || 'ProxyForge Crawler',
    includeForms: request.includeForms,
    headers: normalizeCrawlHeaders(request.headers),
  };
}

function crawlSummary(
  request: CrawlRequest,
  startedAt: Date,
  blocked: boolean,
  message: string,
  routes: CrawlRoute[],
  insertionPoints: CrawlInsertionPoint[],
  exchanges: HttpExchange[],
): CrawlSummary {
  return {
    id: `crawl-${startedAt.getTime()}-${Math.random().toString(16).slice(2)}`,
    startUrl: request.startUrl,
    startedAt: startedAt.toISOString(),
    completedAt: new Date().toISOString(),
    totalRequests: exchanges.length,
    blocked,
    message,
    routes,
    insertionPoints,
    exchanges,
  };
}

function normalizeCrawlHeaders(headers: Record<string, string> | undefined) {
  const normalized = new Map<string, { name: string; value: string }>();
  for (const [name, value] of Object.entries(headers ?? {})) {
    const headerName = normalizeHeaderName(name);
    const headerValue = normalizeHeaderValue(value);
    if (!headerName || !headerValue || isForbiddenCrawlHeader(headerName)) continue;
    normalized.set(headerName.toLowerCase(), { name: headerName, value: headerValue });
  }
  return Object.fromEntries(Array.from(normalized.values()).map((entry) => [entry.name, entry.value]));
}

function mergeRequestHeaders(base: Record<string, string>, extra: Record<string, string>) {
  const merged = new Map<string, { name: string; value: string }>();
  for (const [name, value] of Object.entries(base)) {
    const headerName = normalizeHeaderName(name);
    const headerValue = normalizeHeaderValue(value);
    if (!headerName || !headerValue) continue;
    merged.set(headerName.toLowerCase(), { name: headerName, value: headerValue });
  }
  for (const [name, value] of Object.entries(extra)) {
    const headerName = normalizeHeaderName(name);
    const headerValue = normalizeHeaderValue(value);
    if (!headerName || !headerValue || isForbiddenCrawlHeader(headerName)) continue;
    merged.set(headerName.toLowerCase(), { name: headerName, value: headerValue });
  }
  merged.set('host', { name: 'host', value: base.host });
  return Object.fromEntries(Array.from(merged.values()).map((entry) => [entry.name, entry.value]));
}

function renderRequestRaw(method: string, requestPath: string, headers: Record<string, string>) {
  return [
    `${method} ${requestPath || '/'} HTTP/1.1`,
    ...Object.entries(headers).map(([name, value]) => `${name}: ${value}`),
    '',
    '',
  ].join('\n');
}

function normalizeHeaderName(name: string) {
  const trimmed = name.trim();
  if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(trimmed)) return '';
  return trimmed;
}

function normalizeHeaderValue(value: unknown) {
  const text = String(value ?? '').trim();
  if (!text || /[\r\n]/.test(text)) return '';
  return text;
}

function isForbiddenCrawlHeader(name: string) {
  return /^(host|content-length|transfer-encoding|connection|proxy-connection|proxy-authorization)$/i.test(name);
}

function fetchPage(target: URL, userAgent: string, sessionHeaders: Record<string, string>, rejectUnauthorized: boolean): Promise<FetchedPage> {
  const started = performance.now();
  const transport = target.protocol === 'https:' ? https : http;
  const requestPath = `${target.pathname}${target.search}`;
  const headers = mergeRequestHeaders({
    host: target.host,
    'user-agent': userAgent,
    accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  }, sessionHeaders);
  const requestRaw = renderRequestRaw('GET', requestPath || '/', headers);

  return new Promise((resolve, reject) => {
    const upstream = transport.request({
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port || (target.protocol === 'https:' ? 443 : 80),
      method: 'GET',
      path: requestPath || '/',
      headers,
      ...(target.protocol === 'https:' ? { rejectUnauthorized } : {}),
    }, (response) => {
      const chunks: Buffer[] = [];
      let totalBytes = 0;
      let retainedBytes = 0;
      let truncated = false;
      response.on('data', (chunk: Buffer) => {
        totalBytes += chunk.byteLength;
        if (retainedBytes >= MAX_CRAWLER_RESPONSE_BYTES) {
          truncated = true;
          return;
        }
        const remaining = MAX_CRAWLER_RESPONSE_BYTES - retainedBytes;
        if (chunk.byteLength > remaining) {
          chunks.push(chunk.subarray(0, remaining));
          retainedBytes += remaining;
          truncated = true;
          return;
        }
        chunks.push(chunk);
        retainedBytes += chunk.byteLength;
      });
      response.on('end', () => {
        const buffer = Buffer.concat(chunks);
        const body = buffer.toString('utf8');
        const status = response.statusCode ?? 0;
        const mime = String(response.headers['content-type'] ?? 'application/octet-stream').split(';', 1)[0] || 'application/octet-stream';
        const timing = Math.round(performance.now() - started);
        const responseRaw = renderResponseRaw(response, truncated ? `${body}\n\n[ProxyForge crawler capture truncated at ${MAX_CRAWLER_RESPONSE_BYTES} bytes; upstream response was ${totalBytes} bytes.]` : body);
        const redirect = response.headers.location ? safeUrl(response.headers.location, target) : undefined;
        const tags = ['crawler', 'content-discovery', target.protocol.replace(':', '')];
        if (truncated) tags.push('capture-truncated');

        resolve({
          status,
          mime,
          body,
          title: extractTitle(body),
          timing,
          responseRaw,
          redirectUrl: redirect,
          exchange: {
            id: `crawl-exchange-${Date.now()}-${Math.random().toString(16).slice(2)}`,
            method: 'GET',
            host: target.host,
            path: requestPath || '/',
            url: target.toString(),
            status,
            length: totalBytes,
            mime,
            risk: status >= 500 ? 'medium' : 'info',
            timing,
            notes: truncated
              ? `Crawler discovery fetch truncated after ${MAX_CRAWLER_RESPONSE_BYTES} bytes; upstream response was ${totalBytes} bytes`
              : status >= 300 && status < 400 ? 'Crawler followed redirect candidate' : 'Crawler discovery fetch',
            source: 'crawler',
            time: new Date().toLocaleTimeString([], { hour12: false }),
            requestRaw,
            responseRaw,
            tags,
          },
        });
      });
    });

    upstream.setTimeout(15000, () => {
      upstream.destroy(new Error('Crawler request timed out'));
    });
    upstream.on('error', reject);
    upstream.end();
  });
}

function makeFailedPage(target: URL, userAgent: string, sessionHeaders: Record<string, string>, error: unknown): FetchedPage {
  const message = error instanceof Error ? error.message : 'Crawler request failed';
  const requestPath = `${target.pathname}${target.search}` || '/';
  const requestRaw = renderRequestRaw('GET', requestPath, mergeRequestHeaders({
    host: target.host,
    'user-agent': userAgent,
    accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  }, sessionHeaders));
  return {
    status: 0,
    mime: 'error',
    body: '',
    title: 'Request failed',
    timing: 0,
    responseRaw: message,
    exchange: {
      id: `crawl-error-${Date.now()}-${Math.random().toString(16).slice(2)}`,
      method: 'GET',
      host: target.host,
      path: requestPath,
      url: target.toString(),
      status: 0,
      length: 0,
      mime: 'error',
      risk: 'low',
      timing: 0,
      notes: `Crawler fetch failed: ${message}`,
      source: 'crawler',
      time: new Date().toLocaleTimeString([], { hour12: false }),
      requestRaw,
      responseRaw: message,
      tags: ['crawler', 'fetch-error'],
    },
  };
}

function makeRoute(item: QueueItem, fetched: FetchedPage): CrawlRoute {
  return {
    id: routeId('GET', item.url),
    method: 'GET',
    url: item.url.toString(),
    host: item.url.host,
    path: `${item.url.pathname}${item.url.search}` || '/',
    status: fetched.status,
    mime: fetched.mime,
    depth: item.depth,
    source: item.source,
    parentUrl: item.parentUrl,
    title: fetched.title || item.url.pathname || '/',
    discoveredAt: new Date().toISOString(),
    insertionPoints: [],
  };
}

function makeFormRoute(form: ExtractedForm, depth: number, parentUrl: string): CrawlRoute {
  return {
    id: routeId(form.method, form.url),
    method: form.method,
    url: form.url.toString(),
    host: form.url.host,
    path: `${form.url.pathname}${form.url.search}` || '/',
    status: 0,
    mime: 'form',
    depth: depth + 1,
    source: 'form',
    parentUrl,
    title: form.name || 'HTML form',
    discoveredAt: new Date().toISOString(),
    insertionPoints: [],
  };
}

function addRoute(route: CrawlRoute, routes: CrawlRoute[], routeKeys: Set<string>) {
  const key = `${route.method}:${canonicalUrlKey(new URL(route.url))}`;
  if (routeKeys.has(key)) return;
  routeKeys.add(key);
  routes.push(route);
}

function addUrlInsertionPoints(route: CrawlRoute, insertionPoints: CrawlInsertionPoint[]) {
  const url = new URL(route.url);
  for (const [name] of url.searchParams) {
    const point = makeInsertionPoint(route, 'query', name, `URL query parameter "${name}"`);
    route.insertionPoints.push(point.id);
    insertionPoints.push(point);
  }

  const pathSegments = url.pathname.split('/').filter(Boolean);
  pathSegments.forEach((segment, index) => {
    if (!/[0-9_-]/.test(segment)) return;
    const point = makeInsertionPoint(route, 'path', `segment-${index + 1}`, `Path segment "${segment}"`);
    route.insertionPoints.push(point.id);
    insertionPoints.push(point);
  });
}

function addFormInsertionPoints(route: CrawlRoute, inputs: string[], insertionPoints: CrawlInsertionPoint[]) {
  for (const name of inputs) {
    const point = makeInsertionPoint(route, 'form', name, `HTML form field "${name}"`);
    route.insertionPoints.push(point.id);
    insertionPoints.push(point);
  }
}

function makeInsertionPoint(route: CrawlRoute, type: CrawlInsertionPointType, name: string, evidence: string): CrawlInsertionPoint {
  return {
    id: `ip-${hashValue(`${route.id}:${type}:${name}`)}`,
    routeId: route.id,
    type,
    name,
    method: route.method,
    url: route.url,
    evidence,
  };
}

interface ExtractedResource {
  url: URL;
  source: CrawlRouteSource;
}

function extractResourceUrls(html: string, baseUrl: URL): ExtractedResource[] {
  const resources: ExtractedResource[] = [];
  const seen = new Set<string>();
  const pattern = /\b(href|src)\s*=\s*["']([^"']+)["']/gi;
  let match: RegExpExecArray | null;

  while ((match = pattern.exec(html)) !== null) {
    const [, attribute, value] = match;
    const url = safeUrl(value, baseUrl);
    if (!url || !isHttpUrl(url)) continue;
    const key = canonicalUrlKey(url);
    if (seen.has(key)) continue;
    seen.add(key);
    resources.push({ url, source: attribute.toLowerCase() === 'src' ? 'script' : 'link' });
  }

  return resources;
}

interface ExtractedForm {
  method: string;
  url: URL;
  name: string;
  inputs: string[];
}

function extractForms(html: string, baseUrl: URL): ExtractedForm[] {
  const forms: ExtractedForm[] = [];
  const formPattern = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let formMatch: RegExpExecArray | null;

  while ((formMatch = formPattern.exec(html)) !== null) {
    const attrs = formMatch[1] ?? '';
    const body = formMatch[2] ?? '';
    const method = (extractAttribute(attrs, 'method') || 'GET').toUpperCase();
    const action = extractAttribute(attrs, 'action') || baseUrl.pathname;
    const url = safeUrl(action, baseUrl);
    if (!url || !isHttpUrl(url)) continue;

    forms.push({
      method: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(method) ? method : 'GET',
      url,
      name: extractAttribute(attrs, 'name') || extractAttribute(attrs, 'id') || `${method} ${url.pathname}`,
      inputs: extractInputNames(body),
    });
  }

  return forms;
}

function extractInputNames(formBody: string) {
  const names = new Set<string>();
  const inputPattern = /<(?:input|textarea|select|button)\b([^>]*)>/gi;
  let match: RegExpExecArray | null;
  while ((match = inputPattern.exec(formBody)) !== null) {
    const name = extractAttribute(match[1] ?? '', 'name') || extractAttribute(match[1] ?? '', 'id');
    if (name) names.add(name);
  }
  return Array.from(names);
}

function extractAttribute(attrs: string, name: string) {
  const pattern = new RegExp(`\\b${name}\\s*=\\s*["']([^"']+)["']`, 'i');
  return pattern.exec(attrs)?.[1]?.trim() ?? '';
}

function extractTitle(html: string) {
  return /<title[^>]*>([\s\S]*?)<\/title>/i.exec(html)?.[1]?.replace(/\s+/g, ' ').trim() ?? '';
}

function renderResponseRaw(response: http.IncomingMessage, body: string) {
  const status = response.statusCode ?? 0;
  const lines = [`HTTP/${response.httpVersion} ${status} ${response.statusMessage ?? ''}`.trimEnd()];
  for (const [key, value] of Object.entries(response.headers)) {
    if (Array.isArray(value)) {
      for (const item of value) lines.push(`${key}: ${item}`);
    } else if (value !== undefined) {
      lines.push(`${key}: ${value}`);
    }
  }
  lines.push('', body);
  return lines.join('\n');
}

function safeUrl(value: string, baseUrl: URL) {
  const trimmed = value.trim();
  if (!trimmed || /^(?:javascript|mailto|tel|data):/i.test(trimmed) || trimmed.startsWith('#')) return undefined;
  try {
    return new URL(trimmed, baseUrl);
  } catch {
    return undefined;
  }
}

function isHttpUrl(url: URL) {
  return url.protocol === 'http:' || url.protocol === 'https:';
}

function isAllowedHost(hostname: string, allowlist: string[]) {
  if (allowlist.includes('*')) return true;
  return allowlist.some((pattern) => {
    const normalized = pattern.trim().toLowerCase();
    const host = hostname.toLowerCase();
    if (!normalized) return false;
    if (normalized.startsWith('*.')) {
      const suffix = normalized.slice(1);
      return host.endsWith(suffix) || host === normalized.slice(2);
    }
    return host === normalized || host.endsWith(`.${normalized}`);
  });
}

function canonicalUrlKey(url: URL) {
  const copy = new URL(url.toString());
  copy.hash = '';
  return copy.toString();
}

function routeId(method: string, url: URL) {
  return `route-${hashValue(`${method}:${canonicalUrlKey(url)}`)}`;
}

function hashValue(value: string) {
  let hash = 0;
  for (let index = 0; index < value.length; index += 1) {
    hash = Math.imul(31, hash) + value.charCodeAt(index);
  }
  return Math.abs(hash).toString(36);
}

function clampInteger(value: number, min: number, max: number) {
  if (!Number.isFinite(value)) return min;
  return Math.min(max, Math.max(min, Math.trunc(value)));
}

function delay(ms: number) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}
