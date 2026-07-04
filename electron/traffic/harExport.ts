// HAR 1.2 export for captured HTTP exchanges.

export interface HarEntry {
  startedDateTime: string;
  time: number;
  request: HarRequest;
  response: HarResponse;
  cache: Record<string, never>;
  timings: { send: number; wait: number; receive: number };
}

export interface HarRequest {
  method: string;
  url: string;
  httpVersion: string;
  cookies: Array<{ name: string; value: string }>;
  headers: Array<{ name: string; value: string }>;
  queryString: Array<{ name: string; value: string }>;
  postData?: { mimeType: string; text: string };
  headersSize: number;
  bodySize: number;
}

export interface HarResponse {
  status: number;
  statusText: string;
  httpVersion: string;
  cookies: Array<{ name: string; value: string }>;
  headers: Array<{ name: string; value: string }>;
  content: { size: number; mimeType: string; text?: string };
  redirectURL: string;
  headersSize: number;
  bodySize: number;
}

export interface HarLog {
  version: '1.2';
  creator: { name: string; version: string };
  pages?: unknown[];
  entries: HarEntry[];
}

export interface HarDocument {
  log: HarLog;
}

export interface ExchangeForHar {
  id?: string;
  url: string;
  method: string;
  status?: number;
  requestRaw?: string;
  responseRaw?: string;
  createdAt?: string;
  host?: string;
  path?: string;
}

function parseHeaders(raw: string): Array<{ name: string; value: string }> {
  const sep = raw.indexOf('\n\n');
  const head = sep >= 0 ? raw.slice(0, sep) : raw;
  const lines = head.split('\n').slice(1);
  return lines.flatMap((line) => {
    const idx = line.indexOf(':');
    if (idx <= 0) return [];
    return [{ name: line.slice(0, idx).trim(), value: line.slice(idx + 1).trim() }];
  });
}

function extractBody(raw: string): string {
  const sep = raw.indexOf('\n\n');
  return sep >= 0 ? raw.slice(sep + 2) : '';
}

function parseCookies(raw: string): Array<{ name: string; value: string }> {
  const header = raw.split('\n').find((line) => /^cookie:/i.test(line));
  if (!header) return [];
  return header.split(':').slice(1).join(':').split(';').flatMap((part) => {
    const eq = part.indexOf('=');
    if (eq <= 0) return [];
    return [{ name: part.slice(0, eq).trim(), value: part.slice(eq + 1).trim() }];
  });
}

function parseSetCookies(raw: string): Array<{ name: string; value: string }> {
  return raw.split('\n')
    .filter((line) => /^set-cookie:/i.test(line))
    .flatMap((line) => {
      const val = line.split(':').slice(1).join(':').trim().split(';')[0];
      const eq = val.indexOf('=');
      if (eq <= 0) return [];
      return [{ name: val.slice(0, eq).trim(), value: val.slice(eq + 1).trim() }];
    });
}

function parseQueryString(url: string): Array<{ name: string; value: string }> {
  try {
    const urlObj = new URL(url);
    return Array.from(urlObj.searchParams.entries()).map(([name, value]) => ({ name, value }));
  } catch {
    return [];
  }
}

function detectMimeType(headers: Array<{ name: string; value: string }>): string {
  return headers.find((h) => h.name.toLowerCase() === 'content-type')?.value ?? 'text/plain';
}

function httpVersion(raw: string): string {
  const match = raw.match(/HTTP\/(\d\.\d)/);
  return match ? `HTTP/${match[1]}` : 'HTTP/1.1';
}

export function exchangeToHarEntry(exchange: ExchangeForHar): HarEntry {
  const requestRaw = exchange.requestRaw ?? '';
  const responseRaw = exchange.responseRaw ?? '';

  const requestHeaders = parseHeaders(requestRaw);
  const responseHeaders = parseHeaders(responseRaw);
  const requestBody = extractBody(requestRaw);
  const responseBody = extractBody(responseRaw);
  const requestMime = detectMimeType(requestHeaders);
  const responseMime = detectMimeType(responseHeaders);
  const statusMatch = responseRaw.match(/^HTTP\/\d\.\d\s+(\d+)\s+(.+)/);

  return {
    startedDateTime: exchange.createdAt ?? new Date().toISOString(),
    time: 0,
    request: {
      method: exchange.method ?? 'GET',
      url: exchange.url ?? '',
      httpVersion: httpVersion(requestRaw),
      cookies: parseCookies(requestRaw),
      headers: requestHeaders,
      queryString: parseQueryString(exchange.url ?? ''),
      ...(requestBody ? { postData: { mimeType: requestMime, text: requestBody } } : {}),
      headersSize: requestRaw.indexOf('\n\n') >= 0 ? requestRaw.indexOf('\n\n') : -1,
      bodySize: requestBody.length,
    },
    response: {
      status: exchange.status ?? parseInt(statusMatch?.[1] ?? '200'),
      statusText: statusMatch?.[2] ?? 'OK',
      httpVersion: httpVersion(responseRaw),
      cookies: parseSetCookies(responseRaw),
      headers: responseHeaders,
      content: {
        size: responseBody.length,
        mimeType: responseMime,
        text: responseBody || undefined,
      },
      redirectURL: responseHeaders.find((h) => h.name.toLowerCase() === 'location')?.value ?? '',
      headersSize: responseRaw.indexOf('\n\n') >= 0 ? responseRaw.indexOf('\n\n') : -1,
      bodySize: responseBody.length,
    },
    cache: {},
    timings: { send: 0, wait: 0, receive: 0 },
  };
}

export function exportToHar(exchanges: ExchangeForHar[], projectName = 'ProxyForge Export'): HarDocument {
  return {
    log: {
      version: '1.2',
      creator: { name: 'ProxyForge', version: '1.0.0' },
      pages: [],
      entries: exchanges.map(exchangeToHarEntry),
    },
  };
}

export function harToJson(har: HarDocument): string {
  return JSON.stringify(har, null, 2);
}
