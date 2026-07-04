// Cut / field extraction across selected flows.
// Allows operators to extract specific fields from multiple exchanges at once.

export type CutField =
  | 'url'
  | 'method'
  | 'status'
  | 'host'
  | 'path'
  | 'request-header'
  | 'response-header'
  | 'request-body'
  | 'response-body'
  | 'cookie'
  | 'set-cookie'
  | 'query-param'
  | 'json-path';

export interface CutSpec {
  field: CutField;
  headerName?: string;
  queryParam?: string;
  jsonPath?: string;
  cookieName?: string;
}

export interface CutResult {
  exchangeId?: string;
  field: CutField;
  value: string | string[] | null;
}

export interface ExchangeForCut {
  id?: string;
  url?: string;
  method?: string;
  status?: number;
  host?: string;
  path?: string;
  requestRaw?: string;
  responseRaw?: string;
}

function getHeader(raw: string, name: string): string | null {
  const normalized = name.toLowerCase();
  const lines = raw.split('\n');
  for (const line of lines) {
    const idx = line.indexOf(':');
    if (idx <= 0) continue;
    if (line.slice(0, idx).trim().toLowerCase() === normalized) {
      return line.slice(idx + 1).trim();
    }
  }
  return null;
}

function extractBody(raw: string): string {
  const sep = raw.indexOf('\n\n');
  return sep >= 0 ? raw.slice(sep + 2) : '';
}

function getCookieValue(raw: string, cookieName: string): string | null {
  const cookieHeader = getHeader(raw, 'cookie') ?? '';
  for (const pair of cookieHeader.split(';')) {
    const [name, ...value] = pair.split('=');
    if (name.trim() === cookieName) return value.join('=').trim();
  }
  return null;
}

function getJsonPath(body: string, jsonPath: string): string | null {
  try {
    let obj: unknown = JSON.parse(body);
    const parts = jsonPath.replace(/^\$\.?/, '').split('.');
    for (const part of parts) {
      if (!isRecord(obj)) return null;
      obj = (obj as Record<string, unknown>)[part];
    }
    return obj === undefined || obj === null ? null : String(obj);
  } catch {
    return null;
  }
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

export function cutExchange(exchange: ExchangeForCut, spec: CutSpec): CutResult {
  const base: Pick<CutResult, 'exchangeId' | 'field'> = { exchangeId: exchange.id, field: spec.field };

  switch (spec.field) {
    case 'url': return { ...base, value: exchange.url ?? null };
    case 'method': return { ...base, value: exchange.method ?? null };
    case 'status': return { ...base, value: exchange.status?.toString() ?? null };
    case 'host': return { ...base, value: exchange.host ?? null };
    case 'path': return { ...base, value: exchange.path ?? null };

    case 'request-header':
      return { ...base, value: spec.headerName ? getHeader(exchange.requestRaw ?? '', spec.headerName) : null };

    case 'response-header':
      return { ...base, value: spec.headerName ? getHeader(exchange.responseRaw ?? '', spec.headerName) : null };

    case 'request-body':
      return { ...base, value: extractBody(exchange.requestRaw ?? '') || null };

    case 'response-body':
      return { ...base, value: extractBody(exchange.responseRaw ?? '') || null };

    case 'cookie':
      return { ...base, value: spec.cookieName ? getCookieValue(exchange.requestRaw ?? '', spec.cookieName) : null };

    case 'query-param': {
      try {
        const url = new URL(exchange.url ?? 'https://x');
        return { ...base, value: spec.queryParam ? (url.searchParams.get(spec.queryParam) ?? null) : null };
      } catch {
        return { ...base, value: null };
      }
    }

    case 'json-path':
      return { ...base, value: spec.jsonPath ? getJsonPath(extractBody(exchange.requestRaw ?? ''), spec.jsonPath) : null };

    default:
      return { ...base, value: null };
  }
}

export function cutExchanges(exchanges: ExchangeForCut[], specs: CutSpec[]): CutResult[][] {
  return exchanges.map((exchange) => specs.map((spec) => cutExchange(exchange, spec)));
}

export function formatCutResults(results: CutResult[][], delimiter = '\t'): string {
  return results.map((row) => row.map((r) => r.value ?? '').join(delimiter)).join('\n');
}
