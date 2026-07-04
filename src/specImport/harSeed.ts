// HAR 1.2 seed importer — converts HAR entries into spec routes for insertion-point seeding.
import type { SpecImportResult, ImportedRoute, ImportedParam } from './index';

interface HarEntry {
  request: {
    method: string;
    url: string;
    headers?: Array<{ name: string; value: string }>;
    queryString?: Array<{ name: string; value: string }>;
    postData?: { mimeType?: string; text?: string; params?: Array<{ name: string; value: string }> };
    cookies?: Array<{ name: string; value: string }>;
  };
  response?: { status?: number };
}

interface HarLog {
  version: string;
  entries: HarEntry[];
  pages?: unknown[];
}

interface HarRoot {
  log: HarLog;
}

export function parseHarSeed(raw: string): SpecImportResult {
  const warnings: string[] = [];
  const routes: ImportedRoute[] = [];

  let doc: HarRoot;
  try {
    doc = JSON.parse(raw) as HarRoot;
  } catch {
    return { format: 'har', routes: [], errors: ['Invalid JSON in HAR file.'] };
  }

  if (!doc?.log?.entries || !Array.isArray(doc.log.entries)) {
    return { format: 'har', routes: [], errors: ['Missing log.entries in HAR.'] };
  }

  const seen = new Set<string>();

  for (const entry of doc.log.entries) {
    const req = entry.request;
    if (!req?.url || !req?.method) continue;

    let urlObj: URL;
    try {
      urlObj = new URL(req.url);
    } catch {
      warnings.push(`Skipped invalid URL: ${req.url}`);
      continue;
    }

    const dedupeKey = `${req.method}:${urlObj.origin}${urlObj.pathname}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);

    const params: ImportedParam[] = [];

    // Query params
    for (const qs of (req.queryString ?? [])) {
      params.push({ name: qs.name, location: 'query', required: false, example: qs.value });
    }

    // Body params
    if (req.postData?.params) {
      for (const p of req.postData.params) {
        params.push({ name: p.name, location: 'body', required: false, example: p.value });
      }
    }

    // Notable headers (filter out common/boring ones)
    const boringHeaders = new Set(['host', 'accept', 'accept-encoding', 'accept-language', 'connection', 'user-agent', 'referer', 'origin', 'content-length']);
    for (const h of (req.headers ?? [])) {
      if (!boringHeaders.has(h.name.toLowerCase())) {
        params.push({ name: h.name, location: 'header', required: false, example: h.value });
      }
    }

    // Cookies
    for (const c of (req.cookies ?? [])) {
      params.push({ name: c.name, location: 'cookie', required: false, example: c.value });
    }

    const route: ImportedRoute = {
      method: req.method.toUpperCase(),
      path: urlObj.pathname + (urlObj.search ? urlObj.search : ''),
      operationId: `${req.method.toLowerCase()}_${urlObj.pathname.replace(/\//g, '_').replace(/^_/, '')}`,
      summary: `${req.method} ${urlObj.pathname}`,
      params,
    };

    if (req.postData?.mimeType) {
      route.requestBody = { contentType: req.postData.mimeType };
    }

    routes.push(route);
  }

  if (routes.length === 0) warnings.push('No usable entries found in HAR.');

  return {
    format: 'har',
    routes,
    title: 'HAR Import',
    version: doc.log.version ?? '1.2',
    warnings: warnings.length ? warnings : undefined,
  };
}

export function validateHarShape(parsed: unknown): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  if (!parsed || typeof parsed !== 'object') {
    errors.push('Not an object');
    return { valid: false, errors };
  }
  const p = parsed as Record<string, unknown>;
  if (!p['log'] || typeof p['log'] !== 'object') errors.push('Missing log object');
  else {
    const log = p['log'] as Record<string, unknown>;
    if (!Array.isArray(log['entries'])) errors.push('Missing log.entries array');
    if (typeof log['version'] !== 'string') errors.push('Missing log.version string');
  }
  return { valid: errors.length === 0, errors };
}
