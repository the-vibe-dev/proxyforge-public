// ---------------------------------------------------------------------------
// Postman Collection v2.1 Parser
// ---------------------------------------------------------------------------

import type { ImportedParam, ImportedRoute, SpecImportResult } from './index';

type AnyObject = Record<string, unknown>;

function asObj(v: unknown): AnyObject | null {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as AnyObject) : null;
}

function asArray(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}

function asStr(v: unknown): string {
  return typeof v === 'string' ? v : '';
}

// ---------------------------------------------------------------------------
// URL parsing
// ---------------------------------------------------------------------------

function extractPath(url: unknown): string {
  if (typeof url === 'string') {
    try {
      return new URL(url).pathname;
    } catch {
      // Not a full URL — treat as path
      return url.split('?')[0];
    }
  }
  const urlObj = asObj(url);
  if (!urlObj) return '/';

  // url.path may be an array or a string
  const pathArr = urlObj['path'];
  if (Array.isArray(pathArr)) {
    return '/' + pathArr.map(String).join('/');
  }
  if (typeof pathArr === 'string') {
    return pathArr.startsWith('/') ? pathArr : '/' + pathArr;
  }

  // Fall back to url.raw
  const raw = asStr(urlObj['raw']);
  if (raw) {
    try {
      return new URL(raw).pathname;
    } catch {
      return raw.split('?')[0];
    }
  }
  return '/';
}

function extractBaseUrl(url: unknown): string | undefined {
  if (typeof url === 'string') {
    try {
      const u = new URL(url);
      return u.origin;
    } catch {
      return undefined;
    }
  }
  const urlObj = asObj(url);
  if (!urlObj) return undefined;
  const raw = asStr(urlObj['raw']);
  if (raw) {
    try {
      const u = new URL(raw);
      return u.origin;
    } catch {
      return undefined;
    }
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Parameter extraction
// ---------------------------------------------------------------------------

function extractQueryParams(url: unknown): ImportedParam[] {
  const urlObj = asObj(url);
  if (!urlObj) return [];
  const query = asArray(urlObj['query']);
  return query.flatMap((q) => {
    const qo = asObj(q);
    if (!qo || qo['disabled'] === true) return [];
    return [
      {
        name: asStr(qo['key']),
        location: 'query' as const,
        required: false,
        example: asStr(qo['value']) || undefined,
      },
    ];
  });
}

function extractHeaderParams(headers: unknown[]): ImportedParam[] {
  return headers.flatMap((h) => {
    const ho = asObj(h);
    if (!ho || ho['disabled'] === true) return [];
    return [
      {
        name: asStr(ho['key']),
        location: 'header' as const,
        required: false,
        example: asStr(ho['value']) || undefined,
      },
    ];
  });
}

// ---------------------------------------------------------------------------
// Request body
// ---------------------------------------------------------------------------

function extractRequestBody(body: unknown): ImportedRoute['requestBody'] | undefined {
  const bo = asObj(body);
  if (!bo) return undefined;
  const mode = asStr(bo['mode']);
  switch (mode) {
    case 'raw': {
      const options = asObj(bo['options']);
      const rawOpts = asObj(options?.['raw']);
      const lang = asStr(rawOpts?.['language']) || 'text';
      const contentType = lang === 'json' ? 'application/json' : lang === 'xml' ? 'application/xml' : 'text/plain';
      return { contentType };
    }
    case 'urlencoded':
      return { contentType: 'application/x-www-form-urlencoded' };
    case 'formdata':
      return { contentType: 'multipart/form-data' };
    case 'graphql':
      return { contentType: 'application/json' };
    default:
      return undefined;
  }
}

// ---------------------------------------------------------------------------
// Recursive item walker
// ---------------------------------------------------------------------------

function walkItems(items: unknown[], routes: ImportedRoute[], baseUrlHolder: { value: string | undefined }): void {
  for (const item of items) {
    const itemObj = asObj(item);
    if (!itemObj) continue;

    // Folder — recurse into nested items
    if (Array.isArray(itemObj['item'])) {
      walkItems(itemObj['item'] as unknown[], routes, baseUrlHolder);
      continue;
    }

    const request = asObj(itemObj['request']);
    if (!request) continue;

    const method = asStr(request['method'] || 'GET').toUpperCase();
    const url = request['url'];
    const routePath = extractPath(url);

    if (!baseUrlHolder.value) {
      baseUrlHolder.value = extractBaseUrl(url);
    }

    const queryParams = extractQueryParams(url);
    const rawHeaders = asArray(request['header']);
    const headerParams = extractHeaderParams(rawHeaders);
    const params: ImportedParam[] = [...queryParams, ...headerParams];

    const requestBody = extractRequestBody(request['body']);
    const name = asStr(itemObj['name']) || undefined;

    routes.push({
      method,
      path: routePath,
      summary: name,
      params,
      requestBody,
    });
  }
}

// ---------------------------------------------------------------------------
// Main parser
// ---------------------------------------------------------------------------

export function parsePostman(raw: string): SpecImportResult {
  let collection: AnyObject;
  try {
    collection = JSON.parse(raw) as AnyObject;
  } catch {
    return { format: 'postman', routes: [], errors: ['Failed to parse JSON.'] };
  }

  const info = asObj(collection['info']);
  const title = info ? asStr(info['name']) || undefined : undefined;

  const routes: ImportedRoute[] = [];
  const baseUrlHolder: { value: string | undefined } = { value: undefined };

  const items = asArray(collection['item']);
  walkItems(items, routes, baseUrlHolder);

  return {
    format: 'postman',
    routes,
    title,
    baseUrl: baseUrlHolder.value,
  };
}
