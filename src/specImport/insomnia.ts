// ---------------------------------------------------------------------------
// Insomnia Export Parser
// Handles Insomnia v4 JSON exports (_type: "export").
// No external dependencies.
// ---------------------------------------------------------------------------

export interface InsomniaRequest {
  _id: string;
  name: string;
  method: string;
  url: string;
  body?: { mimeType?: string; text?: string };
  headers?: Array<{ name: string; value: string }>;
}

export interface InsomniaExport {
  _type: 'export';
  __export_format: number;
  resources: unknown[];
}

// ---------------------------------------------------------------------------
// Shape validator
// ---------------------------------------------------------------------------

export function validateInsomniaShape(parsed: unknown): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    errors.push('Root value must be a JSON object.');
    return { valid: false, errors };
  }

  const obj = parsed as Record<string, unknown>;

  if (obj['_type'] !== 'export') {
    errors.push(`Expected _type "export", got ${JSON.stringify(obj['_type'])}.`);
  }

  if (typeof obj['__export_format'] !== 'number') {
    errors.push('Missing or non-numeric __export_format field.');
  }

  if (!Array.isArray(obj['resources'])) {
    errors.push('Expected resources to be an array.');
  }

  return { valid: errors.length === 0, errors };
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

export function parseInsomnia(raw: string): { requests: InsomniaRequest[]; warnings: string[] } {
  const warnings: string[] = [];
  let parsed: unknown;

  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    warnings.push(`JSON parse failed: ${msg}`);
    return { requests: [], warnings };
  }

  const validation = validateInsomniaShape(parsed);
  if (!validation.valid) {
    return { requests: [], warnings: validation.errors };
  }

  const obj = parsed as Record<string, unknown>;
  const resources = obj['resources'] as unknown[];

  const requestResources = resources.filter((r) => {
    return r !== null && typeof r === 'object' && !Array.isArray(r) &&
      (r as Record<string, unknown>)['_type'] === 'request';
  });

  const skipped = resources.length - requestResources.length;
  if (skipped > 0) {
    warnings.push(`Skipped ${skipped} non-request resource${skipped === 1 ? '' : 's'} (environments, folders, etc.).`);
  }

  const requests: InsomniaRequest[] = [];

  for (const raw of requestResources) {
    const r = raw as Record<string, unknown>;

    const id = typeof r['_id'] === 'string' ? r['_id'] : '';
    const name = typeof r['name'] === 'string' ? r['name'] : '';
    const method = typeof r['method'] === 'string' ? r['method'].toUpperCase() : 'GET';
    const url = typeof r['url'] === 'string' ? r['url'] : '';

    if (!id) {
      warnings.push(`Skipped request without _id (name: ${JSON.stringify(name)}).`);
      continue;
    }

    // Body
    let body: InsomniaRequest['body'] | undefined;
    if (r['body'] !== null && typeof r['body'] === 'object' && !Array.isArray(r['body'])) {
      const rawBody = r['body'] as Record<string, unknown>;
      body = {
        mimeType: typeof rawBody['mimeType'] === 'string' ? rawBody['mimeType'] : undefined,
        text: typeof rawBody['text'] === 'string' ? rawBody['text'] : undefined,
      };
      // Drop empty body objects
      if (body.mimeType === undefined && body.text === undefined) body = undefined;
    }

    // Headers
    let headers: InsomniaRequest['headers'] | undefined;
    if (Array.isArray(r['headers'])) {
      const parsed: Array<{ name: string; value: string }> = [];
      for (const h of r['headers'] as unknown[]) {
        if (h !== null && typeof h === 'object' && !Array.isArray(h)) {
          const hObj = h as Record<string, unknown>;
          const hName = typeof hObj['name'] === 'string' ? hObj['name'] : '';
          const hValue = typeof hObj['value'] === 'string' ? hObj['value'] : '';
          if (hName) parsed.push({ name: hName, value: hValue });
        }
      }
      if (parsed.length > 0) headers = parsed;
    }

    requests.push({ _id: id, name, method, url, body, headers });
  }

  return { requests, warnings };
}
