// OData $metadata → entity sets + actions spec importer.
import type { SpecImportResult, ImportedRoute, ImportedParam } from './index';

export function parseOdata(raw: string): SpecImportResult {
  const warnings: string[] = [];
  const routes: ImportedRoute[] = [];

  // Detect XML vs JSON $metadata
  const trimmed = raw.trim();
  const isXml = trimmed.startsWith('<');

  if (isXml) {
    return parseOdataXml(raw, warnings, routes);
  }

  // JSON CSDL (OData 4.01 JSON format)
  try {
    const doc = JSON.parse(trimmed) as Record<string, unknown>;
    return parseOdataJson(doc, warnings, routes);
  } catch {
    warnings.push('Could not parse OData metadata as XML or JSON.');
    return { format: 'openapi3', routes: [], errors: warnings };
  }
}

function parseOdataXml(
  raw: string,
  warnings: string[],
  routes: ImportedRoute[]
): SpecImportResult {
  // Extract service root from xml:base or first EntityContainer
  const baseMatch = raw.match(/xml:base="([^"]+)"/);
  const baseUrl = baseMatch?.[1]?.replace(/\/?$/, '') ?? '';

  // Extract EntitySets
  const entitySetRe = /<EntitySet[^>]+Name="([^"]+)"[^>]+EntityType="([^"]+)"/g;
  let m: RegExpExecArray | null;
  while ((m = entitySetRe.exec(raw)) !== null) {
    const name = m[1];
    routes.push(
      { method: 'GET', path: `/${name}`, operationId: `list${name}`, summary: `List ${name}`, params: buildOdataQueryParams() },
      { method: 'GET', path: `/${name}({id})`, operationId: `get${name}`, summary: `Get ${name} by key`, params: [{ name: 'id', location: 'path', required: true }] },
      { method: 'POST', path: `/${name}`, operationId: `create${name}`, summary: `Create ${name}`, params: [], requestBody: { contentType: 'application/json' } },
      { method: 'PATCH', path: `/${name}({id})`, operationId: `update${name}`, summary: `Update ${name}`, params: [{ name: 'id', location: 'path', required: true }], requestBody: { contentType: 'application/json' } },
      { method: 'DELETE', path: `/${name}({id})`, operationId: `delete${name}`, summary: `Delete ${name}`, params: [{ name: 'id', location: 'path', required: true }] },
    );
  }

  // Extract FunctionImports / ActionImports
  const actionRe = /<(?:ActionImport|FunctionImport)[^>]+Name="([^"]+)"/g;
  while ((m = actionRe.exec(raw)) !== null) {
    routes.push({ method: 'POST', path: `/${m[1]}`, operationId: m[1], summary: m[1], params: [] });
  }

  if (routes.length === 0) warnings.push('No EntitySets or ActionImports found in OData $metadata.');

  return { format: 'openapi3', routes, baseUrl, title: 'OData Service', warnings };
}

function parseOdataJson(
  doc: Record<string, unknown>,
  warnings: string[],
  routes: ImportedRoute[]
): SpecImportResult {
  // JSON CSDL schema: {"$Version":"4.01","EntityContainer":{"@type":"EntityContainer","<Name>": {"$Collection":true,...}}}
  const container = Object.values(doc).find(
    (v) => v && typeof v === 'object' && (v as Record<string, unknown>)['$Kind'] === 'EntityContainer'
  ) as Record<string, unknown> | undefined;

  if (!container) {
    warnings.push('No EntityContainer found in OData JSON CSDL.');
    return { format: 'openapi3', routes: [], warnings };
  }

  for (const [key, val] of Object.entries(container)) {
    if (key.startsWith('$') || key.startsWith('@')) continue;
    const entry = val as Record<string, unknown>;
    if (entry['$Collection']) {
      routes.push(
        { method: 'GET', path: `/${key}`, operationId: `list${key}`, summary: `List ${key}`, params: buildOdataQueryParams() },
        { method: 'POST', path: `/${key}`, operationId: `create${key}`, summary: `Create ${key}`, params: [], requestBody: { contentType: 'application/json' } },
      );
    } else {
      routes.push({ method: 'POST', path: `/${key}`, operationId: key, summary: key, params: [] });
    }
  }

  return { format: 'openapi3', routes, title: 'OData Service', warnings };
}

function buildOdataQueryParams(): ImportedParam[] {
  return [
    { name: '$top', location: 'query', required: false, example: '10' },
    { name: '$skip', location: 'query', required: false, example: '0' },
    { name: '$filter', location: 'query', required: false },
    { name: '$orderby', location: 'query', required: false },
    { name: '$select', location: 'query', required: false },
    { name: '$expand', location: 'query', required: false },
    { name: '$count', location: 'query', required: false, example: 'true' },
  ];
}

export function validateOdataShape(parsed: unknown): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  if (!parsed || typeof parsed !== 'object') {
    errors.push('Not an object');
    return { valid: false, errors };
  }
  const p = parsed as Record<string, unknown>;
  if (!Array.isArray(p['routes'])) errors.push('Missing routes array');
  return { valid: errors.length === 0, errors };
}
