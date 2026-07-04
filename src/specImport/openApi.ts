// ---------------------------------------------------------------------------
// OpenAPI 3.x + Swagger 2.x Parser
// ---------------------------------------------------------------------------

import type { ImportedParam, ImportedRoute, SpecImportResult } from './index';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
// Parameter extraction (shared between OAS2 and OAS3)
// ---------------------------------------------------------------------------

function extractParams(rawParams: unknown[]): ImportedParam[] {
  return rawParams.flatMap((p) => {
    const param = asObj(p);
    if (!param) return [];
    const loc = asStr(param['in']);
    if (!['query', 'path', 'header', 'cookie', 'body'].includes(loc)) return [];
    return [
      {
        name: asStr(param['name']),
        location: loc as ImportedParam['location'],
        required: param['required'] === true,
        schema: param['schema'] ?? param['items'] ?? undefined,
        example: param['example'] != null ? String(param['example']) : undefined,
      },
    ];
  });
}

// ---------------------------------------------------------------------------
// Swagger 2 body parameter → requestBody shim
// ---------------------------------------------------------------------------

function extractSwagger2RequestBody(params: unknown[]): ImportedRoute['requestBody'] | undefined {
  const bodyParam = asArray(params).find((p) => asObj(p) && asStr((p as AnyObject)['in']) === 'body');
  if (!bodyParam) return undefined;
  return {
    contentType: 'application/json',
    schema: (bodyParam as AnyObject)['schema'],
  };
}

// ---------------------------------------------------------------------------
// OAS3 requestBody extraction
// ---------------------------------------------------------------------------

function extractOas3RequestBody(operation: AnyObject): ImportedRoute['requestBody'] | undefined {
  const rb = asObj(operation['requestBody']);
  if (!rb) return undefined;
  const content = asObj(rb['content']);
  if (!content) return undefined;
  const contentType = Object.keys(content)[0] ?? 'application/json';
  const mediaObj = asObj(content[contentType]);
  return { contentType, schema: mediaObj?.['schema'] };
}

// ---------------------------------------------------------------------------
// Auth scheme extraction
// ---------------------------------------------------------------------------

function extractAuthSchemes(spec: AnyObject): string[] {
  // OAS 3: components.securitySchemes
  const components = asObj(spec['components']);
  if (components) {
    const schemes = asObj(components['securitySchemes']);
    if (schemes) return Object.keys(schemes);
  }
  // Swagger 2: securityDefinitions
  const defs = asObj(spec['securityDefinitions']);
  if (defs) return Object.keys(defs);
  return [];
}

// ---------------------------------------------------------------------------
// Server / base URL
// ---------------------------------------------------------------------------

function extractBaseUrl(spec: AnyObject, isOas3: boolean): string | undefined {
  if (isOas3) {
    const servers = asArray(spec['servers']);
    const first = asObj(servers[0]);
    if (first) return asStr(first['url']) || undefined;
  } else {
    // Swagger 2
    const host = asStr(spec['host']);
    const basePath = asStr(spec['basePath']) || '/';
    const schemes = asArray(spec['schemes']);
    const scheme = asStr(schemes[0]) || 'https';
    if (host) return `${scheme}://${host}${basePath}`;
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Main parser
// ---------------------------------------------------------------------------

export function parseOpenApi(raw: string): SpecImportResult {
  const errors: string[] = [];
  let spec: AnyObject;

  try {
    spec = JSON.parse(raw) as AnyObject;
  } catch {
    return { format: 'openapi3', routes: [], errors: ['Failed to parse JSON.'] };
  }

  const isOas3 = typeof spec['openapi'] === 'string' && asStr(spec['openapi']).startsWith('3.');
  const format = isOas3 ? 'openapi3' : 'swagger2';
  const info = asObj(spec['info']);
  const title = info ? asStr(info['title']) || undefined : undefined;
  const version = info ? asStr(info['version']) || undefined : undefined;
  const paths = asObj(spec['paths']);

  const routes: ImportedRoute[] = [];
  const authSchemes = extractAuthSchemes(spec);
  const baseUrl = extractBaseUrl(spec, isOas3);

  if (!paths) {
    errors.push('No paths object found in spec.');
    return { format, routes, title, version, baseUrl, authSchemes, errors };
  }

  const httpMethods = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'trace'];

  for (const [routePath, pathItem] of Object.entries(paths)) {
    const pi = asObj(pathItem);
    if (!pi) continue;

    // Path-level parameters (inherited by all operations)
    const pathLevelParams = asArray(pi['parameters']);

    for (const method of httpMethods) {
      const operation = asObj(pi[method]);
      if (!operation) continue;

      const opParams = asArray(operation['parameters']);
      // Merge: operation params override path params with the same name+in
      const mergedParamMap = new Map<string, unknown>();
      for (const p of pathLevelParams) {
        const po = asObj(p);
        if (po) mergedParamMap.set(`${asStr(po['in'])}:${asStr(po['name'])}`, p);
      }
      for (const p of opParams) {
        const po = asObj(p);
        if (po) mergedParamMap.set(`${asStr(po['in'])}:${asStr(po['name'])}`, p);
      }
      const allRawParams = [...mergedParamMap.values()];

      // For Swagger 2, body params live in parameters; for OAS3 they are requestBody
      const bodyExcluded = isOas3 ? allRawParams : allRawParams.filter((p) => asStr((p as AnyObject)['in']) !== 'body');
      const params = extractParams(bodyExcluded);

      let requestBody: ImportedRoute['requestBody'] | undefined;
      if (isOas3) {
        requestBody = extractOas3RequestBody(operation);
      } else {
        requestBody = extractSwagger2RequestBody(allRawParams);
        // Also add body param names as ImportedParams with location=body
        for (const p of allRawParams) {
          const po = asObj(p);
          if (po && asStr(po['in']) === 'body') {
            params.push({
              name: asStr(po['name']) || 'body',
              location: 'body',
              required: po['required'] === true,
              schema: po['schema'],
            });
          }
        }
      }

      // Security on operation overrides global
      const secReqs = asArray(operation['security'] ?? spec['security']);
      const auth = secReqs.flatMap((s) => {
        const so = asObj(s);
        return so ? Object.keys(so) : [];
      });

      routes.push({
        method: method.toUpperCase(),
        path: routePath,
        operationId: asStr(operation['operationId']) || undefined,
        summary: asStr(operation['summary']) || undefined,
        params,
        requestBody,
        auth: auth.length > 0 ? auth : undefined,
      });
    }
  }

  return { format, routes, title, version, baseUrl, authSchemes: authSchemes.length > 0 ? authSchemes : undefined };
}
