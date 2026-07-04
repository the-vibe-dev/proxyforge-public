// ---------------------------------------------------------------------------
// Spec Import Router
// Detects and routes raw API spec text to the appropriate parser.
// ---------------------------------------------------------------------------

import { parseOpenApi } from './openApi';
import { parsePostman } from './postman';
import { parseGraphqlSchema } from './graphqlSchema';

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

export type SpecFormat =
  | 'odata'
  | 'openapi3'
  | 'swagger2'
  | 'postman'
  | 'insomnia'
  | 'soap-wsdl'
  | 'graphql-schema'
  | 'har';

export interface ImportedParam {
  name: string;
  location: 'query' | 'path' | 'header' | 'cookie' | 'body';
  required: boolean;
  schema?: unknown;
  example?: string;
}

export interface ImportedRoute {
  method: string;
  path: string;
  operationId?: string;
  summary?: string;
  params: ImportedParam[];
  requestBody?: { contentType: string; schema?: unknown };
  auth?: string[];
}

export interface SpecImportResult {
  format: SpecFormat;
  routes: ImportedRoute[];
  baseUrl?: string;
  title?: string;
  version?: string;
  authSchemes?: string[];
  errors?: string[];
  warnings?: string[];
}

// ---------------------------------------------------------------------------
// Format detection
// ---------------------------------------------------------------------------

/**
 * Detect the spec format from the raw text using structural heuristics.
 * Returns null if the format cannot be determined.
 */
export function detectFormat(raw: string): SpecFormat | null {
  // Try JSON parse first; some formats are JSON, others are YAML or SDL.
  let parsed: unknown = null;
  const trimmed = raw.trim();

  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      // Not valid JSON — will fall through to text heuristics
    }
  }

  if (parsed && typeof parsed === 'object' && parsed !== null) {
    const obj = parsed as Record<string, unknown>;

    // OpenAPI 3.x
    if (typeof obj['openapi'] === 'string' && obj['openapi'].startsWith('3.')) {
      return 'openapi3';
    }

    // Swagger 2.0
    if (typeof obj['swagger'] === 'string' && obj['swagger'].startsWith('2.')) {
      return 'swagger2';
    }

    // Postman collection v2.x — has info._postman_id or info.schema containing getpostman.com
    if (obj['info'] && typeof obj['info'] === 'object') {
      const info = obj['info'] as Record<string, unknown>;
      if (info['_postman_id'] || (typeof info['schema'] === 'string' && info['schema'].includes('getpostman.com'))) {
        return 'postman';
      }
    }

    // Insomnia export
    if (obj['_type'] === 'export' && obj['__export_format']) {
      return 'insomnia';
    }

    // GraphQL introspection result
    if (obj['__schema'] || (obj['data'] && (obj['data'] as Record<string, unknown>)['__schema'])) {
      return 'graphql-schema';
    }

    // HAR archive
    if (obj['log'] && typeof obj['log'] === 'object') {
      const log = obj['log'] as Record<string, unknown>;
      if (log['entries'] && log['version']) return 'har';
    }
  }

  // WSDL / SOAP — XML-based
  if (trimmed.startsWith('<') && /wsdl:|definitions\s/i.test(trimmed)) {
    return 'soap-wsdl';
  }

  // OData $metadata XML
  if (trimmed.startsWith('<') && /edmx:|EntityContainer|EntitySet/i.test(trimmed)) {
    return 'odata';
  }

  // GraphQL SDL — look for type Query / type Mutation / schema keyword
  if (/\btype\s+Query\b/i.test(raw) || /\btype\s+Mutation\b/i.test(raw) || /\bschema\s*\{/i.test(raw)) {
    return 'graphql-schema';
  }

  // YAML-flavoured OpenAPI 3
  if (/^openapi\s*:/m.test(raw)) return 'openapi3';
  if (/^swagger\s*:/m.test(raw)) return 'swagger2';

  return null;
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/**
 * Parse a raw spec string, optionally supplying the format when already known.
 * Falls back to detectFormat when format is omitted.
 */
export function importSpec(raw: string, format?: SpecFormat): SpecImportResult {
  const resolved = format ?? detectFormat(raw);

  switch (resolved) {
    case 'openapi3':
    case 'swagger2':
      return parseOpenApi(raw);

    case 'postman':
      return parsePostman(raw);

    case 'graphql-schema':
      return parseGraphqlSchema(raw);

    case 'insomnia':
      try {
        // Dynamic import to avoid hard dep when insomnia.ts not yet compiled
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        const { parseInsomnia } = require('./insomnia') as { parseInsomnia: (r: string) => { requests: unknown[]; warnings: string[] } };
        const { requests, warnings } = parseInsomnia(raw);
        return { format: 'insomnia', routes: (requests as Array<{ method?: string; url?: string; name?: string }>).map((r) => ({ method: r.method ?? 'GET', path: r.url ?? '/', summary: r.name, params: [] })), warnings };
      } catch {
        return { format: 'insomnia', routes: [], errors: ['Insomnia import not yet compiled.'] };
      }

    case 'soap-wsdl':
      try {
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        const { parseWsdl } = require('./soapWsdl') as { parseWsdl: (r: string) => { operations: Array<{ name: string; soapAction?: string }>; services: unknown[]; warnings: string[] } };
        const { operations, warnings } = parseWsdl(raw);
        return { format: 'soap-wsdl', routes: operations.map((op) => ({ method: 'POST', path: `/${op.name}`, operationId: op.name, summary: op.name, params: [], requestBody: { contentType: 'text/xml' } })), warnings };
      } catch {
        return { format: 'soap-wsdl', routes: [], errors: ['SOAP/WSDL import not yet compiled.'] };
      }

    case 'odata':
      try {
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        const { parseOdata } = require('./odata') as { parseOdata: (r: string) => SpecImportResult };
        return parseOdata(raw);
      } catch {
        return { format: 'odata', routes: [], errors: ['OData import not yet compiled.'] };
      }

    case 'har':
      try {
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        const { parseHarSeed } = require('./harSeed') as { parseHarSeed: (r: string) => SpecImportResult };
        return parseHarSeed(raw);
      } catch {
        return { format: 'har', routes: [], errors: ['HAR import not yet compiled.'] };
      }

    default:
      return {
        format: 'openapi3',
        routes: [],
        errors: ['Could not detect spec format.'],
      };
  }
}
