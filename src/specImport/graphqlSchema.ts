// ---------------------------------------------------------------------------
// GraphQL Schema Parser
// Supports: SDL text + introspection JSON
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
// SDL parser (text-based, regex-driven — no external deps)
// ---------------------------------------------------------------------------

interface SdlField {
  name: string;
  args: Array<{ name: string; type: string; required: boolean }>;
}

/**
 * Very lightweight SDL parser: extracts fields from `type Query` and
 * `type Mutation` blocks using line-by-line regex matching.
 */
function parseSdlFields(sdl: string): { queryFields: SdlField[]; mutationFields: SdlField[] } {
  const queryFields: SdlField[] = [];
  const mutationFields: SdlField[] = [];

  // Normalise line endings
  const lines = sdl.replace(/\r\n/g, '\n').split('\n');

  let inQuery = false;
  let inMutation = false;
  let depth = 0;

  for (const rawLine of lines) {
    const line = rawLine.trim();

    if (/^type\s+Query\s*\{/.test(line) || line === 'type Query {') {
      inQuery = true;
      inMutation = false;
      depth = 1;
      continue;
    }
    if (/^type\s+Mutation\s*\{/.test(line) || line === 'type Mutation {') {
      inMutation = true;
      inQuery = false;
      depth = 1;
      continue;
    }

    if (!inQuery && !inMutation) continue;

    // Track brace depth
    for (const ch of line) {
      if (ch === '{') depth++;
      if (ch === '}') depth--;
    }

    if (depth <= 0) {
      inQuery = false;
      inMutation = false;
      depth = 0;
      continue;
    }

    // Field line pattern: fieldName(args): ReturnType
    // or simply: fieldName: ReturnType
    const fieldMatch = line.match(/^(\w+)\s*(\(([^)]*)\))?\s*:\s*/);
    if (!fieldMatch) continue;

    const fieldName = fieldMatch[1];
    const argString = fieldMatch[3] ?? '';
    const args = parseArgString(argString);

    const field: SdlField = { name: fieldName, args };
    if (inQuery) queryFields.push(field);
    if (inMutation) mutationFields.push(field);
  }

  return { queryFields, mutationFields };
}

function parseArgString(argStr: string): SdlField['args'] {
  if (!argStr.trim()) return [];
  // Split on comma, parse each "name: Type"
  return argStr
    .split(',')
    .map((a) => a.trim())
    .filter(Boolean)
    .map((a) => {
      const m = a.match(/^(\w+)\s*:\s*(.+)$/);
      if (!m) return null;
      const name = m[1];
      const typePart = m[2].trim();
      const required = typePart.endsWith('!');
      const type = typePart.replace(/!$/, '').trim();
      return { name, type, required };
    })
    .filter((x): x is SdlField['args'][number] => x !== null);
}

function sdlFieldToRoute(field: SdlField, operationType: 'query' | 'mutation'): ImportedRoute {
  const method = operationType === 'query' ? 'GET' : 'POST';
  const path = `/graphql?${operationType}={${field.name}}`;

  const params: ImportedParam[] = field.args.map((arg) => ({
    name: arg.name,
    location: 'query' as const,
    required: arg.required,
    example: undefined,
  }));

  return {
    method,
    path,
    operationId: field.name,
    summary: `GraphQL ${operationType}: ${field.name}`,
    params,
  };
}

// ---------------------------------------------------------------------------
// Introspection JSON parser
// ---------------------------------------------------------------------------

interface IntrospectionField {
  name: string;
  args: Array<{ name: string; type: { kind: string; name: string | null; ofType: unknown }; defaultValue: unknown }>;
}

function extractIntrospectionFields(
  schema: AnyObject,
  typeName: string | null,
): IntrospectionField[] {
  if (!typeName) return [];
  const types = asArray(schema['types']);
  const typeObj = types.find((t) => {
    const to = asObj(t);
    return to && asStr(to['name']) === typeName;
  });
  if (!typeObj) return [];
  const to = asObj(typeObj);
  if (!to) return [];
  return asArray(to['fields']) as IntrospectionField[];
}

function introspectionFieldToRoute(field: IntrospectionField, operationType: 'query' | 'mutation'): ImportedRoute {
  const method = operationType === 'query' ? 'GET' : 'POST';
  const path = `/graphql?${operationType}={${field.name}}`;

  const params: ImportedParam[] = asArray(field.args).flatMap((a) => {
    const ao = asObj(a);
    if (!ao) return [];
    return [
      {
        name: asStr(ao['name']),
        location: 'query' as const,
        required: (asObj(ao['type']) != null) && asStr((asObj(ao['type']) as AnyObject)['kind']) === 'NON_NULL',
        example: ao['defaultValue'] != null ? String(ao['defaultValue']) : undefined,
      },
    ];
  });

  return {
    method,
    path,
    operationId: asStr(field.name),
    summary: `GraphQL ${operationType}: ${asStr(field.name)}`,
    params,
  };
}

// ---------------------------------------------------------------------------
// Main parser
// ---------------------------------------------------------------------------

export function parseGraphqlSchema(raw: string): SpecImportResult {
  const trimmed = raw.trim();

  // Detect introspection JSON by presence of __schema
  if (trimmed.startsWith('{')) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      // Not JSON — fall through to SDL
    }

    if (parsed && typeof parsed === 'object') {
      const obj = parsed as AnyObject;

      // Unwrap { data: { __schema } } or { __schema }
      const schemaRoot = asObj(obj['__schema']) ?? asObj((asObj(obj['data']) as AnyObject | null)?.['__schema']);

      if (schemaRoot) {
        // Introspection path
        const queryTypeName = asStr((asObj(schemaRoot['queryType']) as AnyObject | null)?.['name'] ?? null);
        const mutationTypeName = asStr((asObj(schemaRoot['mutationType']) as AnyObject | null)?.['name'] ?? null);

        const queryFields = extractIntrospectionFields(schemaRoot, queryTypeName || null);
        const mutationFields = extractIntrospectionFields(schemaRoot, mutationTypeName || null);

        const routes: ImportedRoute[] = [
          ...queryFields.map((f) => introspectionFieldToRoute(f, 'query')),
          ...mutationFields.map((f) => introspectionFieldToRoute(f, 'mutation')),
        ];

        return { format: 'graphql-schema', routes };
      }
    }
  }

  // SDL text path
  const { queryFields, mutationFields } = parseSdlFields(raw);

  const routes: ImportedRoute[] = [
    ...queryFields.map((f) => sdlFieldToRoute(f, 'query')),
    ...mutationFields.map((f) => sdlFieldToRoute(f, 'mutation')),
  ];

  return { format: 'graphql-schema', routes };
}
