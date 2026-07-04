# API Spec Import Guide

Proxy Forge can import six common API specification formats and convert them into seeded scope, insertion points, and Repeater starter tabs — without requiring the app to capture a single real request first.

## Supported Formats

| Format | File Extensions | Key Parser |
|---|---|---|
| OpenAPI 3.x | `.yaml`, `.yml`, `.json` | `src/specImport/openApi.ts` |
| Swagger 2.0 | `.yaml`, `.yml`, `.json` | `src/specImport/openApi.ts` |
| Postman Collection v2.x | `.json` | `src/specImport/postman.ts` |
| Insomnia Export v4 | `.json` | `src/specImport/insomnia.ts` |
| SOAP/WSDL 1.1/1.2 | `.wsdl`, `.xml` | `src/specImport/soapWsdl.ts` |
| GraphQL SDL/Introspection | `.graphql`, `.gql`, `.json` | `src/specImport/graphqlSchema.ts` |
| OData $metadata | `.xml`, `.json` | `src/specImport/odata.ts` |
| HAR Archive | `.har` | `src/specImport/harSeed.ts` |

## Import Wizard

Open **Target → Import Spec** (or press `Cmd/Ctrl+I` from the Import screen). The wizard has three steps:

1. **Select** — choose a local file. The format is auto-detected.
2. **Preview** — review the routes table. Inspect method, path, and parameter count.
3. **Seed** — confirm to populate:
   - Target Map (host + paths)
   - Insertion-point inventory (query / path / header / body / cookie / JSON / multipart)
   - Repeater tabs (one per route)
   - Scanner queue (insertion points ready for active scan)

## Auto-detection Logic

`detectFormat(raw: string): SpecFormat | null` in `src/specImport/index.ts` uses structural heuristics:

- JSON with `openapi: "3.*"` → `openapi3`
- JSON with `swagger: "2.*"` → `swagger2`
- JSON with `info._postman_id` or `info.schema` containing `getpostman.com` → `postman`
- JSON with `_type: "export"` and `__export_format` → `insomnia`
- JSON with `__schema` or `data.__schema` → `graphql-schema`
- JSON with `log.entries` and `log.version` → `har`
- XML with `wsdl:` or `definitions ` → `soap-wsdl`
- XML with `edmx:` or `EntityContainer` → `odata`
- Text with `type Query` / `type Mutation` / `schema {` → `graphql-schema`
- Text with `^openapi:` → `openapi3`
- Text with `^swagger:` → `swagger2`

## Insertion Points

After import, `src/scanner/insertionPointsFromSpec.ts` converts each route's parameters into typed insertion points:

| Param Location | Insertion Point Kind |
|---|---|
| `query` | `query` |
| `path` | `path` |
| `header` | `header` |
| `cookie` | `cookie` |
| `body` (urlencoded/form) | `body` |
| JSON `requestBody` | `json` |
| Multipart `requestBody` | `multipart` |

Path template parameters (e.g., `/users/{id}`) are extracted automatically even when not listed in the spec.

## CLI Import

```sh
# From the proxyforge-agent CLI
node scripts/proxyforge-agent.mjs spec-import \
  --project ./my-project.pfproj \
  --file ./openapi.yaml \
  [--format openapi3]
```

Output:
```json
{ "routes": 47, "insertionPoints": 213, "warnings": [] }
```

## Format-Specific Notes

### OpenAPI 3 / Swagger 2
- Both YAML and JSON are accepted (YAML is line-parsed; no full YAML parser at runtime)
- `$ref` resolution is best-effort (inline refs only)
- Security scheme names are extracted as `authSchemes`

### Postman
- Collection v2.1 supported (v1 is deprecated; v2.0 partially works)
- Variables (`{{baseUrl}}`) in URLs are preserved as-is
- Pre-request scripts are ignored

### Insomnia
- Format 4 (current) supported
- Non-request resources (environments, folders) are counted in warnings

### SOAP/WSDL
- Extracts `<portType>` operations with input/output message names
- Correlates `soapAction` from binding blocks
- Routes are emitted as `POST /<OperationName>` with `Content-Type: text/xml`

### GraphQL
- SDL: extracts Query, Mutation, and Subscription root field names
- Introspection JSON: extracts from `__schema.types`
- Each operation becomes a `POST /graphql` route with a distinct `operationName` parameter

### OData
- Both XML EDMX and JSON CSDL formats
- EntitySets produce GET/POST/PATCH/DELETE routes
- Standard OData query params (`$top`, `$skip`, `$filter`, `$select`, `$expand`) are added to GET routes
- ActionImports and FunctionImports become POST routes

### HAR
- Duplicate method+URL combinations are deduplicated
- Query params, form body params, and non-standard headers are extracted
- Response status is preserved for reference

## Programmatic Import

```typescript
import { importSpec, detectFormat } from './src/specImport/index';

const raw = fs.readFileSync('./openapi.yaml', 'utf8');
const format = detectFormat(raw);              // 'openapi3'
const result = importSpec(raw, format);        // { format, routes, baseUrl, title, ... }

// Convert to insertion points
import { extractInsertionPoints } from './src/scanner/insertionPointsFromSpec';
const points = extractInsertionPoints(result.routes);
```
