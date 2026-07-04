# ProxyForge Extension API

Extensions are TypeScript modules that hook into ProxyForge's traffic pipeline, scanner, and UI.

---

## Manifest

Every extension exports a `manifest` that describes itself.

```typescript
{
  id: string;          // unique slug, e.g. "my-header-injector"
  name: string;        // display name
  version: string;     // semver
  description?: string;
  author?: string;
  license?: string;
  hooks: HookName[];       // which hooks this extension uses
  permissions: string[];   // which resources it may access
  digest?: string;     // SHA-256 of serialised manifest (set by loader)
  signature?: string;  // HMAC-SHA256 from ProxyForge signing key
}
```

### Required fields

`id`, `name`, `version`, `hooks`, `permissions` are always required.

---

## Hooks

| Hook name                   | Trigger                          | Payload type                       | Result type                     |
|-----------------------------|----------------------------------|------------------------------------|---------------------------------|
| `request`                   | Outgoing HTTP request            | `RequestHookPayload`               | `RequestHookResult \| void`     |
| `response`                  | Incoming HTTP response           | `ResponseHookPayload`              | `ResponseHookResult \| void`    |
| `tls_clienthello`           | TLS ClientHello observed         | `TlsClientHelloPayload`            | `void`                          |
| `tcp_message`               | Raw TCP frame                    | `TcpMessagePayload`                | `void`                          |
| `scan_check`                | Active scanner probe             | `ScanCheckPayload`                 | `ScanCheckResult \| void`       |
| `editor_tab`                | Message editor opened            | `EditorTabPayload`                 | `void`                          |
| `intruder_payload_processor`| Intruder payload generated       | `IntruderPayloadProcessorPayload`  | `IntruderPayloadResult \| void` |
| `repeater_action`           | Repeater request sent            | `RepeaterActionPayload`            | `void`                          |
| `scanner_passive`           | Passive scan of a traffic pair   | `ScannerPassivePayload`            | `ScannerPassiveResult \| void`  |

### Payload and result shapes

```typescript
// request / response
RequestHookPayload   { exchangeId, method, url, headers, body? }
RequestHookResult    { headers?, body?, blocked? }
ResponseHookPayload  { exchangeId, status, statusText, headers, body? }
ResponseHookResult   { headers?, body?, blocked? }

// scan_check
ScanCheckPayload     { exchangeId, checkId, insertionPointId?, payload? }
ScanCheckResult      { finding?: { title, severity, confidence, detail } }
  severity:          'info' | 'low' | 'medium' | 'high' | 'critical'
  confidence:        'tentative' | 'firm' | 'certain'

// scanner_passive
ScannerPassivePayload  { exchangeId, requestRaw, responseRaw }
ScannerPassiveResult   { issues?: Array<{ title, severity, detail }> }

// intruder_payload_processor
IntruderPayloadProcessorPayload  { original, position }
IntruderPayloadResult            { transformed }
```

---

## Permissions model

Extensions declare the permissions they require. ProxyForge enforces them at load time.

| Token            | Grants                                            |
|------------------|---------------------------------------------------|
| `read:history`   | Read proxy history entries                        |
| `write:history`  | Modify or annotate proxy history entries          |
| `read:issues`    | Read scanner issues                               |
| `write:issues`   | Create or update scanner issues                   |
| `read:project`   | Read project settings and metadata                |
| `network:request`| Make outbound HTTP requests via the ProxyForge API|
| `ui:tab`         | Register custom UI tabs or context-menu items     |

---

## Installation

Place your extension directory (containing `index.ts` or compiled `index.js`) inside
`extensions/` in your ProxyForge project, then add it to `proxyforge.config.json`:

```json
{
  "extensions": [
    "./extensions/my-extension"
  ]
}
```

ProxyForge compiles TypeScript extensions on first load with the project's local `tsc`.

---

## SDK helpers (`src/extensions/sdkHelpers.ts`)

Import from `../../sdkHelpers` inside your extension.

| Helper | Description |
|--------|-------------|
| `base64Encode(s)` | UTF-8 → base64 |
| `base64Decode(s)` | base64 → UTF-8 |
| `extractHeader(headers, name)` | Case-insensitive header lookup; returns `null` if absent |
| `parseQueryParams(url)` | Returns query-string as `Record<string, string>` |
| `isJson(s)` | Returns `true` if `s` is valid JSON |
| `prettyJson(s)` | JSON.stringify with 2-space indent |
| `matchesPattern(value, pattern)` | Glob match; supports `*` and `?` |
| `truncate(s, maxLen)` | Truncate to at most `maxLen` characters |
| `isSensitiveHeader(name)` | Returns `true` for Authorization, Cookie, Set-Cookie, X-Api-Key, etc. |
| `redactSensitiveHeaders(headers)` | Replaces sensitive header values with `'[REDACTED]'` |

---

## Manifest utilities (`src/extensions/manifest.ts`)

```typescript
import { validateManifest, normalizeManifest, computeDigest,
         VALID_HOOKS, VALID_PERMISSIONS } from '../extensions/manifest';

validateManifest(obj)          // → { valid: boolean; errors: string[] }
normalizeManifest(partial)     // → ExtensionManifest with defaults applied
computeDigest(manifestJson)    // → 64-char SHA-256 hex string
VALID_HOOKS                    // readonly HookName[]
VALID_PERMISSIONS              // readonly string[]
```

---

## Sample extensions

### passive-secret-detector

Passively scans every HTTP response body for leaked secrets (API keys, tokens, private keys).
Uses `scanner_passive` hook. Requires `read:history` + `write:issues`.

```typescript
import { extension } from './sampleExtensions/passive-secret-detector';
```

Detected patterns: `api_key`, `access_token`, `password`, PEM private keys, AWS secret keys,
GitHub `ghp_` tokens, and OpenAI `sk-` keys.

### header-injector

Injects `X-ProxyForge-Extension: header-injector/1.0` into every outgoing request.
Additional headers are supplied via the `PF_INJECT_HEADERS` environment variable (JSON object).

```bash
PF_INJECT_HEADERS='{"X-Debug":"1"}' proxyforge start
```

Uses `request` hook. Requires `read:history` + `write:history`.

### intruder-base64

Intruder payload processor that base64-encodes each payload before injection.
Useful when the target insertion point expects base64 values.

```typescript
// payload 'hello' → transformed 'aGVsbG8='
```

Uses `intruder_payload_processor` hook. Requires `read:history`.

### custom-scan-check

Active scanner check that reports a finding when a debug query parameter
(`?debug=1`, `?test=true`, `?verbose=1`, etc.) is accepted by the server.

Uses `scan_check` hook. Requires `read:history` + `write:issues`.
Reports severity `low` / confidence `tentative`.
