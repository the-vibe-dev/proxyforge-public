---
name: client_security
description: Client-side JavaScript attack surface — route extraction, source-map recovery, DOM sink identification, postMessage isolation, CSP/CORS enforcement, token leakage in storage, service-worker XSS, prototype pollution.
---

# Client-Side Security

JavaScript in the browser remains a high-yield attack surface. Most programs focus on server-side auth and API validation but neglect client-side logic, DOM sanitization, and storage isolation. This pack systematically hunts the attack surface that server-side code cannot protect.

This pack composes with `shared/scope_guard.md`, `shared/evidence_rules.md`, `packs/web_hunter/SKILL.md` (endpoint discovery), `packs/dom_taint_hunter/SKILL.md`, and `packs/triage_validation/SKILL.md`.

## When to Use

- Target ships a JavaScript Single-Page Application (SPA), React/Vue/Angular frontend, or mobile web app.
- Service Workers are registered and cache application state or user data.
- Application accepts route parameters, query strings, postMessage events, or user input in the DOM.
- CSP, CORS, or storage security policies are in place but may be misconfigured.
- API keys, session tokens, or credentials appear in network traffic or are stored client-side.

## Operating Rules

- **Authorization**: confirm scope explicitly permits client-side testing. Some programs restrict testing to production APIs only.
- **Storage inspection**: do not exfiltrate real user tokens or credentials beyond proof-of-presence in console or DevTools. Document the path (localStorage key, sessionStorage key) and do not commit the token itself in the report.
- **postMessage testing**: test with same-origin and cross-origin framing. Document origin-check bypass, not just the listening channel's existence.
- **Source map**: if source maps are public, note this as an informational or low-severity finding (source disclosure); the impact comes only if combined with secrets in the source.

## Phase 0: Surface Discovery

### 1. Enumerate JavaScript bundles

```bash
# Fetch the main page and extract script tags
curl -s https://target.com | grep -oP '(?<=src=")[^"]*\.js(?=")'

# Common bundle names to hunt for
/static/bundle.js /assets/app.js /js/main.js /dist/app.js
```

### 2. Check for source maps

```bash
# Look for sourceMappingURL comment in the bundle
curl -s https://target.com/static/bundle.js | tail -20 | grep -i "sourceMappingURL"

# Fetch the map file directly
curl -s https://target.com/static/bundle.js.map | head -20
```

### 3. Discover service workers

```bash
# Check the manifest and common paths
curl -s https://target.com/manifest.json | grep -i "service_worker"
curl -s https://target.com/sw.js
curl -s https://target.com/service-worker.js
```

### 4. Extract API routes from bundle analysis

```bash
# If source map is public, extract all fetch/axios/fetch call patterns
grep -oP '(fetch|axios|fetch\(|xhr\.open)\(["\x27]/api/[^"\x27]+' bundle.js.map | sort -u
```

## Phase 1: Source Map Recovery

Source maps expose full application logic, internal routing, API endpoints, and sometimes hardcoded credentials.

### Find and download the map

```bash
# The bundle often includes a sourceMappingURL comment pointing to the map location
curl -s https://target.com/static/bundle.js | grep -i "sourceMappingURL"
# => //# sourceMappingURL=bundle.js.map

# Download the map
curl -s https://target.com/static/bundle.js.map -o bundle.js.map

# Parse the map to extract source paths and logic
python3 -c "
import json
with open('bundle.js.map') as f:
  data = json.load(f)
  for source in data['sources']:
    print(source)
"
```

### Search the decompiled sources

```bash
# Look for credentials, API keys, hardcoded URLs, or sensitive logic
grep -r "password\|api.key\|secret\|token" . --include="*.js"
grep -r "http://\|https://" . --include="*.js" | head -20
```

## Phase 2: DOM Sink Identification

DOM sinks are JavaScript functions that can execute code if given tainted input. High-risk sinks: `innerHTML`, `eval`, `Function`, `document.write`.

### Map input sources to sinks

```javascript
// Dangerous pattern: route parameter → innerHTML
const route = window.location.pathname;
document.getElementById('content').innerHTML = route;  // ✗ Sink

// Dangerous pattern: postMessage → eval
window.addEventListener('message', (e) => {
  eval(e.data);  // ✗ Sink
});

// Safer pattern: innerHTML with sanitization
const sanitized = DOMPurify.sanitize(route);
document.getElementById('content').innerHTML = sanitized;  // ✓ OK
```

### Audit sinks in the application

```bash
# Grep for dangerous DOM functions
grep -r "innerHTML\|eval\|Function\|document.write" src/ --include="*.js*"

# For each match, trace back the input:
# 1. Does the input come from URL, postMessage, or user input?
# 2. Is there sanitization (DOMPurify, sanitizer, escaping)?
# 3. If no sanitization, it's a DOM XSS sink.
```

## Phase 3: postMessage Review

postMessage is used for cross-window communication but requires strict origin validation.

### Common vulnerability: missing origin check

```javascript
// ✗ Dangerous: no origin check
window.addEventListener('message', (e) => {
  const user = JSON.parse(e.data);
  localStorage.setItem('user', user);
});

// ✓ Safe: origin check before processing
window.addEventListener('message', (e) => {
  if (e.origin !== 'https://trusted.com') return;
  const user = JSON.parse(e.data);
  localStorage.setItem('user', user);
});
```

### Attack: origin bypass with substring matching

```javascript
// ✗ Dangerous: substring match
if (e.origin.includes('example.com')) {
  // ...process data...
}
// Attacker can use: https://example.com.attacker.com

// ✓ Safe: exact match or URL constructor
if (e.origin === 'https://example.com') {
  // ...process data...
}
```

### Test harness

```html
<!-- attacker-frame.html on attacker.com -->
<iframe id="target" src="https://target.com/app"></iframe>
<script>
// Attempt to exploit postMessage
document.getElementById('target').contentWindow.postMessage({
  action: 'login',
  token: 'stolen-token'
}, '*');
</script>
```

## Phase 4: CSP and CORS Policy Review

### Content-Security-Policy (CSP)

```bash
# Fetch CSP header
curl -sI https://target.com | grep -i "content-security-policy"

# Dangerous CSP:
# unsafe-inline, unsafe-eval, wildcard script-src, weak nonce patterns
```

**Bypass: static or reused nonce**

```bash
# Collect nonce values from multiple requests
for i in {1..5}; do
  curl -s https://target.com | grep -oP 'nonce="[^"]*' | head -1
done

# If the nonce is identical across requests or guessable, it's a bypass vector
```

### CORS misconfiguration

```bash
# Test origin reflection
curl -s -H "Origin: https://attacker.com" -H "Access-Control-Request-Method: POST" \
  -X OPTIONS https://target.com/api/sensitive-endpoint

# If the response includes:
# Access-Control-Allow-Origin: https://attacker.com
# Access-Control-Allow-Credentials: true
# Then cross-origin requests with credentials are allowed from any origin
```

## Phase 5: Storage and Token Leakage

### Inspect storage for secrets

```javascript
// In DevTools console
console.log(localStorage);
console.log(sessionStorage);

// Programmatic inspection
Object.keys(localStorage).forEach(key => {
  console.log(key, '=', localStorage.getItem(key));
});
```

**Common leaks:**

- JWT tokens in localStorage (accessible to inline script XSS)
- API keys in sessionStorage (if window remains open)
- Password-reset tokens in URL fragments (logged in history, shared via link)
- OAuth access tokens in URL (if SPA uses implicit flow)

### IndexedDB inspection

```javascript
// Check for sensitive data in IndexedDB
const dbs = await indexedDB.databases();
dbs.forEach(db => {
  const req = indexedDB.open(db.name);
  req.onsuccess = () => {
    const stores = req.result.objectStoreNames;
    console.log(db.name, stores);
  };
});
```

## Phase 6: Service Worker and Cache Security

### Identify cache poisoning vectors

```javascript
// Service Worker cache strategy
self.addEventListener('fetch', (e) => {
  e.respondWith(
    caches.match(e.request).then((cached) => {
      return cached || fetch(e.request).then((res) => {
        // Bug: cache key includes query string but not user ID
        caches.open('api-cache').then((cache) => {
          cache.put(e.request, res.clone());
        });
        return res;
      });
    })
  );
});

// Attack: attacker requests /api/user?id=1, it gets cached
// Next request from victim for /api/user?id=2 retrieves attacker's cached response for /api/user?id=1
```

### Review cache scope

```bash
# Check what endpoints the service worker caches
grep -A 20 "caches.open\|cache.put\|caches.match" service-worker.js

# For each cached endpoint, ask:
# 1. Is the cache key specific to the current user?
# 2. Can one user trigger a cache entry that another user sees?
```

## Phase 7: Prototype Pollution

### Identify unsafe object merging

```javascript
// ✗ Dangerous: user input merged into app state
Object.assign(appState, userInput);

// Attacker sets: userInput = { "__proto__": { "isAdmin": true } }
// Result: appState.isAdmin === true globally

// ✓ Safe: whitelist merging
const allowed = ['username', 'email'];
allowed.forEach(key => {
  if (userInput[key]) appState[key] = userInput[key];
});
```

### Test for prototype pollution

```javascript
// In console
const obj = {};
const tainted = JSON.parse('{"__proto__": {"isAdmin": true}}');
Object.assign(obj, tainted);

// Check if the pollution affected the prototype
({}).isAdmin === true  // ✗ Vulnerable if true
```

## Submission Gates

Run `packs/triage_validation/SKILL.md` 7-Question gate. Then for this class:

- [ ] Source map (if present) publicly accessible and contains business logic or API routes.
- [ ] DOM sink identified with clear taint-flow from input to sink.
- [ ] postMessage origin check bypass confirmed with cross-origin test.
- [ ] Storage leakage: specific key names and data types documented (do not include actual tokens).
- [ ] CSP bypass reproducible (e.g., nonce reuse across N requests).
- [ ] CORS misconfiguration: specific origin and credentials combination tested.
- [ ] Service worker cache poisoning: attack flow and cache key leakage documented.

## Evidence

Store under run artifact root, named `client_<attack-class>_<timestamp>/`:

- `01_discovery.txt` — bundle URLs, service worker registration, storage enumeration.
- `02_source_map.json` — decompiled source (if applicable).
- `03_dom_sinks.txt` — list of all innerHTML, eval, Function calls with line numbers.
- `04_postmessage_test.html` — test harness and results.
- `05_csp_policy.txt` — full CSP header content.
- `06_cors_test.txt` — curl requests and responses showing misconfiguration.
- `07_storage_contents.txt` — keys only, redacted values (e.g., "Authorization: [REDACTED_JWT]").
- `08_serviceworker_cache_test.log` — cache key patterns and poisoning flow.
- `README.md` — summary table per `shared/evidence_rules.md`.

## Exclusions

- No actual account takeover or privilege escalation beyond proof-of-concept.
- No persistence or malware injection into the application.
- Storage inspection: document secrets' presence, not exfiltrate them.
- Do not target real users' browsers or sessions; use self-targeting only.

## See Also

- `agent_skills/packs/dom_taint_hunter/SKILL.md` — DOM XSS payloads and vector enumeration
- `agent_skills/packs/web_hunter/SKILL.md` — endpoint discovery
- `agent_skills/packs/cache_smuggling/SKILL.md` — web cache poisoning (extends to service-worker cache)
- `agent_skills/packs/api_security/SKILL.md` — CORS policy enforcement and API-level controls
- External tools: HTML sanitizer libraries, JS beautifier, source-map-explorer, intercepting proxy

