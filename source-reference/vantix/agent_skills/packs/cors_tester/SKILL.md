---
name: cors_tester
description: CORS policy testing across 12 origin variants to detect authentication bypass and credential leaks.
---
# CORS Tester

CORS misconfiguration is common and high-impact. Applications often whitelist Origins by naive string matching, allowing subdomain takeovers, domain-suffix confusion, and null-origin confusion. The "Access-Control-Allow-Credentials: true + Access-Control-Allow-Origin: *" state is an impossible CORS configuration that leaks all credentials. This pack tests 12 Origin variants and classifies outcomes: credentials leaked, metadata leaked, or properly denied.

Composes with `packs/api_security/SKILL.md`, `packs/web_hunter/SKILL.md`, `packs/triage_validation/SKILL.md`, `packs/skeptic_validator/SKILL.md`.

## When to Use

- Target has an API accessible from the browser (XHR, fetch, any CORS-subject request).
- The API returns sensitive data (user profile, financial, PII, auth tokens).
- The application has subdomains or is part of a public DNS zone.
- The program permits CORS testing and origin-variant testing.

## Operating Rules

- CORS testing via browser JavaScript (fetch API) is the canonical attack vector; replicate this via `browser_execute_script`.
- Test from locally-controlled origins (localhost:8000, 127.0.0.1:8000, or a registered attacker domain).
- Do not attempt to register domains that belong to other organizations; use your own attacker domain.
- Document the exact request (method, headers, body), response status code, and CORS response headers.
- If credentials are leaked, immediately stop, escalate to Critical, and request cleanup.

## Phase 0: CORS Header Baseline

For every authenticated API endpoint, capture the CORS response headers:

```
curl -i -H "Origin: https://target.com" https://target.com/api/user
```

Capture:

- `Access-Control-Allow-Origin` (echo, wildcard, or specific).
- `Access-Control-Allow-Credentials` (true or absent).
- `Access-Control-Allow-Methods` (GET, POST, PATCH, DELETE, etc.).
- `Access-Control-Allow-Headers` (Authorization, Content-Type, custom headers).
- `Vary: Origin` (presence indicates dynamic origin handling).
- `Access-Control-Max-Age` (preflight cache duration).

Create a baseline table per endpoint:

```
| Endpoint | Method | Allow-Origin | Allow-Credentials | Allow-Methods | Vary |
|----------|--------|---|---|---|---|
| GET /api/user | GET | https://target.com | absent | GET, OPTIONS | Origin |
```

## Phase 1: Origin Variant Testing

For each endpoint, test 12 Origin variants:

1. `https://attacker.example.com` — arbitrary attacker domain.
2. `https://target.com.attacker.example.com` — domain suffix bypass (attacker.example.com registered by you).
3. `https://sub.target.com` — registered subdomain (if target has dangling DNS).
4. `https://target.com:8080` — port mismatch.
5. `http://target.com` — protocol downgrade (HTTP instead of HTTPS).
6. `https://TARGET.com` — case confusion.
7. `null` — null origin (use data: URL or file:// simulation in browser context).
8. `https://target.com` — baseline (should be allowed).
9. `https://anything.target.com.attacker.example.com` — nested subdomain bypass.
10. `https://target.com/` — trailing slash (rarely relevant but test).
11. `https://target.com..attacker.example.com` — double-dot obfuscation (unlikely but documented in some browsers).
12. `https://sub.target.com.attacker.example.com` — multi-level confusion.

For each variant, test with a fetch request:

```javascript
// In browser console or via browser_execute_script
fetch("https://target.com/api/user", {
  method: "GET",
  credentials: "include",  // Include cookies/auth
  headers: { "Origin": "https://attacker.example.com" }
}).then(r => r.json()).then(console.log).catch(console.error)
```

Record per variant:

- **Response status**: 200, 401, 403, 400.
- **CORS headers returned**: Allow-Origin, Allow-Credentials.
- **Data accessible**: yes/no (check if response body contains user data).
- **Credentials included**: were cookies/auth headers sent? Did the server respond with `Allow-Credentials: true`?

## Phase 2: Credential Leak Detection

For variants that return 200 + data, test if credentials are accepted:

1. **Cookies**: Preflight request includes cookies if `Allow-Credentials: true` and origin is whitelisted.
2. **Authorization header**: If the endpoint accepts an Authorization header, test if it's returned in the preflight response (should NOT be).
3. **Response contains secrets**: Check if the response body includes API keys, auth tokens, or PII that should only be accessible to the origin user.

Vulnerability matrix:

```
| Variant | Allow-Origin | Allow-Credentials | Data Leaked | Severity |
|---------|---|---|---|---|
| attacker.example.com | attacker.example.com | true | yes, user profile + email | CRITICAL |
| null | * | true | yes (impossible state) | CRITICAL |
| sub.target.com | sub.target.com | true | yes | HIGH (requires subdomain takeover) |
```

## Phase 3: Preflight & OPTIONS Behavior

For POST, PATCH, DELETE requests, a preflight OPTIONS request is required:

1. Send OPTIONS /api/user with the test Origin.
2. Capture: `Access-Control-Request-Method` (POST, PATCH), `Access-Control-Request-Headers` (Authorization, Content-Type).
3. Record the response: `Allow-Methods`, `Allow-Headers`, `Allow-Origin`, `Max-Age`.
4. If the preflight succeeds for the attacker origin, the actual request will also succeed (same CORS check).
5. Test if the preflight response includes `Vary: Origin` — if not, the response may be cached incorrectly across origins.

## Phase 4: Subdomain & Dangling DNS

If target has subdomains:

1. Enumerate subdomains (via DNS zone transfer, public records, certificate transparency).
2. Check if any are dangling (DNS points to defunct service or external provider).
3. If dangling, attempt to register the subdomain on the external provider (e.g., GitHub Pages, AWS S3).
4. Once registered, host JavaScript that fetches the target API with the registered subdomain as origin.
5. If the target allows *.target.com, your subdomain fetch will succeed.

## Submission Gates

- [ ] CORS header baseline captured for 10+ authenticated endpoints.
- [ ] All 12 origin variants tested for at least 5 endpoints.
- [ ] Response status code and CORS headers recorded per variant per endpoint.
- [ ] Credential leak test: `credentials: include` in fetch; verify cookies/auth are sent or leaked in response.
- [ ] Preflight test: OPTIONS request tested for POST/PATCH/DELETE endpoints.
- [ ] Evidence table: per endpoint, per variant, outcome (allowed/denied/leaked).
- [ ] If vulnerability found: documented the exact origin variant, the endpoint, and the leaked data.

## See Also

- `packs/api_security/SKILL.md` — API authentication and authorization.
- `packs/web_hunter/SKILL.md` — endpoint discovery.
- `packs/triage_validation/SKILL.md` — 7-question gate.

## Exclusions

- Do not register domains or DNS records that violate your test account's scope.
- Do not attempt subdomain takeover on assets outside your control.
- Do not exhaust rate limits on preflight requests (OPTIONS is not rate-limited separately on most servers, but test with reasonable parallelism).
