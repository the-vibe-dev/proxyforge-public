---
name: parameter_mutator
description: Systematic parameter mutation and semantic-diff analysis for IDOR, authorization bypass, and business-logic discovery. Tests 14 parameter variants against baseline behavior.
---
# Parameter Mutator

Parameter mutations expose hidden authorization and business-logic boundaries through systematic value transformation and semantic comparison. Most web applications validate one variant (typical input) but fail silently on others (edge cases, encoding, type coercion). By mutating every parameter in every discovered request and comparing responses semantically—not just by status code—this pack surfaces IDOR, mass-assignment, and ownership-leakage findings that isolated testing misses.

This pack composes with `packs/web_hunter/SKILL.md` (endpoint discovery), `packs/api_security/SKILL.md` (authz model), `packs/triage_validation/SKILL.md` (semantic-diff gates), and `packs/skeptic_validator/SKILL.md` (false-positive elimination).

## When to Use

- You have a set of discovered endpoints and valid baseline requests with known ownership (from your own account).
- The endpoint takes identifiers: userId, accountId, resourceId, postId, orderId, email, UUID, or path-embedded IDs.
- The target is multi-user or multi-tenant with documented authorization checks.
- You want to find IDOR and ownership-leakage in bulk without manual hypothesis per endpoint.

## Operating Rules

- Baseline first: capture one successful request from your own account (status 200, owned data returned).
- Time-box mutations: test 5-10 endpoints per session. Each endpoint × 14 variants = ~140 requests; capture in HAR.
- Semantic comparison, not status code: a 403 is clearer than a 200 with leaked data, but the latter is the vulnerability. Parse response bodies for object leakage (userId, email, secret fields).
- Scope discipline: limit mutations to owned/test accounts only. Never mutate to production user IDs without explicit scope approval.
- Document all divergences: status-code changes, response-size deltas, error-text differences, timing anomalies, side effects.

## Phase 0: Baseline Capture

Identify a request with clear ownership:

```bash
curl -H "Authorization: Bearer <your-token>" \
  https://target.com/api/posts/123 \
  -w "\nStatus: %{http_code}\nTime: %{time_total}\n" \
  -o baseline.json

# Expected: 200, your post data with your userId, timestamp, content
cat baseline.json | jq '.'
```

Record:
- Request method, path, headers, body.
- Response status, headers, body (parse for sensitive fields).
- Response size in bytes.
- Response time in milliseconds.

## Phase 1: Identify Mutable Parameters

Scan the baseline request for all parameters (path, query, body):

```
POST /api/posts/123?expand=author
Body: { "postId": 123, "ownerId": "user-abc", "comment": "text" }
Headers: Authorization, Content-Type, X-Api-Version

Parameters to mutate: 123 (path), expand (query), postId, ownerId, comment (body)
```

For each parameter, create 14 variants:

1. **same-user**: replace with your own known ID (should behave identically to baseline).
2. **other-owned**: another valid user ID (known or guessed).
3. **nonexistent**: ID that doesn't exist ("99999", "uuid-zero").
4. **negative**: if numeric, "-1" or "-<original>".
5. **zero**: "0" (often defaults or bypasses range checks).
6. **large**: maximum safe integer or very large UUID.
7. **uuid-swap**: if a UUID, swap to a different valid UUID from your account or another.
8. **url-encoded**: "%<hex>" encoding of special chars.
9. **double-encoded**: "%25<hex>" (percent-encoded percent-hex).
10. **array-instead-of-string**: wrap in `["original"]` if endpoint is JSON.
11. **object-instead-of-string**: wrap in `{"value":"original"}`.
12. **null**: `null` in JSON or empty string in form data.
13. **empty**: zero-length string `""`.
14. **duplicate**: repeat the parameter twice in the request (form-data or query string).

## Phase 2: Systematic Mutation & Capture

For each parameter variant, fire a request and capture semantically:

```bash
# Variant: other-owned
curl -H "Authorization: Bearer <your-token>" \
  https://target.com/api/posts/999 \
  -w "\nStatus: %{http_code}\nSize: %{size_download}\nTime: %{time_total}\n" \
  -o variant_other_owned.json

# Variant: null
curl -H "Authorization: Bearer <your-token>" \
  -H "Content-Type: application/json" \
  https://target.com/api/posts \
  -d '{"postId": null}' \
  -o variant_null.json

# Variant: array-instead-of-string
curl -H "Authorization: Bearer <your-token>" \
  -H "Content-Type: application/json" \
  https://target.com/api/posts \
  -d '{"postId": [123]}' \
  -o variant_array.json
```

Store all responses in a timestamped directory. Parse each for:
- HTTP status code.
- Content-Type and size.
- JSON/XML structure (parse, don't just diff bytes).
- Presence of sensitive fields (userId, email, apiKey, secret).
- Error message content (compare across variants).
- Response time (variance >100ms is notable).

## Phase 3: Semantic Comparison & Divergence

Compare each variant to baseline:

| Variant | Status | Size | Sensitive Fields | Error Text | Time | Classification |
|---------|--------|------|-------------------|------------|------|-----------------|
| baseline (own) | 200 | 256 | userId=abc | — | 45ms | ✓ expected |
| other-owned | 200 | 256 | userId=xyz | — | 42ms | ⚠️ IDOR candidate |
| nonexistent | 404 | 89 | — | "Post not found" | 38ms | ✓ expected |
| null | 500 | 152 | — | "Null pointer" | 1200ms | ⚠️ crash / logic bug |
| array | 200 | 287 | userId=abc | — | 48ms | ⚠️ type coercion |

**Findings trigger on:**
- **Status divergence** (200 vs 403): authorization applied to one variant, not the other.
- **Sensitive-field leakage** (object ownership via userId/email in response).
- **Size divergence >20%**: entire response structure changed (may indicate different business-logic path).
- **Error-text differences**: validator rejected one variant but not another (parser differential).
- **Timing anomaly** (>3x baseline): may indicate different code path or timing-side-channel.
- **Side effects** (new objects created, state modified in database): duplicate or boundary-bypass finding.

## Theories This Pack Owns

- `idor.parameter-swap` (direct object reference bypass via ID change)
- `authz.null-bypass` (null/empty parameter defaults to permissive state)
- `authz.encoding-bypass` (URL/double-encoding bypasses validator)
- `business-logic.duplicate-key` (duplicate parameter processed inconsistently)
- `mass-assignment.array-coercion` (array variant unwraps to scalar, bypasses validation)
- `mass-assignment.object-coercion` (object variant bypasses type check)

## Tooling

- `curl` with `-w` for semantic metadata (status, size, time).
- `jq` for JSON parsing and field extraction.
- intercepting proxy for transparent capture and replay.
- Custom mutation scripts (Python/bash) to generate 14 variants per parameter.

## See Also

- `packs/web_hunter/SKILL.md` — endpoint discovery source
- `packs/api_security/SKILL.md` — authz model classification
- `packs/triage_validation/SKILL.md` — semantic-diff gates for IDOR proof
- `packs/skeptic_validator/SKILL.md` — false-positive elimination

## Exclusions

- No mutation against production user IDs outside your authorized test scope.
- No attempt to trigger unrelated bugs (DoS, code injection) as side effects.
- No persistence of mutated state beyond proof capture (revert or request cleanup).
- No mutations of payment/critical fields without explicit scope approval.
