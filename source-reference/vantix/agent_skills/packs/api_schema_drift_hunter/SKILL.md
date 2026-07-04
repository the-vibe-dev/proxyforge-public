---
name: api_schema_drift_hunter
description: API schema drift and surface discrepancy hunting. Documented vs. observed endpoint mismatch, OpenAPI/GraphQL gaps, undocumented endpoints, parameter overposting, deprecated endpoints still live.
---
# API Schema Drift Hunter

API schemas (OpenAPI, GraphQL, Protobuf) document the intended API surface, but production implementations frequently diverge. Undocumented endpoints, extra parameters, deprecated endpoints still responding, and method mismatches create attack surface that is invisible to passive API discovery but readily available to attackers who compare schemas to observed traffic. Findings here lead to hidden endpoints, overposting, and privilege escalation, and pay $1k–$8k+ depending on what the gap exposes.

This pack composes with `shared/scope_guard.md`, `packs/api_security/SKILL.md`, and `packs/web_hunter/SKILL.md` (for endpoint discovery).

## When to Use

- Target publishes an OpenAPI specification, GraphQL schema, or Protobuf definitions.
- Frontend or mobile application code is available (decompiled APK, minified JS, etc.).
- API traffic can be captured and analyzed against documented schema.
- Multiple API versions or schema versions exist.
- Documentation suggests deprecated endpoints or legacy API routes.

## Operating Rules

- Scope: schema drift hunting is passive enumeration. Testing undiscovered endpoints must be explicitly in scope.
- Comparison: document gaps between schema and observed behavior systematically. One discrepancy is an anomaly; multiple suggest a pattern.
- Overposting: test overposting candidates with benign values first (role fields, timestamps) before attempting privilege escalation.
- Deprecated endpoints: confirm deprecation by checking schema metadata before testing. Some "deprecated" endpoints are intentionally supported.
- Cleanup: if overposting discovers writeable fields, do not modify production data. Use test accounts or development environments.

## Phase 0: Schema Collection

### Gather OpenAPI specs

```bash
# Standard locations:
curl -s https://target.com/openapi.json
curl -s https://target.com/swagger.json
curl -s https://target.com/api/docs/openapi.json
curl -s https://target.com/api/v1/docs

# GraphQL introspection:
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name } } }"}'

# Protobuf reflection (gRPC):
grpcurl -plaintext target:50051 describe
```

### Extract from frontend

```bash
# JavaScript bundle:
grep -r "fetch\|axios\|fetch" src/ | grep -oE '\/api\/[^"'\'']+' | sort -u

# Decompiled APK:
apktool d app.apk && grep -r "api/" smali/ | grep -oE '\/api\/[^"'\'']+' | sort -u
```

## Phase 1: Schema vs. Observed Endpoint Enumeration

Compare documented endpoints to observed traffic:

1. Extract all endpoints from OpenAPI spec:
   ```bash
   jq '.paths | keys[]' openapi.json
   ```
2. Extract all endpoints from observed traffic (HAR, proxy logs, APK strings):
   ```bash
   grep -oE '\/api\/[a-zA-Z0-9_/]+' traffic.har | sort -u
   ```
3. Find undocumented endpoints (in traffic, not in schema):
   ```bash
   comm -23 <(observed | sort) <(schema | sort)
   ```
4. For each undocumented endpoint, document:
   - Method (GET, POST, etc.)
   - Parameters
   - Expected behavior

## Phase 2: Method and Parameter Mismatch

Check whether endpoints support methods or parameters not in the schema:

1. For each documented endpoint, test additional methods:
   ```bash
   # Schema says GET /users/<id>
   # Test:
   curl -X POST https://target.com/users/123 -d '{"role": "admin"}'
   curl -X PUT https://target.com/users/123 -d '{"email": "attacker@example.com"}'
   curl -X PATCH https://target.com/users/123 -d '{"is_admin": true}'
   curl -X DELETE https://target.com/users/123
   ```
2. If additional methods are accepted, method mismatch is possible.
3. For each endpoint, test additional parameters not in the schema.

## Phase 3: Overposting Candidate Discovery

Schemas often document client-facing parameters but not backend-accepted parameters:

1. Compare schema parameters to backend-accepted parameters (from source code, APK strings, or traffic analysis).
2. Identify fields that are backend-writeable but not client-exposed (role, is_admin, email, created_date, etc.).
3. Test overposting by sending these fields:
   ```bash
   curl -X POST https://target.com/api/users \
     -H "Content-Type: application/json" \
     -d '{
       "username": "test",
       "password": "test",
       "email": "test@example.com",
       "role": "admin",
       "is_verified": true
     }'
   ```
4. If overposting fields are accepted and affect system state, overposting vulnerability is present.

## Phase 4: Deprecated Endpoint Still Live

Endpoints marked as deprecated in schema may still respond:

1. Identify deprecated endpoints in the schema:
   ```bash
   jq '.paths[] | select(.deprecated == true) | keys' openapi.json
   ```
2. For each deprecated endpoint, test if it still responds and works.
3. Attempt to use the deprecated endpoint to bypass validation or access legacy functionality.

Example:
- `/api/v1/users/create` deprecated, but still accepts requests
- `/api/v2/users` has validation, but `/api/v1/users/create` does not
- Attacker uses v1 to bypass v2 validation

## Phase 5: API Version Mismatch

Test whether API versions are enforced or bypassable:

1. Identify all documented API versions (v1, v2, v3, etc.).
2. For endpoints that exist in multiple versions, test calling v2 endpoint with v1 parameters or vice versa.
3. If version constraints are not enforced, version confusion attacks are possible.

## Phase 6: GraphQL Overposting via Introspection

GraphQL schemas expose all available fields via introspection:

1. Query the schema for all available fields:
   ```bash
   curl -s -X POST https://target.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query": "{ __type(name: \"User\") { fields { name } } }"}'
   ```
2. Compare to fields exposed in the frontend.
3. Identify fields not used by frontend but available via GraphQL.
4. Test requesting these fields in GraphQL queries to discover data exfiltration opportunities.

## Submission Gates

Run `packs/triage_validation/SKILL.md` 7-Question gate. Then:

- [ ] Schema mismatch is documented with proof (schema vs. observed behavior).
- [ ] Undocumented endpoint or parameter is confirmed and callable.
- [ ] Method mismatch or parameter overposting is reproducible.
- [ ] Deprecated endpoint still responds and demonstrates divergent behavior.
- [ ] No actual privilege escalation or data modification beyond PoC scope.

## Evidence Artifacts

- `01_schema_collection.txt` — all collected schemas (OpenAPI, GraphQL, Protobuf, APK strings).
- `02_endpoint_comparison.txt` — documented vs. observed endpoints with differences highlighted.
- `03_method_mismatch_test.txt` — undocumented methods accepted on documented endpoints.
- `04_parameter_overposting_test.txt` — overposting payload, proof of field acceptance and effect.
- `05_deprecated_endpoint_test.md` — deprecated endpoint still responding, behavior comparison.
- `06_graphql_field_discovery.txt` — introspection results showing overposting-eligible fields.
- `README.md` — verified gates per evidence_rules.md.

## Exclusions

- No modifying production data via overposting beyond PoC.
- No accessing other users' data via schema drift.
- No triggering denial of service via deprecated endpoints.
- No API version confusion leading to actual attacks on unintended versions.

## See Also

- `agent_skills/packs/api_security/SKILL.md` — API authentication and authorization
- `agent_skills/packs/web_hunter/SKILL.md` — endpoint discovery and enumeration
- `agent_skills/packs/graphql_hunter/SKILL.md` — GraphQL-specific attack patterns
- External: OpenAPI specification, GraphQL introspection security
