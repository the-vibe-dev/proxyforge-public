---
name: api_security
description: API Security: API discovery, authz, schema, and business-flow testing.
---
# API Security

## Use When
API discovery, authz, schema, and business-flow testing. Apply this pack for roles: researcher, developer, executor.

## Operating Rules
- Follow SecHive shared scope, evidence, memory, and execution policy.
- Produce dense, machine-reviewable notes with fields: `obs`, `evidence`, `risk`, `next`, `blocked`.
- Mark uncertainty explicitly; do not promote scanner hits to findings without validation.
- If execution is allowed, propose the least intrusive action first with noise level and evidence path.

## Role Focus
Map endpoints, auth boundaries, object ownership, and safe PoCs.

## Exhaustive API Surface Method
- Treat public docs, OpenAPI/Swagger, GraphQL introspection errors, JS bundle route literals, network logs, source routers, mobile clients, and form actions as equal API discovery inputs.
- If browser coverage is thin, switch to raw HTTP/API discovery from current-run endpoint candidates, forms, JS route literals, response headers, and same-origin docs before declaring the route family exhausted.
- Extract JavaScript submit targets, AJAX URL literals, content-type hints, CSRF field names, and hidden parameter names from current-run HTML and bundles. Use those as the first API replay targets when visible pages return generic method errors.
- Recompute the API skill route whenever a new API schema, object ID shape, auth token, role marker, or error family appears.
- Build a method/object matrix for each endpoint family: method, auth required, object identifier shape, owned reference, unowned reference, malformed reference, role requirement, state change, and response delta.
- For every non-public endpoint, assume authorization must be enforced locally at that endpoint. Do not trust that a previous login, frontend route guard, API key, or gateway check covers record-level access.
- Include method tampering in the matrix: allowed method, unexpected method, method override header/body fields, and action-like routes that accept both resource and workflow operations.
- In full proof mode, continue across all meaningful endpoint families instead of stopping after the first IDOR/auth finding. Cap only when repeated identical evidence shows the family is exhausted.
- Close each high-value endpoint family explicitly as `validated`, `negative evidence`, `blocked`, or `capped`; do not end a proof-oriented run with the family only partially explored.
- Promote only runtime-validated findings, but preserve unvalidated endpoint candidates separately so the operator sees coverage.
- Keep endpoint/content-type matrices budget-aware by applying per-request timeouts. A hung method, body parser, or content type is a response class to record, not a reason for the API lane to stall.

## CMS REST Surfaces
- For WordPress REST, enumerate namespaces and routes to identify plugins, custom endpoints, auth requirements, object IDs, and exposed backup/export functionality.
- Prioritize plugin-specific REST routes over generic post/page enumeration once the CMS and active plugin family are known.
- If REST evidence shows backup/export or file-management capabilities, hand off to web/PoC validation for public artifact checks and bounded file-read validation.

## API Differential And State Handling
- For object IDs, tenant IDs, user IDs, and role-bound routes, compare owned, unowned, missing, and malformed references with the same session before broad route fuzzing.
- When an app uses typed identifiers such as Mongo/ObjectId, UUID, ULID, slug, or signed IDs, do not hammer incompatible raw numeric guesses into typed routes. First collect app-issued IDs from registration redirects, profile links, API JSON, hidden form fields, cookies/JWT claims, source schemas, or list/search endpoints, then run owned/unowned comparisons with valid identifier shape.
- For invited login, registration, employee/admin, profile, info, and start-time flows, model the whole session lifecycle. Preserve cookies, CSRF values, redirects, issued IDs, and role hints, then replay only the next app-indicated routes before broad endpoint mutation.
- Treat distance, rank, sequence, invitation, or "next user" hints as identity-pivot evidence. Derive the likely target relation from app-visible state and obtain a valid route identifier through normal app flows before testing authorization.
- Preserve status, body length, key fields, and authorization headers/cookies used for each comparison.
- If an auth hint or admin-only route appears, convert it into a post-auth route hypothesis and hand it to credential/session validation.
- When API responses are quiet, use boolean or length differential checks rather than assuming failure from lack of visible output.
- If server-side session storage or debug session output is visible, compare what the route validates against what the route later consumes. A mismatch between validated identity and consumed identity is a high-priority state-desync hypothesis.
- For role-gated routes, test one same-session state-change pair when source or runtime evidence shows mutable shared session state; otherwise keep to normal owned/unowned differential checks.
- For JWT or bearer-token APIs, decode claims and test proof-safe boundary questions: algorithm/header confusion signals, issuer/audience mismatch, expiration or logout replay, role claim trust, user-id claim trust, and whether server-side state invalidates old tokens.
- For auth endpoints, compare generic error text, status, length, selected headers, and timing across nonexistent user, wrong password, locked/disabled user when available, and valid-login baseline. Treat discrepancy as enumeration or timing-candidate evidence, then cap.
- When identical responses repeat across a compact probe set, record that family as negative evidence or capped and switch to the next strongest route/object/state hypothesis instead of retrying the same shape.
- For password reset, security-question, or recovery flows, model the complete state machine: discovery, verification prompt, token/code issue, token/code use, password change, and post-change session behavior. Test whether tokens are bound to user, stage, freshness, and single use.
- For security-question recovery, record only the prompt category, evidence source class, and success/failure state. Do not publish personal answers or scrape unrelated real people; stay inside lab identities, owned accounts, or operator-approved OSINT boundaries.
- When an endpoint accepts duplicate parameters or duplicate JSON keys, compare the validator's view against the persistence/action view. Preserve raw request bytes or a replay spec so ambiguity is reproducible.
- For callback, JSONP, or cross-origin shaped APIs, test whether authenticated data can be read by an untrusted browser origin. Callback support without sensitive readback is a candidate, not a finding.

## Workflow And Business API Checks
- For create -> validate -> approve -> finalize workflows, invoke each step in order once, then try one direct later-stage request and one replayed token/request from the wrong stage.
- For checkout, order, wallet, profile, address, coupon, membership, invite, support, and admin actions, record the resource owner, actor role, workflow state, price/quantity/rank fields, and whether the server recomputes or trusts client-supplied values.
- For mass-assignment surfaces, compare normal request bodies to expanded bodies containing role, owner, price, balance, verified, status, coupon, discount, points, and workflow-state fields only when those fields are observed in responses, schemas, source, or client bundles.
- If a login page exposes app-provided credentials or a test account, submit that exact workflow once and then prioritize the post-auth route/API map. Do not replace invited workflow completion with generic login payload spray.
- If the response advertises the next action in text, headers, scripts, or redirects, follow that action before trying unrelated payload classes.
- For prototype-style JSON sinks, test only compact harmless pollution indicators when Node/JavaScript object merge behavior is evidenced by source, dependencies, errors, or JSON body handling.
- For money-like, points-like, wallet, coupon, membership, basket, order, and quantity APIs, check whether the server recomputes value from authoritative state after each step. A client-visible disabled button or UI-only validation must be followed by a direct API replay.
- For review, feedback, contact, complaint, support, and profile APIs, compare hidden/implicit owner fields against server-derived identity. Test one harmless owner mismatch and verify with readback.
- For anti-automation controls, model binding to account, session, IP/header, challenge ID, action, and freshness. Use low-volume proof only.

## Token, Key, And Crypto API Checks
- Decode bearer tokens and signed IDs locally when format permits. Treat decoded claims as untrusted hints until the server accepts a changed token or rejects it consistently.
- Test token acceptance boundaries with owned or lab identities: algorithm confusion, missing signature acceptance, key confusion, stale token reuse, audience/issuer mismatch, and server-side logout invalidation.
- If an API exposes public keys, encryption keys, salts, or token-generation hints, route to crypto/token validation and preserve how the key was discovered.
- For opaque codes such as coupons, invitations, continuation codes, reset tokens, or order IDs, gather multiple current-run examples and classify length, alphabet, date/role/value correlation, and replay/freshness behavior before attempting derivation.

## Cross-Origin API Checks
- For CORS, JSONP, and unauthenticated identity endpoints, prove browser feasibility: whether cookies are sent, whether custom headers trigger preflight, whether the response is readable, and whether sensitive fields are present.
- For CSRF, prove a state-changing request can be produced cross-site with the victim's ambient credentials and without custom headers that a browser cannot send.
- For redirects that feed API or URL-fetch behavior, compare parser interpretation between the redirect validator, HTTP client, and browser.

## GraphQL Method
- Treat GraphQL endpoints as API schemas even when introspection is disabled. Use errors, operation names, persisted-query hashes, client bundles, network logs, and source to recover query, mutation, type, and object names.
- Build the same authz matrix for queries and mutations: unauthenticated, low-privilege, owned object, unowned object, malformed object, role-gated field, and state-changing mutation.
- Test field-level authorization, not only endpoint authorization. A single `/graphql` route can expose public fields, private fields, and privileged mutations behind the same transport.
- For Node-style global IDs or relay nodes, derive valid IDs from app responses before testing unowned access. Preserve decoded ID shape when decoding is harmless and local.
- For batch, alias, depth, and introspection behavior, record risk and coverage. Do not run resource-impact stress tests unless explicitly authorized.

## CSRF, CORS, And Browser Token Boundaries
- For cookie-authenticated state-changing routes, check whether the route requires a server-validated anti-CSRF token, same-site cookie posture, origin/referer validation, or fetch-metadata behavior. Do not report CSRF from missing token alone; prove a feasible cross-site request shape.
- For JSON APIs, note whether content type, preflight, custom headers, and credentials mode make browser-based CSRF practical.
- For CORS, compare allowed origin, reflected origin, credentialed responses, exposed headers, and token-bearing responses. CORS is impact-relevant when a browser from an untrusted origin can read sensitive authenticated data.
- Treat CSP and security headers as exploit-shaping data: they change the XSS/browser proof path but rarely confirm a finding by themselves.

## WebSocket And Event API Method
- Treat WebSocket, SSE, and long-poll endpoints as APIs with their own auth, origin, object, and message authorization boundaries.
- Capture handshake headers, cookie/token binding, origin handling, subprotocols, and the first normal message flow.
- For each message type, build a compact matrix: unauthenticated, stale session, wrong origin where safe, owned object, unowned object, role-gated action, malformed schema, and replay.
- If a WebSocket action changes state, pair it with an HTTP/API readback so proof is visible in saved artifacts.

## API Chain Questions
- If an auth bypass works, what admin/function/object routes become reachable?
- If an object read works, can object write, delete, export, checkout, or workflow action be tested with the same valid identifier shape?
- If schema/docs expose hidden routes, which routes change state, read sensitive data, call URL fetchers, parse files, or cross tenant boundaries?
- If an endpoint accepts URLs, filenames, templates, expressions, callbacks, redirects, or uploads, hand off to the matching web/PoC skill and return with the runtime result.
- If an endpoint leaks stack traces, framework names, route names, file paths, or dependency versions, immediately feed that evidence to vulnerability intel and route discovery before generic fuzzing.

## Schema-Driven API Validation
- Treat API schemas, generated route maps, client SDKs, mobile traffic, and JavaScript route literals as candidate truth, not proof. Convert them into endpoint, method, auth-state, object-shape, content-type, and role matrices.
- Prioritize endpoints that read or mutate object-owned records, roles, workflow state, money-like fields, file/import state, callbacks, URLs, or nested private objects.
- For each endpoint family, record `validated`, `negative_evidence`, `blocked`, or `capped` with a replay artifact or explicit closure note.

## Property Overposting And Response Minimization
- Test overposting only with fields evidenced by schemas, responses, source models, hidden inputs, or client bundles. Do not spray arbitrary admin fields.
- Compare normal bodies with compact expanded bodies containing server-owned fields such as owner, role, status, verified, price, balance, quota, workflow state, tenant, or permission.
- Promotion requires server-side acceptance, persistence, authorization effect, or changed workflow behavior. Reflected ignored fields are negative evidence.
- For excessive response data, classify each leaked field by actor, object relation, workflow need, and sensitivity. Preserve key names and redacted structure rather than raw values.

## Realtime, Graph, And Browser API Boundaries
- For realtime transports, build the same auth/object/message matrix used for REST: unauthenticated, stale, wrong origin, owned, unowned, malformed, and role-gated.
- For graph-like APIs, test field-level authorization and mutation authorization separately from endpoint reachability.
- For browser-token APIs, evaluate CSRF and CORS by feasible browser request shape: content type, preflight, custom headers, SameSite, credential mode, Origin/Referer, and readback.

## JWT/OIDC/SAML Token Validation Attacks
- Inventory token formats (JWT, JWE, OAuth bearer, OIDC id_token, SAML assertion) and the validation paths that consume them. For each, decode header/claims locally and verify which library validates and which paths trust the decoded claims without re-validation.
- For JWT: probe `alg=none` (and case variants), RS256<->HS256 confusion using the published public key as HMAC secret, `kid` injection (path traversal, SQL fragments, JWK lookup poisoning), `jku`/`x5u` redirects to attacker JWKS origin, and JWE `alg=dir` with known/default content-encryption keys.
- For OIDC/OAuth: test `redirect_uri` matching strictness (exact vs substring vs prefix; open-redirect chained through registered URI), PKCE downgrade (non-PKCE code accepted without `code_verifier`), missing/ignored `state` and `nonce`, response-mode downgrade (form_post -> fragment), and refresh-token rotation behavior.
- For SAML SP: test assertion replay past `NotOnOrAfter`, audience-mismatched assertions, and XSW1-8 signature-wrap variants where the signed assertion is moved to a position the verifier inspects while attacker-injected unsigned assertions reach the application.
- All forged-token findings must be corroborated end-to-end: response reflects the forged identity in an authenticated action, not just decoder echo or log entry.
- Tools: `jwt_tool` for fuzz/forge; `python -c` snippets for HS-of-public-key minting; a SAML signature-wrap testing extension for XSW; intercepting proxy + browser for OIDC flow capture.
- Theories: `jwt.none_alg_acceptance`, `jwt.kid_jku_x5u_confusion`, `jwt.rs_to_hs_key_confusion`, `jwt.jwe_direct_key_mode`, `oidc.redirect_uri_and_pkce_bypass`, `saml.assertion_replay_and_xsw`, `crypto.token_signing_confusion`. Playbook: `playbook.token_signature_validation_attacks`.

## Exclusions
No out-of-scope, destructive, persistence, DoS, credential-stuffing, or secret-disclosure actions.
