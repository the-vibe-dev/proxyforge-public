---
name: web_hunter
description: Web Hunter: web application discovery, fuzzing, and validation guidance.
---
# Web Hunter

## Use When
web application discovery, fuzzing, and validation guidance. Apply this pack for roles: recon, researcher, developer, executor.

## Operating Rules
- Follow SecHive shared scope, evidence, memory, and execution policy.
- Produce dense, machine-reviewable notes with fields: `obs`, `evidence`, `risk`, `next`, `blocked`.
- Mark uncertainty explicitly; do not promote scanner hits to findings without validation.
- If execution is allowed, propose the least intrusive action first with noise level and evidence path.

## Role Focus
Rate-limit web tests, start narrow, and preserve request/response evidence.

## General Web Assault Loop
- Build a living surface map before declaring failure: routes, methods, forms, static files, JS bundles, source maps, API schemas, upload paths, redirects, URL-fetch parameters, parser endpoints, exports/imports, admin paths, docs, and backup/config artifacts.
- Mine client bundles and HTML config blobs for route literals, API base paths, role names, feature toggles, third-party service settings, security metadata, upload paths, redirect allowlists, and hidden admin/config namespaces. Feed every high-confidence route back into API/browser validation.
- After each new high-confidence surface, loop back through skill triage and vulnerability intel instead of continuing with the old plan. New evidence can change the right specialist.
- Treat each new route as a hypothesis source: identify input-bearing parameters, auth boundary, object identifiers, state changes, parser behavior, and possible output channels.
- Do not stop after the first class of success. Convert the success into a capability and ask what it unlocks next: post-auth sweep, source/config disclosure, privileged route, upload/include intersection, local service, SSRF target, or business-flow bypass.
- In full proof mode, enumerate every meaningful in-scope surface family until it is validated, disproven, or capped by repeated identical evidence. Still preserve target scope, request evidence, and cleanup notes.
- If browser coverage stays at `0-2` meaningful routes, switch to raw HTTP/API discovery from current-run forms, JS literals, docs, and endpoint candidates before declaring the web surface exhausted.
- If the browser misses routes that JS, API docs, network logs, source, or errors reveal, revisit browser/recon with those exact route families and then re-run skill matching.

## Web Test Coverage Matrix
- Track coverage across these families before declaring a web run complete: information gathering, configuration/deployment, identity/authentication, session management, authorization, input validation, API/schema, file/upload/parser, business logic, client-side/browser, error handling/logging, and cryptography/transport.
- For each family, record one of: validated finding, validated capability, candidate with next action, negative evidence, not applicable, or blocked by scope/tooling.
- If a family is skipped because the surface was not discovered, loop back to recon/browser/client-bundle/API discovery once before final reporting.
- If a family has only scanner/source evidence, produce the shortest live-validation packet or a non-promotion reason.

## Training-Grade Weakness Search
- Do not search for named challenge answers or copy public solution steps. Search for transferable weakness classes and prove them from the current target's own routes, scripts, responses, and state changes.
- For deliberately vulnerable, training, or CTF-like web apps, use the score or solved-state only as a secondary oracle. The reusable evidence is the underlying security boundary that failed.
- Treat client-visible "unavailable", "disabled", hidden navigation, hidden fields, and client-side route guards as prompts to test whether the server enforces the same invariant.
- When a page behaves like an app shell, prioritize bundle and runtime mining before broad wordlists: routes, components, translation files, build manifests, generated license files, feature flags, hidden admin/support/privacy/profile paths, and API method names.
- Check common operational disclosures generically: metrics endpoints, security policy files, logs, generated docs, backup files, key directories, static directory listings, language catalogs, source maps, third-party license inventories, and stale build artifacts.
- For content-driven apps, inspect image/video/subtitle/document metadata and companion files as discovery signals. Validate only harmless reads and preserve provenance.
- For chatbot, support, coupon, contact, feedback, or assistant-like flows, test business logic pressure and state handling with benign repeated prompts or normal inputs first; avoid prompt injection or social-engineering content unless explicitly authorized.

## Client Bundle And SPA Route Mining
- Extract route tables, lazy-loaded chunk names, component names, navigation labels, guard names, and feature flags from bundled JavaScript and HTML config.
- Search for semantic words rather than answers: admin, support, debug, metrics, score, profile, privacy, wallet, token, coupon, upload, complaint, invoice, redirect, sandbox, legacy, language, encryption, key, backup, log, and route aliases.
- Distinguish three route classes: browser-only hidden route, server-backed API route, and static artifact path. Each needs different validation evidence.
- If a hidden route requires auth or role state, follow the normal login or registration path first, then compare low-privilege and role-gated access.
- If source maps or build manifests are exposed, use them only to identify reachable routes and sinks; return to runtime proof before promotion.

## Static Artifact And Directory Exposure
- Enumerate from current evidence before brute force: links, bundle literals, error paths, robots/security files, generated docs, asset directories, uploaded filenames, package manifests, license lists, translation paths, and API docs.
- For suspected backup or filtered static files, test extension-appending, URL encoding, double encoding, content negotiation, and path normalization only when the route shows file-handler behavior.
- For logs and operational files, preserve redacted structure and timestamps. Do not collect more sensitive content than needed to prove exposure.
- If key material or cryptographic config is exposed, treat it as a crypto/token-boundary candidate and hand off to API or payload validation.

## Workflow And UI-Invariant Checks
- For disabled buttons, hidden inputs, client-side validators, price/quantity fields, role fields, coupon fields, and membership or wallet actions, capture the normal network request and replay one minimal server-side invariant change.
- If the server rejects the mutation, record negative evidence. If it accepts or changes state, preserve before/after readback.
- For contact, feedback, review, profile, privacy, and support flows, inspect hidden fields and server responses for user identifiers, role hints, object IDs, and owner fields before mutating anything.
- For checkout, order, basket, wallet, and coupon flows, record whether the server recomputes totals, ownership, balance, discounts, and workflow state or trusts client values.

## Expand Every Discovered Surface
- Any time you discover a NEW surface — a previously-unseen vhost, an internal port, a hidden route, an admin endpoint, an API namespace, a separate WSGI app, a sub-application mounted at a path, an upstream service named in a header or stack trace — treat it as a SEPARATE application and run the full assault loop scoped to it. A single probe or single error response is NEVER reason to abandon a surface.
- Minimum expansion when a new surface is detected:
  - GET `/` + capture body; mine for links / forms / route literals / JS chunks
  - List-style endpoints: `/devices`, `/items`, `/users`, `/api`, `/api/v1`, `/list`, `/catalog`, `/index`
  - For every name returned by a list endpoint, probe `/<list_root>/<name>`, `/<list_root>/<name>/status`, `/<list_root>/<name>/info`, `/<list_root>/<name>/details`, `/<list_root>/<name>/config`
  - Admin / debug / health endpoints: `/admin`, `/admin/`, `/console`, `/dashboard`, `/debug`, `/debug/vars`, `/debug/pprof`, `/health`, `/healthcheck`, `/status`, `/info`, `/version`, `/metrics`, `/management`, `/system/info`
  - Flag / secret-leak conventional paths: `/flag`, `/flag.txt`, `/private/flag`, `/internal/flag`, `/devices/flag/status`, `/api/flag`, `/api/secret`, `/secret`
  - OPTIONS `/` to enumerate allowed methods; probe any non-GET method advertised
- Declare a discovered surface exhausted only after at least 12 distinct paths have been probed AND every link / route literal mined from the responses has been followed.
- Do NOT collapse multiple distinct internal surfaces into one finding — each gets its own validated finding with the full request/response evidence pair.
- Anti-pattern guardrails:
  - One 500-response from a single endpoint on a surface is NOT a reason to abandon the surface (the endpoint may be hard-coded to return 500; other endpoints on the same surface may serve the real content).
  - One "Not authorized" response from a single endpoint is NOT a reason to abandon the surface — internal surfaces often have NO auth at all and trust the upstream layer (proxy / IP allowlist / Host header) for gating. Try other paths on the same surface unauthenticated before assuming auth is required globally.
  - A successful Host-header / proxy / port pivot that lands on a different backend is a high-value win, not an exit point — that's the moment to expand harder, not pivot away.

## Vhost / Host-Header Routing Discovery
- When any response reveals proxy/backend infrastructure (`Server: haproxy`, `Server: nginx`, `Server: Apache`, `Via:`, `X-Forwarded-*`, `X-Upstream-Proxy`, `traefik`, `envoy`, `cloudfront`, `cdn`, an error page mentioning a backend hostname, or a docker-compose-style internal hostname leaking in a stack trace), STOP and test Host-header-based internal routing before continuing.
- Build the vhost candidate list from current-run evidence first (any hostname seen in error pages, redirect Location headers, JSON body fields, JS literals, robots, sitemap, proxy capture logs, X-Forwarded-Host) and ADD these canonical generics:
  `internal.router  internal.admin  internal.api  internal.local  admin.local  admin.internal  mgmt.internal  mgmt.local  api.internal  api.local  dashboard.internal  console.internal  private.local  backend.local  upstream.local  proxy.local  localhost  127.0.0.1  0.0.0.0  metadata  metadata.google.internal  169.254.169.254`
- For each candidate, send the same baseline `GET /` with `Host: <candidate>` and diff the response: body sha1, status, content-length, page title, unique tokens (admin/debug/internal/devices/dashboard/login). Any material divergence = an internal vhost is reachable.
- **CRITICAL port-confusion rule**: when target evidence reveals an internal backend address like `haproxy:8001`, `nginx:8002`, `backend:80`, or any `<service>:<port>`, that port is the **container-internal port**. It is almost never the externally-exposed port — Docker/Compose port mappings publish a DIFFERENT host-side port (e.g. internal 8001 -> external 33232). Do NOT try the internal port externally: `curl http://target:8001/...` will return "Connection refused" because nothing on the host machine listens on 8001. Always test `Host: <internal-vhost>` against the ORIGINAL target port (the one the operator's task brief named) FIRST, before chasing any internally-disclosed port number.
- WHEN A HOST HEADER UNLOCKS A DIFFERENT RESPONSE, treat the internal vhost as a SEPARATE application and run a full assault on it. Do NOT abandon it after one or two probes. Minimum sweep against each discovered internal vhost, in this order:
  1. `GET /` (capture body + parse links/forms/route literals)
  2. `GET /devices` then for each device listed: `GET /devices/<device_name>/status`, `GET /devices/<device_name>`, `GET /devices/<device_name>/info`
  3. `GET /api`, `GET /api/`, `GET /api/v1`, `GET /api/v1/`, `GET /api/devices`, `GET /api/admin`, `GET /api/internal`, `GET /api/debug`, `GET /api/flag`, `GET /api/status`
  4. `GET /admin`, `/admin/`, `/admin/index`, `/administration`, `/internal`, `/internal/`, `/private`, `/management`, `/console`, `/dashboard`, `/debug`, `/debug/vars`, `/debug/pprof`, `/healthcheck`, `/health`, `/status`, `/info`, `/metrics`, `/version`, `/system/info`
  5. `GET /flag`, `GET /flag.txt`, `GET /devices/flag/status`, `GET /devices/flag`, `GET /api/flag`, `GET /private/flag`, `GET /internal/flag`, `GET /admin/flag`
  6. `OPTIONS /` to enumerate allowed methods; then any non-GET method the OPTIONS surface advertises.
  7. Mine the responses for `<a href=`, `fetch(`, `axios.get(`, route literals — feed each new path back into the matrix.
- Common gotchas the agent must NOT forget:
  - Internal vhosts often have NO auth at all — they trust the proxy to gate access. A `Host: internal.<X>` request that succeeds in front of haproxy/nginx is fully trusted by the backend.
  - Endpoints like `/devices`, `/devices/<x>/status`, `/internal/*`, `/private/*`, `/api/internal/*`, `/admin/api/*` on internal vhosts commonly serve admin / secret / flag data with no auth at all.
  - The proxy's own error body or `X-Forwarded-Host` header often disclosed the canonical internal vhost name — read those bodies, don't skip them.
  - A single 500 response from one path on the internal vhost is NEVER reason to abandon the vhost. Probe at least 12 distinct paths from the sweep above before declaring the internal vhost exhausted.
- Promote each material vhost divergence to a validated finding with class `vhost_routing_internal_exposed` and preserve the request/response pair. Do NOT collapse multiple distinct internal vhosts into one finding.

## Shell-Safe Request Construction
- Treat every discovered or guessed path, query, header value, cookie value, and form value as untrusted data when building shell commands.
- Put candidate paths in quoted arrays or newline-delimited files, pass them to tools as data, and quote every expansion; never inline raw candidates into a shell `for` list.
- Preserve exploit-critical bytes with URL encoding or `--path-as-is` when needed, but do not let metacharacters such as `;`, `&`, `|`, `$`, backticks, spaces, quotes, `<`, or `>` become shell syntax.
- If a candidate breaks command parsing, record that as tooling error evidence, rebuild the probe with safe quoting, and continue the same validation path instead of abandoning the surface.
- For multi-header, auth-scheme, cookie, or method matrices, prefer a tiny Python `requests` script or a newline-delimited data file read with `while IFS=$'\t' read -r ...`; avoid nested shell heredocs or inline command substitution around values that contain quotes, commas, parentheses, or base64 padding.
- Treat shell parse errors such as `unexpected EOF`, `bad substitution`, or closed stdin as probe tooling failures, not target evidence; immediately rerun the same compact matrix through the safer Python/data-file form.
- Add per-request timeouts to every raw HTTP loop. If a payload hangs the parser or transport, save that as timeout-class evidence and continue with the next bounded probe instead of blocking the browser/API proof loop.

## Authenticated Surface Pivoting
- When SQL injection, auth bypass, or valid credential material yields a session, immediately run a compact authenticated surface sweep before deeper cracking or route fuzzing.
- In the authenticated sweep, prioritize upload/import/export/admin/profile/template/report/invoice/document routes and preserve the first request/response pair for each new privileged page.
- When registration or onboarding returns a user number, rank, distance, invitation code, or profile redirect, preserve it as structured state. If the profile route uses a typed backend identifier, find the typed ID through normal app links/API/session data before trying neighboring-account authorization.
- For multi-step registration/login/profile flows, cap repeated form-family probes: after one baseline path, one authenticated replay, and at most one compact variant matrix, stop if the response shape is unchanged and write negative evidence instead of replaying the whole workflow with more object-expression guesses.
- Require stateful workflow completion before capping auth-like surfaces: follow visible page hints, app-provided credential hints, JavaScript submit targets, hidden fields, redirects, cookies, and post-auth routes as one coherent app path.
- If a visible page and client script disagree about the semantic action, prefer the JavaScript/network target for direct replay and preserve the visible-target comparison as evidence.
- Treat hidden fields named like role, access, owner, status, state, user, or admin as server-trust questions. Submit the normal workflow first, then one compact same-session mutation matrix and record whether the server trusted or rejected the field.
- When a login/register/admin/profile workflow succeeds, immediately run a small browser plus raw HTTP/API sweep with the preserved session before returning to generic unauthenticated fuzzing.
- If a template or session expression primitive only echoes inert or empty values across that compact matrix, pivot to source review, error evidence, or reportable negative evidence rather than enumerating framework object graphs through the UI.
- For upload routes, determine accepted extensions, storage path, served content type, and whether uploaded content is executed, included, rendered, parsed, or downloadable.
- If an upload accepts compound extensions or stores files under web-accessible paths, test one inert proof payload per likely handler family and verify cleanup; do not keep testing broad payload lists after the execution model is known.
- If source review later identifies an upload or include sink, revisit browser/recon with that exact route family and compare it against the authenticated sweep so runtime validation remains live-evidence driven.

## Blind And Filtered Surface Handling
- When a route accepts input but direct output is absent, collect one baseline and one probe, then compare status, body length, body hash, headers, and timing.
- Use blind inference only when current evidence indicates a sink or oracle; avoid random delay probes.
- When filters block tags, separators, traversal, or quotes, infer the blocked family from the response and try a compact mutation set before pivoting.
- Treat repeated identical responses as stagnation evidence. Summarize what changed, what stayed the same, and which single pivot should run next.

## Context-Aware Injection Mapping
- For every reflected, stored, or DOM-propagated value, identify its context before payload choice: HTML text, HTML attribute, URL, JavaScript string, JavaScript code, CSS, JSON, template, markdown/rendered HTML, or server log/error.
- For DOM XSS, trace source to sink from client bundles and browser runtime: location/hash/search, storage, postMessage, cookies, API JSON, WebSocket data, then sinks such as innerHTML, outerHTML, insertAdjacentHTML, document.write, unsafe URL assignment, event-handler attributes, eval-like calls, setTimeout strings, and framework escape hatches.
- A browser console alert is not enough when the app has a server-side verifier or tracked security state. Preserve browser-observed execution plus the server-recorded state, callback, or changed response that proves the app accepted the payload.
- For reflected or stored XSS, test one payload per relevant context. If it reflects in JSON or a script string, prefer context breakout and encoding tests over unrelated tag lists.
- If the response includes an execution oracle such as "expected value X but observed value Y", model the verifier contract before more tags: identify whether the app evaluates a JavaScript expression, calls a named function, records an `alert()` argument, parses only one content type, or strips values before browser execution. Then test compact expression/statement wrappers, quote/no-quote variants, and body/content-type shapes that preserve the value in the executable context.
- For verifier oracles, do response-class fuzzing rather than flat payload lists. Classify each attempt as neutral/not parsed, reflected inert, tag stripped, verifier type/error, wrong observed value, or expected proof; keep only families that change class or observed value.
- Derive the next attempt from the observed transform: stripped tags imply filter/desync variants, fixed TypeError implies alternate invocation wrappers such as call/apply/throw/onerror or indirect function access, neutral content types should be stopped, and reflected inert expressions should pivot to context breakout.
- Before capping a tag-stripping verifier path, infer the sanitizer grammar. Probe a tiny inert tag-name corpus and compare reflected transforms to learn which tag names survive, whether whitespace is deleted, whether attributes survive, and which delimiters are preserved. If whitespace collapses, switch from space-separated attributes to slash-delimited or otherwise separator-preserving event-handler syntax instead of replaying normal HTML payloads.
- If CSP, sanitization, or framework escaping blocks execution, record the exact sink and blocked characters/tags/events, then hand off to payload mutation with that filter shape.

## SQL, NoSQL, And Query Injection Mapping
- Identify the backend query family from errors, dependencies, source, route names, response shapes, and parameter behavior before choosing payloads.
- Start with non-destructive differential checks: baseline, true condition, false condition, quote/no-quote error, comment/whitespace, type mismatch, and one time delay only when no direct output or error channel exists.
- For JSON APIs and document stores, test operator-shape behavior only when JSON body parsing, Mongo-like object IDs, query operators, or source/dependency evidence indicate it. Compare primitive values against object values, arrays, and malformed types.
- For LDAP, XPath, search, filter, and selector-like parameters, test delimiter/operator behavior with harmless true/false or result-count deltas before trying extraction.
- If authentication bypass works, immediately validate a post-auth route and preserve token/session state before attempting extraction.
- For SQL-like UNION or extraction paths, first determine column count and output mapping with inert constants, then minimize extracted data to schema or proof fields necessary for validation. Do not dump full data when a redacted structure proves the boundary.
- For document-store or JavaScript-evaluated query paths, compare syntax errors, truthy/falsey expression behavior, operator objects, and route timing with strict request timeouts. Treat sleeps or expensive expressions as bounded parser signals, not stress tests.

## Blind SQL Oracle Loopback
- When runtime evidence shows boolean SQLi, SQL syntax errors, UNION width errors, timing deltas, or true/false response differences, loop back into `playbook.web_blind_sql_oracle_escalation` before switching to unrelated surfaces.
- Build the first packet as an oracle matrix, not an extraction run: baseline, broken syntax, true predicate, false predicate, comment closure, content-type/parser shape, and one DBMS clue if the evidence supports it.
- Ask what the oracle can prove with the least data: authenticated/session transition, existence of an authorized object, one redacted schema field, one current-run proof marker, or a negative closure.
- If a hash or credential-looking value appears during the oracle path on a **login surface**, first apply the SQL Injection Login / Auth-Bypass branch below (forged-row UNION / tautology / boolean reconstruction) — that is usually the intended solve. Only hand the hash to Credential Tester as a parallel last-resort branch, not the primary forward path; do not continue broad table extraction or password guessing from Web Hunter.
- If the oracle proves a primitive but not the objective, hand the lane to PoC Validator's objective proof mapper with the saved matrix and exact missing proof shape.

## SQL Injection Login / Auth-Bypass
When the injectable parameter is a **login/credential field**, the objective is an authenticated session, not data extraction. Extracting a password hash and routing it to cracking is a last resort, not the path — most SQLi login challenges are unsolvable by cracking and are designed to fall to the injection logic. First determine the auth query model, then apply the matching bypass:

- **Determine the model.** Probe the username field: `admin'` (error/invalid), `admin'-- ` and `admin' OR 1=1-- ` (does a valid-user response return?). If username injection alone yields a session → single-query model. If username injection returns the user but a separate password check still rejects → two-stage (fetch-row-then-compare) model. If only true/false deltas, no output → boolean-blind-only.
- **Single-query** (`... WHERE user='$u' AND pass='$p'`): comment out the password test or tautologize. Username payloads: `admin'-- `, `admin'#`, `admin'/*`, `' OR 1=1 LIMIT 1-- `, `' OR '1'='1'-- `, `admin') OR ('1'='1`. Vary closure (`'`, `"`, none, `)`), comment style (`-- `, `#`, `/*`), and try first-row pinning (`LIMIT 1`, `ORDER BY 1`).
- **Two-stage** (app fetches the user row by username, then compares the submitted password to the row's stored value/hash in application code): the username injection must return a **forged row** whose password column equals a value that makes the app's comparison pass.
  1. Discover column count: `' ORDER BY n-- ` increasing until the oracle flips, or `' UNION SELECT 1,2,3,…-- ` until no width error.
  2. Identify which column is the username and which is the stored password, and the hash scheme (plaintext vs md5/sha1/sha256/bcrypt) — from error text, response differences, length, or app framework hints.
  3. Inject a forged row with a password value you control: `nonexistent' UNION SELECT 1,'admin','<value>',… -- ` where `<value>` is what the app will compare the submitted password against — e.g. `md5('Passw0rd!')` if the app does `stored == md5(input)`, the literal `Passw0rd!` if plaintext compare, or a precomputed bcrypt hash of a known password if `password_verify()`. Then log in as that username with the known password.
- **Boolean-blind-only:** reconstruct the stored credential/hash char-by-char via the boolean oracle (`SUBSTRING((SELECT password…),i,1)>X`), then either replay it or feed it as a forged-row value if any UNION/output channel exists. Cracking the reconstructed hash is the lowest-priority branch.
- **Why a forged-row UNION fails** — treat each as a discrete variable to flip; do not conclude "auth is hardened" until all are exhausted:
  - wrong column *count*
  - correct count but hash in the **wrong column position**
  - wrong hash *algorithm* (you injected md5 but the app uses sha1/bcrypt/plaintext)
  - trailing original query not terminated (need `-- `, `#`, or `/* … */`, sometimes a trailing space/`%20`)
  - typed columns rejecting your constants (use `NULL` for non-target columns, cast where needed)
  - `UNION` vs `UNION ALL`
  - `LIMIT`/`ORDER BY` needed so the app reads *your* row, not the real one
  - quote/keyword filtering (try case, inline comments `/**/`, encoding)

## Crypto, Encoding, And Token Surface Mapping
- Treat coupons, continue codes, password reset values, invitation codes, bearer tokens, JWTs, signed IDs, encrypted comments, and opaque route IDs as token-boundary candidates.
- First classify the value: encoding, compression, hash-like, signed token, encrypted token, sequential ID, random ID, or app-specific format.
- Use known plaintext only when current target behavior provides it, such as a visible discount, role claim, route ID, or decoded header. Avoid guessing secret material.
- For JWTs and signed tokens, inspect headers, algorithm, key identifiers, issuer/audience, expiration, and server-side revocation behavior. Test only harmless claim changes against owned or lab identities unless the operator approves role-bound proof.
- If public keys, symmetric keys, salts, or algorithm names are exposed, preserve the disclosure and test whether it affects server authorization or token acceptance with one bounded proof.
- For weak encoding or coupon-like logic, prove predictability by deriving one current-run equivalent value from observed examples rather than relying on a known answer.

## Cross-Origin And Browser Data Exposure
- For JSONP, callback parameters, CORS, frameable pages, redirects, and unauthenticated "whoami" or profile-like endpoints, define the browser attacker capability before proof.
- Promotion requires a feasible untrusted-origin read or state change, not just a permissive header or callback-shaped response.
- Test callback wrapping, content type, credential mode, Origin behavior, exposed headers, SameSite posture, and readback with one owned account or lab session.
- If a redirect allowlist is present, compare exact allowlisted targets, parameter confusion, URL parser differences, and redirect-chain behavior before using the result in SSRF or image-fetch chains.

## Race And Anti-Automation Checks
- Treat like/vote/review/feedback/captcha/coupon/order and quota routes as concurrency candidates only after the normal route is mapped.
- Capture one normal request, prove replay rejection or rate behavior, then run a tiny concurrent or pinned-state matrix within allowed noise limits.
- Preserve timestamps, request IDs, and final readback. Stop immediately once the invariant is proven or the response class stays stable.
- For CAPTCHA and anti-automation, test whether the challenge is bound to session, action, freshness, and single use. Do not brute force human accounts.

## Upload And Parser Surface Mapping
- For upload/import/parser endpoints, determine all four boundaries before payloads: allowed extension after decoding, MIME/content-type trust, content signature/parser behavior, and storage/retrieval path.
- Test double extensions, encoded null/path separators, filename normalization, content-type mismatch, and signature mismatch only as compact probes tied to the observed allowlist.
- If uploaded content is publicly retrievable, compare served path, content type, download disposition, caching headers, and whether active content executes in browser context.
- If upload feeds another parser such as XML, image, archive, PDF, YAML, markdown, template, or spreadsheet, hand off to the matching parser primitive and validate one inert proof before impact checks.

## Filesystem And Command Boundary Mapping
- Treat filename, path, download, export, template, theme, language, image, and document parameters as filesystem candidates. Establish the application-root baseline before traversal variants.
- For traversal, compare direct filename, dot-segment, encoded dot-segment, double-encoded, mixed-separator, absolute-path, extension-appended, and path-normalization variants only against routes that evidence file access.
- For command-wrapper routes, distinguish command injection from argument injection. If user input becomes an argument to a trusted command, test option/argument boundary behavior before shell metacharacters.
- Prefer output-visible proof in this order: direct response, existing downloadable/static path, application-visible log/status artifact, then timing only when no output path exists.
- Do not use destructive commands. A proof should establish interpreter control or file-read boundary with the smallest harmless command/file artifact.

## SSRF And URL Fetch Mapping
- Treat any URL, image, webhook, callback, import, avatar, fetch, redirect, preview, metadata, or remote resource parameter as a URL-fetch candidate.
- Establish baseline fetch behavior with a same-origin or harmless external URL, then test parser normalization and redirect behavior before internal targets.
- In target-scoped proof mode, prioritize same-origin private routes, localhost spellings, explicit ports observed in config/source/errors, and redirect-to-internal behavior. Preserve response deltas rather than assuming access from a 200 alone.
- If only blind fetch is available, use callback/log evidence when allowed or compare timing/status/body-length changes from reachable vs unreachable destinations.

## CVE And Web Search Loop
- When runtime evidence identifies a product, framework, package, plugin, extension, server, component version, API generator, or distinctive endpoint family, trigger a focused intel loop.
- Search local intel first. If no precise hit exists, perform one narrow live web/CVE search using observed product/version/endpoint words only.
- Bring back affected versions, vulnerable entrypoints, prerequisites, minimal safe validation criteria, and references. Do not bring back unrelated exploit dumps.
- If intel identifies a likely entrypoint, validate reachability and behavior before unrelated fuzzing.
- If live behavior contradicts intel, record the mismatch and continue with evidence-derived route testing rather than forcing the advisory.

## Headers, Errors, And Runtime Clues
- Treat verbose errors as structured recon: framework, route, file path, middleware order, parser, dependency version, enabled feature, and unexpected path behavior.
- Treat security headers as context for exploitability: CSP affects XSS proof shape, cookie attributes affect session proof, CORS affects browser-token exposure, redirect headers affect open redirect and SSRF chains.
- If a 404/500 reveals a generated route handler, API router, static root, or middleware path, enumerate adjacent route families from that evidence before unrelated fuzzing.
- Record header/security gaps as findings only when impact is clear; otherwise use them to choose the next proof path.

## Browser Platform Surface Mapping
- Inventory browser-exposed trust boundaries: localStorage/sessionStorage, IndexedDB, service workers, Web Workers, postMessage, WebSockets, CORS, CSP, sandboxed iframes, redirects, URL fragments, and client-side routers.
- For postMessage, record origin checks, message schema, sink, and whether the receiver accepts wildcard or missing origin. Test one harmless message that reaches the sink before impact payloads.
- For storage-backed auth or state, compare whether sensitive tokens, roles, feature toggles, or object IDs are trusted by server routes or only used for UI display.
- For service workers and caches, record scope and cached sensitive routes. Do not attempt persistence; use this evidence to explain stale data, token exposure, or route discovery.
- When a browser security control blocks a vector, preserve the block as negative evidence and route to the correct alternate primitive rather than repeating payloads.

## Browser Side-Channel And Framing Checks
- Treat frameability, cross-origin load events, cache timing, `window.open` behavior, and cross-origin resource policy as side-channel candidates, not direct data access.
- For XS-Leak-style candidates, define the binary question first, then prove whether a cross-site primitive can distinguish the answer with load/error, frame count, navigation, cache, or timing behavior.
- Check `frame-ancestors`, `X-Frame-Options`, `Cross-Origin-Resource-Policy`, `Cross-Origin-Opener-Policy`, `Cache-Control`, and fetch-metadata behavior as proof context.
- Do not run high-volume enumeration from side channels. One owned-account or self-contained binary proof is enough before reporting or marking negative evidence.

## Client-Side Logic Trust Checks
- Treat all client-side business rules as bypassable until the server proves otherwise. If the client computes price, role, discount, route visibility, object ownership, or workflow state, replay the equivalent server request with one tampered value.
- Never stop at "the frontend blocked it." Use browser devtools/network evidence, JS bundle route discovery, or direct API calls to test the server-side invariant.

## Node And JSON Runtime Checks
- When Node/Express-like behavior is evidenced by headers, errors, dependencies, source, or bundle clues, add compact checks for JSON/query parser type confusion, HTTP parameter pollution, method override behavior, prototype-style object merge sinks, and auto-generated REST route siblings.
- For JSON endpoints, compare scalar, array, object, nested object, null, and malformed types only on high-value parameters. Stop after stable identical behavior and record negative evidence.
- For generated REST APIs, enumerate collection, item, filter, sort, include, and relation route shapes with auth/no-auth and owned/unowned comparisons.

## WordPress And Backup Plugins
- When WordPress is detected, identify active plugins from HTML, REST namespaces, public readmes, debug logs, and exposed backup paths before broad content enumeration.
- When a plugin/version is confirmed, loop once to vulnerability intel or web search using the product/plugin name, version, and exposed endpoint names. Bring back only CVE IDs, affected-version bounds, vulnerable entrypoints, and safe validation criteria.
- If vulnerability intel names an unauthenticated plugin endpoint or background worker, test that endpoint with a tiny reachability/behavior probe before backup dump mining, password cracking, or unrelated WordPress enumeration.
- If a backup/export plugin is visible, test only a compact public-backup path set for backup ZIPs, debug logs, config files, and database dumps; preserve filenames and response headers.
- For migration/staging plugins, prioritize generated storage roots and staging roots discovered from HTML, readmes, logs, plugin options, or directory listings. Check for archive inventory, manifest/config JSON, progress logs, staging configuration files, and temporary autologin/bootstrap artifacts before broad WordPress fuzzing.
- If a backup archive or config leak is recovered, immediately extract `wp-config.php`, active plugins, table prefix, users, roles, and plugin options, then pivot to the shortest live validation path.
- Do not loop over large WordPress SQL dumps. Search them for active plugins, users, roles/capabilities, upload paths, backup settings, and target proof filenames, then stop dump mining.
- For WordPress backup leaks, close out once the live path proves config disclosure, database disclosure, admin credential/session feasibility, plugin file read, or bounded file-read impact unless vulnerability intel shows a shorter, safe route to stronger impact.
- When `.htaccess` or index guards appear inside plugin-created storage, still verify from the served origin: container/proxy/web-server config may not enforce local guards the way source suggests. Record the served/not-served result instead of assuming protection.

## Source Disclosure And Local Service Pivots
- If a web app exposes its own source, read only the reachable app/router/config files needed to identify routes, credentials, local services, and sinks, then return to runtime validation.
- When source shows the app authenticating to a same-host or same-origin side service, treat embedded credentials as a capability. Validate the side service once if it is explicitly in scope, then run a single read-only command or API call that proves the service boundary.
- If the side service is referenced as `localhost`, reconcile it with recon before stopping: container-internal ports often appear externally as different same-host ports. Probe only discovered in-scope ports with matching service signatures, and preserve both the internal reference and external mapping in evidence.
- If no same-host candidate matches the source-local protocol, escalate recon once: run a scoped same-host high-port/full-port inventory in proof/full-send mode, then return immediately to the side-service proof path. Do not replace this with unrelated route fuzzing or broad credential guesses.
- If the page already displays output from a local side service, correlate the displayed command/output with the source command and test whether the recovered credential unlocks a shorter direct path. Do not stop at "hardcoded credential found".
- Preserve the exact source line refs, decoded transformation command, runtime connection attempt, and result. If the service is not reachable from the assessment environment, record that as a reachability blocker and keep the disclosure as candidate evidence.

## Server-Side Session Race Checks
- When source or runtime evidence shows server-side sessions, shared session stores, debug session dumps, low isolation levels, multi-worker routing, or routes that validate session state and then re-read mutable state, add a compact state-desynchronization hypothesis.
- First prove the normal session flow with a low-privilege account and capture the session cookie plus any debug/session view. Then test one coordinated same-session request pair that changes session fields while a privileged route is between validation and authorization.
- Compare baseline, role-change attempt, and privileged-route response. Repeat only if timing noise is plausible; otherwise preserve negative evidence and pivot.
- Never assume a race from source alone. The proof is a live role/state mismatch, not the presence of a suspicious session store.

## Source-Guided Web Server Checks
- If source review provides a web-server product/version plus route/alias/module/access-control config, skip browser-first navigation when the browser would normalize exploit-critical encodings or methods.
- Convert source refs into a live request plan, not a finding: exact endpoint or alias, required method, harmless primitive check, bounded impact check, expected safe evidence, and fallback question if blocked.
- For traversal, CGI, rewrite, proxy, static-file, include, or upload-handler issues, validate the primitive against the live target before reading any source-indicated sensitive path.
- If a live primitive works, stop broad fuzzing and package the runtime-validation artifacts for report promotion. If it fails, revisit source with the observed status/headers/body rather than switching to unrelated guesses.

## XSS Filter Handling
- When a reflected XSS target reports an exact browser-executed callback requirement, validate against the server response that records execution, not only the local browser console.
- If common tags such as `<script>`, `<svg>`, `<img>`, or closing tags are blocked, infer the blacklist shape from error responses and try one compact allowed-tag/event-handler family before broad fuzzing.
- For alphabetic tag blacklists, test tags outside the blocked range such as `<z autofocus onfocus=alert('XSS')>` and a double-quoted equivalent.
- When the app uses a headless validator, prefer payloads that self-trigger without user interaction, especially `autofocus` plus `onfocus`, then inspect the response for server-recorded execution evidence.
- When tag payloads collapse to a neutral/start response but raw text reaches an "alert/result" oracle, treat the neutral response as likely "not parsed/not evaluated" rather than proof. Compare form-urlencoded, multipart, JSON, text/plain, query string, and method-with-body delivery only as a compact matrix, then continue with the body shape that actually triggers the oracle.
- For alert-oracle targets, try expression-level payload shapes before broad HTML fuzzing: raw expected literal, quoted literal, string concatenation, character-code construction, assignment-free IIFE/function-call wrappers, and semicolon/comment terminators. Cap the family once those shapes produce the same observed value or error and record the exact error as filter evidence.
- If the same verifier error repeats across expression shapes, run one solver-style follow-up before capping: indirect alert invocation, `call`/`apply`, comma operator, `throw` plus `onerror`, timer/function wrappers, and the smallest filter-desync variants supported by the observed sanitizer.
- If common tags are stripped to a neutral/start response, do not assume all HTML is blocked. Run allowed-tag grammar discovery: submit inert variants from standard, SVG, media, form, and custom-looking tag names; record which names are reflected, which are removed, and how attributes are transformed. Include safe no-space probes such as slash-separated attributes when responses show whitespace deletion.
- For headless-browser verifiers, pair each surviving tag grammar with one self-triggering event family. Prefer broken-resource events (`src` plus `onerror`) and explicit focus events (`autofocus` plus `onfocus`) because they can execute without user interaction. Use the target's expected oracle value as data only when current-run evidence identifies that expected value.

## Route Family Closure
- Build a route-family ledger for every meaningful resource family: route pattern, method, content type, auth state, object identifier shape, parser, and state-changing behavior.
- Close each family as `validated`, `negative_evidence`, `blocked`, or `capped`. A route family is not done just because the visible browser path was visited.
- When browser navigation is thin, switch to raw HTTP replay using same-origin route literals, forms, JavaScript endpoints, and response-advertised next actions before declaring the surface exhausted.
- If a new family appears from source, logs, client bundles, scanner output, mobile traffic, or runtime errors, reacquire the surface lock and finish the family before broadening.

## Path And Routing Normalization
- Treat path normalization as a boundary between proxy, web server, framework router, static serving, helper routes, and app-level file handlers.
- Compare baseline paths against one encoding or separator family at a time: dot segments, encoded dot/slash, double encoding, mixed separators, extension suffixes, and route parameter decoding.
- Use harmless in-root resources first. Sensitive paths require explicit proof permission and a live primitive showing that the target route actually reads server-side files.
- Preserve status, headers, served path, body hash/length, and routing/error differences; a normalization finding needs the baseline/confused pair.

## Realtime And Browser Boundary Checks
- Treat WebSocket, server-sent event, long-poll, and subscription transports as APIs. Record handshake auth, origin, cookies/tokens, subprotocols, and first normal message flow.
- For each message family, compare unauthenticated, stale session, wrong origin where safe, owned object, unowned object, malformed schema, and role-gated action.
- For CORS, CSRF, framing, and fetch-metadata candidates, prove a feasible browser action. Missing or weak headers are context unless an untrusted origin can read sensitive data or change state.
- Pair state-changing realtime or browser-boundary evidence with an HTTP/API readback whenever possible.

## Upload, Import, And Parser Boundaries
- For upload/import routes, map extension checks, content type trust, content signature, parser behavior, storage path, retrieval path, and cleanup behavior before payload work.
- Test one harmless parser or storage delta at a time: filename normalization, content-type mismatch, archive member path, metadata parser error, retrieval disposition, or active-content serving.
- If parser proof appears, route to the precise primitive: file read, template/include, XML/YAML/JSON parser, markdown/rendered HTML, archive extraction, image/PDF processing, or API state change.

## SSRF Deep — Sink Inventory and Filter Bypass

Server-Side Request Forgery is a wide attack class with several distinct sinks and many filter-bypass variants. The `web_hunter` discovery loop surfaces the *candidate* sinks; this section is the deep-dive playbook for each one.

### Sink inventory (where SSRF lives)

| Sink | Where to look |
|---|---|
| Webhook URL parameter | `webhook_url`, `callback_url`, `notification_url` fields in API endpoints |
| Avatar / image URL fetch | `avatar_url`, `image_url`, profile-image upload-by-URL |
| OAuth `redirect_uri` | Authorize endpoint — but the SSRF is via the redirect chain, not `redirect_uri` itself |
| PDF / image generator | Send a URL → server fetches → renders to PDF or thumbnail (Headless Chrome is the engine) |
| XML / XSLT parser | `Content-Type: application/xml` with attacker-controlled `<!DOCTYPE>` or `xsl:include` |
| Server-side import | "Import data from URL" features — RSS, CSV, OPML, JSON-LD |
| URL preview generator | "Show preview of this link" → server fetches OG tags |
| WebSocket proxy / forwarding | Server proxies WebSocket to attacker-supplied URL |
| Webhook validation | Some apps validate a webhook URL by fetching it before saving |

For each, the candidate exists if the application takes a URL from the user and the server (not the user's browser) fetches it.

### Internal targets worth reaching

| Target | Why interesting | URL |
|---|---|---|
| AWS metadata v1 | IAM token leak | `http://169.254.169.254/latest/meta-data/iam/security-credentials/` |
| AWS metadata v2 (IMDSv2) | Token-protected; requires PUT for token | `PUT http://169.254.169.254/latest/api/token` |
| GCP metadata | Service-account token | `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` (requires `Metadata-Flavor: Google` header) |
| Azure metadata | Managed identity token | `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=...` |
| ECS task metadata | Container-level credentials | `http://169.254.170.2/v2/credentials/<role>` |
| Kubernetes API server | Cluster info if reachable | `https://kubernetes.default.svc/api/v1/...` |
| Internal admin panel | `http://localhost:8080/admin`, `http://10.0.0.X:8080/admin` |
| Internal Redis / Memcached | Pre-auth RCE on most installs | `http://127.0.0.1:6379/`, `http://127.0.0.1:11211/` |
| Internal Elasticsearch | Cluster state, indices | `http://127.0.0.1:9200/_cat/indices` |
| Internal MongoDB / MySQL / Postgres | Some are HTTP-protocol-reachable via SSRF | various |

### Filter-bypass matrix

When the application's URL validator tries to block private addresses, these bypass the simple regex / parser checks:

| Class | Examples |
|---|---|
| Decimal IP | `http://2130706433/` (= 127.0.0.1) |
| Hex IP | `http://0x7f000001/`, `http://0x7f.0x0.0x0.0x1/` |
| Octal IP | `http://0177.0.0.1/` |
| Mixed encoding | `http://0177.0.0.0x1` |
| IPv6 | `http://[::1]/`, `http://[::ffff:7f00:1]/` |
| Short IPv4 | `http://127.1/`, `http://127.1.1/` |
| URL-userinfo trick | `http://attacker.com#@169.254.169.254/` |
| DNS rebinding | `attacker.com` resolves to attacker-IP on first DNS lookup (passes filter), then 169.254.169.254 on second lookup (server fetches). Use `1u.ms` / `rbndr.us` for prebuilt rebind hosts. |
| DNS-CNAME-to-internal | Own `evil.com` → CNAME to `internal.target.local` |
| URL-protocol smuggling | `gopher://`, `dict://`, `ldap://`, `file://`, `ftp://` if the URL parser allows them |
| Redirect-chasing | Attacker URL returns `302 Location: http://169.254.169.254/...`. Server follows. Some validators check the original URL only. |
| HTTP/0.9 line-folding | Carefully-crafted multi-line URL exploits naive line-by-line parsing |

### Confirmation evidence

A confirmed SSRF needs:

- **DNS callback only** → informational on most programs (use OOB MCP for this; see `secops/mcp/oob_server.py`).
- **HTTP fetch of internal endpoint with response visible** → Medium tier.
- **HTTP fetch with IAM/SA credentials returned in response** → Critical (cloud-metadata SSRF).
- **HTTP fetch with internal admin panel response visible** → Medium-High.
- **gopher://Redis/Memcached → pre-auth RCE** → Critical.

Stop at the minimum proof. One credentials response is enough; never enumerate the cloud account beyond the credential-exists demonstration.

### Proxy-forwarding SSRF (no `url=` parameter needed)

When the app has *no* obvious URL parameter but makes outbound requests, behaves like a proxy, or sits behind one, test the **absolute-URI request line**:

```
GET http://internal-host/ HTTP/1.1
Host: <real-target-host>
```

Some servers/proxies/gateways treat a full URL in the request line (absolute-form, RFC 7230 §5.3.2) as a *forward instruction* and fetch it server-side, returning the body — a textbook SSRF with no parameter. If it forwards:

- **Test every method, not just GET.** Replay `POST`/`PUT`/`PATCH`/`DELETE` (with bodies) through the same primitive. If the full request forwards, this is a *bidirectional internal HTTP proxy*, not a read-only fetch — far higher impact (internal writes, state-changing internal APIs).

### The impact lever: historical non-resolvable hostnames

A confirmed SSRF's ceiling is set by **what you can name**, not RFC1918 IP scans. Internal services sit behind internal DNS names that return NXDOMAIN to public resolvers but still resolve inside. **"Dead outside, live inside."** Build the SSRF payload list from **target-specific historical hostnames**, not generic wordlists:

- Certificate-transparency logs, JS bundles / source maps, API/redirect/`Location`/error-message bodies, passive & historical DNS, prior recon artifacts.
- A hostname that is publicly NXDOMAIN today but once appeared in any of those is a *prime* SSRF payload — test `GET http://<that-host>/` through the SSRF. A valid HTTP response to a publicly-non-resolvable org name = an internal-only system reached.
- Route this enumeration through `recon_advisor` / the recon-intel sources (cert transparency, DNS history); do not discard non-resolvable names — they are leads, not dead ends.

Stop at one bounded internal-system proof; do not mass-pivot the internal network.

## JWT Cracker — Token-Side Attack Matrix

When the application uses JWT for session or API auth, the token itself becomes attack surface. This section covers the practical attack matrix.

### Step 1 — recover and decode

```bash
# Recover from cookies, Authorization header, response bodies
echo 'eyJhbGciOi...' | cut -d. -f1 | base64 -d   # header
echo 'eyJhbGciOi...' | cut -d. -f2 | base64 -d   # payload
```

`jwt.io` for interactive decoding. CLI: `jwt-cli`, `pyjwt`, `node-jsonwebtoken`.

### Step 2 — attack the algorithm

| Algorithm | Attack |
|---|---|
| `none` | Set header `alg: none`, drop the signature segment (token: `<header>.<payload>.`). Many libraries still accept; CVE history continues to surface this. |
| `HS256` | If signature secret is leaked or weak, brute-force with `hashcat` mode `16500`. Common weak secrets: `secret`, `password`, app name, year + app name. |
| `RS256 → HS256 confusion` | Take the public RSA key (often at `/.well-known/jwks.json` or `/jwks`). HMAC-sign a new token using the PUBLIC key as the HMAC secret. Server verifies with HS256, using the public key as the HMAC key — passes. |
| Custom alg | Many libraries support pluggable algorithms with unsafe defaults (`HS256` + key-from-header). |

### Step 3 — manipulate kid / jku / x5u

```json
// Original JWT header
{"alg":"RS256","typ":"JWT","kid":"key-2024-1"}

// Attack 1: kid path traversal
{"alg":"HS256","typ":"JWT","kid":"../../../../dev/null"}
// Signed with the file contents of /dev/null (empty), HMAC matches the empty key.

// Attack 2: kid SQL injection
{"alg":"HS256","typ":"JWT","kid":"abc' UNION SELECT 'attacker-key"}

// Attack 3: jku confusion - public JWKS URL
{"alg":"RS256","typ":"JWT","jku":"https://attacker.com/jwks.json"}
// Server fetches attacker's JWKS; uses attacker's public key to verify.
// Attacker has the matching private key.

// Attack 4: x5u confusion - public certificate URL
{"alg":"RS256","typ":"JWT","x5u":"https://attacker.com/cert.pem"}
// Same as jku but X.509.
```

For `jku` / `x5u`: most modern libraries default-disable these. The bug is when an application explicitly enables them without an allowlist.

### Step 4 — payload manipulation

| Claim | Manipulation |
|---|---|
| `sub` / `user_id` | Change to another user's ID — IDOR via JWT |
| `role` | `user` → `admin` |
| `aud` | Re-target to a different audience (cross-app token re-use) |
| `exp` | Extend expiration (useful when paired with weak signing) |
| `iss` | Cross-IdP confusion if the verifier doesn't strictly bind to issuer |

### Step 5 — crack signing keys

```bash
# Save the token to a file
echo "eyJhbGciOi..." > token.txt

# Hashcat HS256
hashcat -m 16500 -a 0 token.txt /usr/share/wordlists/rockyou.txt

# jwt_tool
python3 jwt_tool.py <token> -C -d /path/to/wordlist.txt
```

For HS256/HS384/HS512: common-secret success rate is high on internal/self-hosted apps; effectively zero on commercial-product apps.

### Step 6 — implementation bugs (CVE-2018-1000531 era)

- `RS256` → `none` algorithm-swap.
- Time-based comparison leaks in signature verification.
- `kid` injection allowing alternate key selection.
- `jku` / `x5u` URL fetched without allowlist.
- Missing audience check.
- Missing expiration check.
- Algorithm confusion across libraries (different language libs ship different `verify()` defaults).

### Tools

- `jwt_tool` (ticarpi) — multi-attack JWT tester. Canonical.
- `jwt-cracker` (lmammino) — fast HS256 dictionary cracker.
- `hashcat -m 16500` — HS256.
- `john --format=hmac-sha256` — alternative.

## Documented Pivots

These are routine cross-pack pivots from a web_hunter run. They are entry points to specialized packs, not new techniques.

### `/scope-aggregate` — multi-platform asset pull

When the operator is hunting against a program registered across multiple bug bounty platforms, run `/scope-aggregate <program>` before recon to unify the in-scope asset list. Eliminates the "I tested a subdomain that was only in-scope on one platform" failure mode and dedupes across platforms.

Trigger: program announced on multiple platforms, or a wildcard scope where the explicit asset list disagrees between platforms.

Composes with `packs/recon_advisor/SKILL.md` (memory-aware ranking) — the aggregated list feeds straight into ranking.

### `/param-discover` — hidden HTTP parameter discovery

When an endpoint accepts query or body parameters but the docs / JS / responses don't reveal all of them, run `/param-discover <url>` to brute-force candidate names. Common hits: `debug`, `admin`, `internal`, `_token`, `redirect`, `next`, `return_url`, `discount_rate`, `role`, `is_admin`, version-specific params (`v`, `api_version`), legacy-route params (`old_id`, `legacy`).

Trigger: a route accepts at least one named parameter; the response varies based on input; the JS bundle / OpenAPI schema is incomplete.

Tools registered in `agent_ops/config/tool_registry.yaml`: `arjun` (Python, default), `x8` (Rust, faster on large wordlists).

A successful hidden-parameter discovery is usually the start of a chain — `debug=true` enables verbose errors that leak stack traces; `admin=1` enables priv-esc; `redirect=<url>` enables open-redirect. After discovery, return to the trigger matrices above with the new parameter as input.

## Advanced Web Technique Theories
This pack also owns the advanced-web theory family for layered probing of protocol- and rendering-level weaknesses. Trigger `playbook.web_advanced_techniques` when the surface map shows a CDN/proxy chain, HTTP/2 origin, complex SPA, or deserialization/XML/SAML endpoints:
- `web.http_smuggling.cl_te_te_cl_h2` — CL.TE/TE.CL/H2.CL/H2.TE desync
- `web.cache_poisoning` — unkeyed-input cache poisoning
- `web.cache_deception` — path-suffix cache deception
- `web.proto_pollution.client_and_server` — JS object-merge prototype pollution
- `web.dom_clobbering` — name/id-attribute global override
- `web.css_exfil` — attribute-selector CSS exfiltration
- `web.race.single_packet` — HTTP/2 single-packet race
- `web.deserialization.java_dotnet_yaml` — Java/.NET/YAML/Pickle/JSON-types deserialization
- `web.injection.nosql_ldap_xpath_ssi_el` — non-SQL injection family
- `web.saml_xxe_signature_wrap` — SAML XXE / XSW / comment-truncation

## Exclusions
No out-of-scope, destructive, persistence, DoS, credential-stuffing, or secret-disclosure actions.
