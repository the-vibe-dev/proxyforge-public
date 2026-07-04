# Adaptive Attack Theory

This shared guidance is target-agnostic. Do not assume a lab pattern, product
name, scoring route, or expected proof string. Derive every next action from
the current target's observed services, routes, source, responses, headers,
forms, client bundles, errors, versions, and saved artifacts.

## Core Loop

1. Enumerate the current in-scope surface broadly enough to know what exists:
   routes, forms, methods, APIs, static/client bundles, auth flows, object IDs,
   uploads, redirects, URL fetchers, parsers, exports, docs, backups, admin
   surfaces, and source-derived entrypoints.
2. Classify each surface by primitive: auth/session, object access, file read,
   upload, parser, template/render, URL fetch, command wrapper, business flow,
   secret/config exposure, component/version, or mobile/deep-link boundary.
3. Load or recompute skills whenever new high-confidence evidence changes the
   surface map: new service/version/CVE, new client route, new API schema, new
   auth state, new source sink, new error class, new capability, or stagnation.
4. Validate the most likely primitive with the smallest proof that can
   distinguish success from baseline. Preserve request, response, status,
   headers, body length/hash, timing, state change, cleanup, and artifact path.
5. Chain every capability by asking what it unlocks next. Do not stop at a
   partial capability if a short, safe follow-on proof is available.
6. If no progress is made, summarize tried families, negative evidence, and
   surviving capabilities, then switch strategy instead of restarting blind.

## Coverage Ledger

- Maintain a lightweight coverage ledger for each run: information gathering,
  configuration, authentication, session, authorization, input validation, API,
  file/upload/parser, business logic, client/browser, mobile platform when
  relevant, error/logging, crypto/transport, and dependency/version exposure.
- Each family should end in exactly one state: validated finding, validated
  capability, candidate with next action, negative evidence, not applicable, or
  blocked. Unknown families trigger one recon or source/browser revisit before
  final reporting.

## Evidence-Driven Revisits

- New product, framework, library, plugin, extension, firmware, package, or
  version evidence triggers a CVE/intel loop. Query local intel first; if empty,
  stale, or ambiguous, perform a narrow live web/CVE search using only observed
  product/version/endpoint terms. Return affected versions, vulnerable
  entrypoints, proof conditions, and safe validation shape.
- New route, form, API schema, JS bundle, or source sink triggers skill
  recomputation. The next agent prompt must include why the skill was added and
  which evidence refs caused it.
- New auth/session/token/credential capability triggers a compact authenticated
  surface sweep before unrelated fuzzing.
- New upload, file-read, template, URL-fetch, parser, or command-wrapper signal
  triggers exploit-chain planning from that primitive before generic scanning.
- New client-side route/config/API evidence triggers a second surface-map pass.
  Mine bundles, source maps, network logs, HTML config blobs, security metadata,
  and error pages for routes, methods, object names, hidden roles, generated API
  namespaces, URL-fetch parameters, upload/import paths, and framework-specific
  parser behavior.
- New stack trace, verbose error, dependency banner, or framework-specific
  parsing clue triggers both route discovery and version/config triage. Treat
  errors as structured recon, not as noise.
- New negative evidence should reduce or cap that strategy, not end the run.

## Candidate Resolution Contract

- Treat late runtime signals as capability candidates, not as noise: auth
  unlocked surface, role/property control, object access delta, file listing,
  upload/parser path, server-side fetch, client sink, template/include path,
  component/version research, and error-driven route discovery.
- Each candidate gets one bounded revisit with the right specialist skills.
  Resolve it as validated finding, validated capability, negative evidence, or
  capped with the exact failed precondition.
- Do not restart broad enumeration when a candidate appears. Preserve the
  current state, derive the smallest baseline/probe matrix, and continue from
  the discovery that created the candidate.
- Do not encode measurement-target routes, proof strings, product names, or
  expected secrets into reusable methods. The only allowed source of those
  details is current-run evidence.

## Full-Capability Proof Profile

When the selected run profile explicitly enables target-scoped proof mode:

- Keep the scope fence strict: all requests, callbacks, credentials, and artifact
  paths must still belong to the selected target or operator-approved local test
  environment.
- Do not treat high-impact labels as blockers inside scope. Treat them as risk
  metadata that requires bounded proof, artifact capture, and cleanup notes.
- Expand enumeration and validation depth: try each meaningful surface family
  until it is validated, disproven, or capped by repeated identical evidence.
- Prefer live runtime proof over source-only claims. Source can generate a
  hypothesis and shortest path, but execution must prove it when proof mode is
  evaluating runtime capability.
- Do not use destructive persistence, stealth, credential stuffing, phishing, or
  out-of-scope lateral movement. Full capability means full target-scoped proof,
  not uncontrolled harm.
- For full-run requests, inventory all current-run surfaces and vector families,
  attempt each meaningful one, and close it as validated, negative evidence,
  blocked, or capped. A single exploit does not complete the run if adjacent
  routes, APIs, files, parser paths, credentials, side services, privilege
  boundaries, or patch insights remain unresolved.
- For command execution in full-run requests, continue into bounded
  post-exploitation validation: execution identity, host/container boundary,
  writable paths, config/secrets, reachable services, privilege escalation or
  root/admin attempts when authorized, cleanup, and remediation evidence.

## Payload Mutation Theory

- Mutate only after evidence shows filtering, parser behavior, normalization, or
  blind/no-output behavior.
- Keep mutation compact and explainable: encoding/double-encoding, quote/no
  quote, case changes, comment/whitespace variants, alternate separators, XSS
  tag/event families, template syntax families, traversal normalization, URL
  host/port forms, and command separators.
- When a browser/client-side surface exposes a verifier oracle, such as an
  "expected value but observed value" message, first model the contract that
  produced the observation. Preserve the request body shape that reaches the
  oracle, then try compact expression/statement variants before broad tag
  fuzzing. Treat neutral/default pages from other content types as parser
  negatives unless they include explicit success evidence.
- Drive verifier-oracle testing from response classes. For each attempt, record
  payload, delivery, reflected transform, observed value/error, and class
  (`neutral`, `reflected-inert`, `tag-stripped`, `verifier-error`,
  `wrong-observed-value`, or `expected-proof`). Continue only classes that
  change state or observed value; stop stable classes with negative evidence.
- If a fixed verifier error repeats, run one solver-style mutation set derived
  from that error before capping: indirect function invocation, `call`/`apply`,
  comma operator, throw/onerror, timer/function wrappers, and sanitizer desync
  variants when tags are stripped.
- When tags are stripped, neutralized, or reflected after character removal,
  switch from payload guessing to sanitizer grammar inference before capping.
  Use inert probes to learn surviving tag names, removed tag names, case
  handling, attribute preservation, delimiter handling, and transforms such as
  whitespace deletion. Then combine only the surviving grammar with one or two
  self-triggering event families.
- Whitespace deletion changes the payload language. If the reflected transform
  removes spaces, normal HTML attribute syntax is not meaningful negative
  evidence. Try separator-preserving variants such as slash-delimited
  attributes, quote-free values, encoded separators, or event handlers on tags
  that current-run evidence shows survive the sanitizer.
- Stop a family after repeated identical deltas; preserve negative evidence and
  pivot to a new primitive or source/intel revisit.

## Modern Web Runtime Theory

- JavaScript/Node-style apps often parse the same input as string, array,
  object, nested object, or malformed type depending on query/body shape. When
  evidence shows this stack, include one compact type-confusion matrix for high
  value parameters before broad payloads.
- Auto-generated REST routes, debug routes, docs, metrics, health endpoints,
  security metadata, and admin/config endpoints are first-class surface. If one
  generated route works, enumerate the sibling namespace deliberately.
- CORS, CSP, cookie attributes, redirect behavior, and security headers are route
  context. They rarely prove impact alone, but they tell the agent which browser,
  token, or cross-origin proof is plausible.
- Large-body, parser, and event-loop issues should be recorded as risk or
  negative evidence unless the run explicitly allows resource-impact testing.

## Blind Proof Theory

- Establish a baseline before the probe.
- Compare status, selected headers, body length, body hash, and elapsed time.
- Repeat only the strongest signal if noisy.
- A single weak timing or length delta is candidate evidence, not confirmation.
- Bundle baseline, probe, delta summary, confidence, and noise notes.

## Hunting Discipline Rules (Always Active)

These rules apply to every bug-bounty run; breaking them wastes time and damages validity ratio.

1. **Read full scope first.** Before any request: in-scope list, out-of-scope list, excluded bug classes, safe-harbor clause. One out-of-scope request risks ban; one out-of-scope report = instant close.
2. **Never hunt theoretical bugs.** Ask: can an attacker do this RIGHT NOW, against a real user, causing real harm? If no, stop.
3. **Kill weak findings fast.** Run the 7-Question gate (`agent_skills/packs/triage_validation/SKILL.md`) before spending time. Every minute on a weak finding is a minute not finding a real one.
4. **Check scope explicitly per asset.** Wildcards in scope cover specific subdomains only if the program text says so. Third-party services the target merely consumes are out-of-scope by default.
5. **5-minute rule.** A target surface with nothing interesting after 5 minutes → move on. Kill signals: all 403/static, no ID parameters, no JS with interesting paths, `detection-engine` returns 0 medium/high.
6. **Automation = dup rate.** Use automation for recon (subdomain enum, live hosts, URL crawl, detection-engine tags). Manual testing for IDOR / auth bypass / business logic / race conditions. Scanners find duplicates; humans find unique bugs.
7. **Impact-first hunting.** Ask "what's the worst thing if auth was broken here?" If "nothing valuable" → skip the feature. If "admin / PII / fund theft" → hunt there.
8. **Hunt less-saturated bug classes.** High competition: XSS basics, SSRF basics, open redirect alone. Low competition: cache poisoning, race conditions, business logic, HTTP smuggling, CI/CD.
9. **Depth over breadth.** One target deeply understood > ten shallowly tested. Read 5+ disclosed reports for the target. Understand the business domain. Map the crown jewels.
10. **The sibling rule.** When `/api/user/123/orders` requires auth, check `/api/user/123/export`, `/delete`, `/share`. Explains ~30% of paid IDOR/auth bugs.
11. **A→B signal method.** When you confirm bug A, stop and hunt for B and C before writing the report. A confirmed bug = signal the developer made a class of mistake elsewhere. Time-box 20 minutes on B.
12. **New == unreviewed.** Features <30 days old have the lowest security maturity. Monitor GitHub commits. Hunt new features first.
13. **Follow the money.** Billing / credits / refunds / wallet endpoints have the most developer shortcuts. Price manipulation, race conditions, quota bypass = high ROI.
14. **20-minute rotation.** Every 20 min ask: am I making progress? No → rotate endpoint / subdomain / vuln class. Fresh context finds more bugs than brute force.
15. **Business impact > vuln class.** Clickjacking is usually $0 but MetaMask paid $120k for one. Estimate severity by business impact, not bug class.
16. **Validate before writing.** Run the 7-Question gate before drafting. Gate 0 (`Reality Check`) is 30 seconds; killing a bad lead at gate 0 saves 30 minutes of report writing.
17. **Credential leaks need exploitation proof.** Finding a key = informational. Proving what the key accesses (S3 read, DB, admin) = Medium/High. Always call the API as the leaked key with canonical existence-proof curl from `agent_skills/packs/secrets_scanner/SKILL.md`.
18. **Mobile and CI/CD are different attack surfaces.** Mobile apps expose endpoints the web doesn't — decompile in scope. CI/CD pipelines (GitHub Actions, GitLab CI) often have critical secrets and `pull_request_target` injection risks.

## Capability Chaining Questions

- Auth bypass or token leak: what privileged route, object, export, admin
  function, upload, or profile action is now reachable?
- Source disclosure or backup/config leak: what route, key, credential, version,
  local service, file path, or sink did it expose that can be validated live?
- Upload: where is it stored, how is it served, and can any include/render/parser
  path consume it?
- File read/LFI/traversal: can it disclose route config, source, credentials,
  templates, upload paths, or service connection details?
- SSRF/URL fetch: can it reach localhost, internal admin, metadata, same-origin
  private routes, or application endpoints with different trust?
- SSTI/template/include: can a minimal expression, include path, or uploaded
  template reach a bounded runtime proof?
- XSS/filter bypass: what filter shape is observed, and what one compact
  tag/event family can produce server-recorded or browser-observed proof? Which
  tag names and delimiters survive the sanitizer, and does the sanitizer delete
  whitespace or other syntax needed by normal HTML attributes?
- Command execution: what shortest safe output channel exists before falling
  back to timing? If objective proof is required, use that channel to recover
  the target-provided proof; otherwise place, read back, and clean up a unique
  nonce marker so execution is fully validated.
