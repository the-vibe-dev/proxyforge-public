---
name: poc_validator
description: PoC Validator: non-destructive vulnerability confirmation.
---
# PoC Validator

## Use When
non-destructive vulnerability confirmation. Apply this pack for roles: developer, executor, researcher.

## Operating Rules
- Follow SecHive shared scope, evidence, memory, and execution policy.
- Produce dense, machine-reviewable notes with fields: `obs`, `evidence`, `risk`, `next`, `blocked`.
- Mark uncertainty explicitly; do not promote scanner hits to findings without validation.
- If execution is allowed, propose the least intrusive action first with noise level and evidence path.

## Role Focus
Use canaries/read-only checks; kill false positives before reporting.

## VRP PoC Validation Addendum

When validating a bug bounty or VRP PoC, load the matching local policy packet
before promotion:

- General Google Bug Hunters quality and invalid-report filters:
  `vrp_best.md`
- Chrome Browser / Chromium / d8 / Chrome-component issues: `chrome_vrp.md`
- Google or Alphabet web, mobile, service, or browser-extension issues:
  `google_vrp.md`

For Chrome VRP, the validator must explicitly check that the PoC is minimized,
attached or packageable as individual files, reproducible in unmodified
Chrome/`d8`/a supported binary, uses only necessary supported flags, records
affected versions and OS/platform, and includes symbolized ASAN/MTE output or a
crash ID for memory bugs.

Chrome VRP block condition: if the only proof is a modified Chromium unit test,
modified browser test, test fixture, custom harness, CDP-only controller, or
unsupported command-line mode, return `blocked:
chrome_vrp_supported_poc_missing` and do not promote.

For Google/Alphabet VRP, the validator must explicitly check attacker and
victim account separation, test-account-only evidence, raw HTTP or product
state evidence where useful, and that existing permissions do not already allow
the claimed impact.

If the relevant policy packet is not applied, return `blocked:
vrp_policy_reference_not_loaded` instead of promoting.

## Full-Send Proof Mode
- When the run explicitly selects target-scoped proof mode, validation should be aggressive inside the selected target and conservative outside it.
- Do not skip a meaningful in-scope vector merely because it is labeled high impact. Instead, bound the proof, record risk tags, capture artifacts, note state changes, attempt cleanup when relevant, and continue.
- Convert every validated vector into either a finding or an explicit non-promotion reason. Do not silently leave validated runtime evidence as a raw artifact.
- Continue from partial proof: if a primitive is validated but the impact is not complete, ask what shortest follow-on proof would demonstrate real impact.
- For full runs, build a surface/vector ledger before final reporting and attempt each meaningful discovered family: route/API/method/content-type/parameter, auth/object, file/read/upload/parser, dependency/CVE, side-service, credential, command execution, and post-exploitation vectors. Close every family as validated, negative evidence, blocked, or capped.
- If a proof attempt fails because of tooling, quoting, timeout, stale auth, or missing route mapping, fix the harness and retry the same vector before calling it negative evidence.
- In payload or endpoint matrices, every request needs a per-request timeout and an output artifact. Classify parser hangs/timeouts separately, then keep the loop moving rather than letting one payload consume the run budget.
- In proof-oriented runs, close each candidate as validated, negative evidence, blocked, or capped before final reporting. Avoid "likely exploitable" endings when the current target can still be tested safely.
- For workflow-driven web apps, proof is not complete until the validator has followed the app-indicated path: visible hints, JavaScript submit target, hidden fields, cookies, redirects, and the first post-auth route/API sweep.
- When app-provided credentials are visible, validate that exact invited path once, preserve the cookie jar, and continue to the post-auth surface before unrelated payload mutation.
- If validation reaches command execution, template execution, object-store access, or admin capability, complete the capability with the shortest safe proof artifact and cleanup or an explicit blocked reason.

## Bug Bounty Proof Floor
- Runtime proof is mandatory before promotion. Source review, scanner output,
  emulator-only behavior, dummy endpoint responses, and inferred downstream
  flows remain candidate evidence.
- For UI/auth/session/account/mobile/browser chains, capture a full-path video,
  screenshots of every critical transition, full request/response evidence, and
  the final impact state.
- If any chain link fails or cannot be reproduced, preserve the exact negative
  evidence and tell the reporter to reduce the claim to the strongest proven
  behavior.
- Never validate `full ATO`, `complete chain`, `critical`, or `verified exploit`
  wording unless the saved artifacts prove attacker-side acquisition,
  downstream consumption when claimed, and final privileged state.

## Backup Exposure Validation
- For exposed backup archives or config files, validate impact with the smallest artifact that proves sensitivity: config constants, DB connection settings, user table metadata, role/capability rows, or a bounded proof file.
- Prefer archive inventory plus targeted extraction over unpacking or summarizing entire dumps.
- If plugin/version intel identifies a known vulnerable entrypoint, validate the entrypoint with a minimal non-persistent probe first. Prefer read-only output or short staged checks over deploying shells or broad payload lists.
- If a one-shot payload fails due to request/header limits, switch to the exploit family's compact staged validation path or record the limit as a blocker; do not keep replaying oversized payloads.
- If a backup leak reveals credentials, validate only one safe login/session or one read-only DB-derived impact path, then hand off to reporting or cleanup.
- Record whether the artifact was public, authenticated, path-traversal-derived, or source-derived so reports distinguish exposure class from follow-on impact.
- For migration/staging backup products, validate generated archive, manifest, log, and staging artifacts in this order: HTTP headers, small inventory or first bytes, targeted security-relevant extraction, then one shortest live follow-on proof. Do not unpack bulky archives unless targeted extraction fails.
- If source suggests local filesystem guards but HTTP proves the artifact is served, trust the runtime result and package both the source guard and served response as evidence of deployment drift.

## Source-Derived Known-Vulnerable Component Validation
- When source review identifies an exact product/version plus enabling configuration for a known exploit family, treat that as the primary validation packet and avoid broad recon before the first live check.
- Confirm runtime reachability with the least intrusive probe that proves the primitive, such as a harmless command identity check, a non-sensitive path traversal read, a versioned endpoint behavior probe, or a request/response delta.
- Only after the primitive is live-confirmed, perform one bounded objective read or impact check that follows directly from source-indicated application state; never claim proof from source alone.
- When source/deploy files indicate runtime environment variables, container ARG/ENV values, mounted config, or source-named sensitive files, prefer the shortest read-only runtime check for those locations before archive spelunking or broad filesystem search.
- Prefer non-persistent execution channels. If a temporary script or uploaded helper is unavoidable, record its exact path, use a randomized name, remove it before handoff, and preserve cleanup verification.
- Preserve request, response status, response body excerpt, source refs, and artifact paths in a runtime-validation JSON/Markdown bundle so report promotion can distinguish source hypothesis from live proof.
- If live behavior contradicts source, stop broad exploitation and send a narrow revisit question back to source review with exact status codes, headers, and response snippets.

## Hardcoded Credential Validation
- If source reveals a credential transformation, preserve the encoded source value and the exact decode/derive command, then validate the resulting credential only against the service the application already uses.
- If the service is reachable and in scope, run one read-only proof action that matches the app's own behavior, such as listing a harmless status endpoint or command output the UI already displays.
- For containerized or proxied targets, translate source-local service references into discovered externally reachable same-host mappings before declaring the proof blocked. Match by protocol and banner first, not by port number alone.
- In target-scoped proof mode, a source-local side service is enough evidence to justify one scoped same-host high-port/full-port inventory when the current recon set lacks a matching protocol candidate.
- If the service is not reachable externally, use the application output that depends on the credential as runtime corroboration and mark direct service proof blocked by network reachability.
- Do not escalate from one recovered credential to broad password reuse or spraying; convert the credential into a bounded capability and hand it to the chain planner.

## Session Race And State-Desync Validation
- For server-side session races, establish three artifacts: a normal low-privilege session baseline, the state-changing request that mutates the same session, and the privileged-route request that observes the mismatched state.
- Use a small coordinated loop only when source shows a real mutable-state gap, such as validation before a second session read, debug session access, shared SQL/cache sessions, multi-worker execution, or weak isolation. This is not a generic brute-force loop.
- Success requires a live response where the authorization decision and later state read disagree. If repeated attempts only return the baseline role, preserve timing/noise notes and mark the race unproven.

## Objective Proof Handling
- Treat decoded or transformed secrets as candidate evidence until they satisfy the run's explicit proof requirement, verifier, or objective pattern.
- If an artifact decodes to a secret-looking value but does not match the requested proof shape, record it as a live secret exposure and continue the most promising chain instead of declaring objective completion.
- Preserve both the encoded value and decoded output with the exact decode command so the reporter can reproduce the transformation.
- When the run provides proof regexes or proof needles, include a field or note stating whether each required proof matched; do not rely on prose such as "objective proof recovered" without the matching value.
- When a validated primitive stalls before the objective, write an objective-to-capability map: validated capabilities, missing proof artifact, shortest next replay, required auth/session state, expected output channel, and stop condition.
- If no saved request/response, marker lifecycle, screenshot, state readback, or export artifact proves the claim, label it unproven and either run the single shortest replay or cap it with negative evidence.

## Blind Inference Proof Strategy
- When the sink does not return direct output, establish a baseline response before testing the probe.
- Compare status, body length, body hash, selected headers, and elapsed time. Repeat only the strongest signal if the response is noisy.
- Preserve baseline request/response, probe request/response, delta summary, confidence, and noise notes in the validation bundle.
- Do not claim confirmation from a single weak timing or length delta; either repeat once or mark it as candidate evidence.

## Evidence-Guided Payload Mutation
- Mutate payloads based on observed filter or parser behavior, not broad spray.
- Use compact families: encoding/double encoding, quote/no-quote, mixed case, comments/whitespace, alternate separators, XSS tag/event variants, template syntax variants, traversal normalization, and command separators.
- For browser-verifier or alert-oracle XSS, mutate the execution shape before expanding tag lists: preserve the delivery format that triggers the oracle, then test raw/quoted expected value, string-building, assignment-free wrappers, and terminators. If other content types return a neutral page, record them as parser negatives instead of treating them as near-success.
- Validate verifier-oracle progress by response class, not by payload count. Keep a small table of payload, delivery, reflected/observed value, response class, and next decision; continue only if the class or observed value changes.
- Before closing an XSS verifier path as capped, require sanitizer-grammar closure when tags were stripped or transformed. Preserve a small matrix of inert tag-name probes, reflected transform, surviving attributes, whitespace behavior, delimiter behavior, and one attempted self-triggering event on the strongest surviving grammar. If whitespace is removed, a normal space-delimited HTML payload is not adequate negative evidence.
- Stop a family after the compact variants produce the same response and record negative evidence before pivoting.

## Context-Specific Proof Floors
- XSS proof requires the value to reach an executable browser or verifier context. Save the reflected/stored/DOM sink, payload context, browser evidence, and any server-recorded execution state.
- For alert-oracle XSS, proof is the server-recorded expected value, a browser-observed execution artifact, or an equivalent verifier state transition. A neutral/start response is not proof unless the verifier explicitly defines it as success.
- For sanitizer-bypass XSS, proof or cap must include the sanitizer transform. A valid cap needs evidence that accepted tag names, delimiter forms, whitespace/comment transforms, and self-triggering event families were either tested or were not applicable from current-run evidence.
- SQL/NoSQL injection proof requires a baseline/probe delta that maps to query behavior: true vs false, error vs baseline, time delta with repeat, or minimal authenticated/session impact. Do not report only because a quote changed an error page.
- SSRF proof requires a fetch-side behavior delta: same-origin or callback baseline, internal/local target delta, redirect handling result, or response content reachable only from server context.
- Upload proof requires accepted file metadata plus retrieval/parser/execution evidence. An accepted upload alone is not enough unless the vulnerability is policy bypass with impact.
- Access-control proof requires a valid actor/resource comparison. Always save owned and unowned or role-shifted request/response pairs.
- CSRF proof requires a feasible browser cross-site request shape plus state-changing effect under the target's cookie/content-type/header constraints. Missing token or SameSite alone is candidate evidence.
- CORS proof requires an untrusted origin read of sensitive authenticated data or headers, not only an echoing header.
- GraphQL proof requires operation/field-level evidence: query or mutation, variables, actor, object ownership, response delta, and whether batching/depth was only noted or actually validated.
- WebSocket proof requires handshake context plus message-level state or authorization delta, preferably confirmed by an HTTP/API readback.
- XS-Leak proof requires a defined binary secret/state question, a cross-site observable difference, a baseline/control, and a low-noise repeat. Security headers alone are not proof.
- Client-side logic proof requires the direct server request showing whether the server trusted or rejected the tampered value.
- Stateful workflow proof requires the saved request sequence, cookie jar continuity, CSRF or hidden-field handling, redirect chain, and the post-auth or post-state response that demonstrates the server-side effect.
- JavaScript-target proof requires evidence that the replay used the client-indicated action URL, method, content type, and parameter shape, plus a comparison to any misleading visible route when that route failed.

## Evidence Hygiene And Redaction
- When validation touches logs, config, tokens, cookies, reset codes, or personal data, store redacted structure plus artifact hashes/paths. Keep enough context to reproduce without disclosing raw secrets.
- Separate "secret exposed" from "secret usable." Promote usability only after one bounded service-specific validation or a clear server-side trust delta.
- For logs and debug artifacts, capture the endpoint/path, status, timestamp, key names, route/version clues, and proof-safe excerpt. Avoid bulk log copying.

## Coverage Accounting
- Report four buckets separately: validated findings, validated proof candidates, unvalidated candidates, and negative evidence.
- A run with many candidates but few validated findings should not be called "complete" until high-value candidate families are either validated or explicitly capped.
- If source, recon, browser, CVE, or skill triage discovers new high-value evidence, loop back once before final reporting.

## Command-Injection Proof Strategy
- Once command or argument injection is confirmed, do not default to slow timing or character-by-character oracle extraction.
- Do not close command execution on `echo` alone. If a target-provided proof artifact is required, use the command channel to recover it. If no proof artifact is provided, create a randomized validation marker, read it back from the target, clean it up, and store the marker path, nonce, readback, cleanup result, and state-change notes.
- In full-run mode, continue from command execution into bounded privilege and root/admin validation when authorized: record execution identity, host/container boundary, writable paths, security controls, root/admin proof if reached, and negative evidence for failed privilege paths.
- First distinguish whether control is through shell metacharacters, command arguments/options, template wrappers, filename-to-command wrappers, or environment variables. The proof and cleanup path depends on this boundary.
- Prefer the shortest safe output path in this order: direct response body, command output redirected to an already web-served writable path, command output into an application-visible file/download endpoint, then compact boolean/timing oracle only if no output channel exists.
- Before timing enumeration, test two tiny output-channel probes such as `id` into the response and `echo marker > known-writable-web-path/marker.txt` followed by a GET; keep these probes scoped to current-run observed upload/static/cache paths.
- If an oracle is the only channel, bound extraction to path discovery from current evidence and stop after the first validated proof artifact; do not wander the filesystem broadly.

## Native Surface Proof Floors
- Property overposting proof requires baseline body, expanded body, evidenced field origin, server acceptance or rejection, and persistence/action readback.
- Excessive response proof requires actor, object relation, auth state, redacted field/key evidence, and why the returned field exceeds the workflow need.
- Route-family proof requires a closure matrix, not only a successful request. Preserve validated, negative, blocked, and capped rows.
- Transport proof requires host, certificate/protocol/cipher evidence, affected scope, and an impact or policy classification.
- Scanner proof requires replay or runtime validation. A module hit without current-target replay remains a candidate.
- Mobile proof requires static evidence plus runtime behavior or a clear source/remediation boundary. Redact raw tokens, PII, cookies, and private app data.
- Agentic proof requires a trust-boundary violation: untrusted instruction to tool action, cross-context memory retrieval, skipped approval, hidden delegation, or unsupported promotion.

## Tool And Protocol Safety
- Brute-force, destructive, route-modifying, malformed-protocol, and stress modules are blocked unless the active run explicitly grants them.
- Enterprise protocol validation defaults to banner, version, and route evidence. Admin actions and credential checks require a separate operator grant.

## Exclusions
No out-of-scope, destructive, persistence, DoS, credential-stuffing, or secret-disclosure actions.
