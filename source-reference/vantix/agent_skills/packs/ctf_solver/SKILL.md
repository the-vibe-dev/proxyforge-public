---
name: ctf_solver
description: CTF Solver: CTF methodology across web, pwn, rev, crypto, forensics.
---
# CTF Solver

## Use When
CTF methodology across web, pwn, rev, crypto, forensics. Apply this pack for roles: orchestrator, researcher, developer, executor, reporter.

## Operating Rules
- Follow SecHive shared scope, evidence, memory, and execution policy.
- Produce dense, machine-reviewable notes with fields: `obs`, `evidence`, `risk`, `next`, `blocked`.
- Mark uncertainty explicitly; do not promote scanner hits to findings without validation.
- If execution is allowed, propose the least intrusive action first with noise level and evidence path.

## Role Focus
Guide enumeration-first solving and record repeatable learning.

## Training Posture
- Treat CTF, lab, and deliberately vulnerable apps as training grounds for general security reasoning, not as answer banks.
- Do not rely on public writeups, challenge-specific strings, hardcoded credentials, known routes, or memorized payloads unless the operator explicitly provides them as current-run evidence.
- Build reusable capability notes: what signal revealed the weakness, which target-controlled input mattered, which server-side invariant failed, and how the proof was bounded.
- Prefer transferable primitives over named challenge goals: hidden route discovery, auth workflow modeling, parser boundary testing, weak token analysis, upload handling, cross-origin trust, and business-logic invariant checks.
- When a challenge-like app exposes a score, achievement, or solved-state oracle, use it only as secondary validation. Primary evidence is still the request/response, browser behavior, state transition, or artifact that proves the underlying weakness.

## General Web Lab Method
- Start with a surface ledger: visible routes, client-side routes, API endpoints, static directories, generated docs, upload/import handlers, account flows, support/contact flows, checkout or money-like flows, profile/privacy flows, redirects, URL-fetchers, and downloadable artifacts.
- Mine client assets for route literals, feature names, role labels, hidden pages, API base paths, source-map hints, license manifests, translation files, build artifacts, security metadata, and dead or debug code paths.
- Treat every discovered route as a hypothesis, not a solution. For each route, identify auth state, method, content type, object identifiers, workflow state, parser, and readback path.
- Use normal app workflows first, then replay the equivalent server request with one changed invariant at a time.
- Record negative evidence. A stable rejection, unchanged state, or browser-only guard is useful training data when it closes a family cleanly.

## Weakness Families To Search
- Client-side trust: hidden routes, disabled controls, client-only validation, local/session storage state, role or price fields, and JavaScript-only allowlists.
- API trust boundaries: object ownership, function-level authorization, mass assignment, method override, duplicate parameter handling, schema mismatches, excessive response fields, and generated REST siblings.
- Injection and parser boundaries: SQL-like errors and boolean deltas, document-store operator shapes, template rendering, unsafe expression evaluation, XML/YAML/archive parsing, and command argument boundaries.
- Browser execution: DOM, reflected, stored, header-fed, markdown/rendered HTML, and media/subtitle-like sinks. Always map source to sink and preserve browser or server-recorded proof.
- File and static exposure: directory listings, backup/config/license/build artifacts, language files, logs, metrics, well-known security files, key material, and path normalization behavior.
- Upload and import: extension checks, MIME checks, content signatures, archive member paths, parser errors, storage paths, retrieval paths, and cleanup.
- Crypto and token logic: weak encodings, predictable token formats, unsafe JWT algorithm handling, key confusion, public key exposure, hash/continue-code style tokens, and client-side coupon or discount logic.
- Account recovery and OSINT: security-question prompts, public profile clues, metadata leakage, alias reuse, and reset state-machine binding. Keep testing limited to authorized accounts or lab identities.
- Automation and race behavior: CAPTCHA or anti-automation replay, request pinning, concurrent state changes, and time-window checks with strict rate and noise limits.
- Cross-origin behavior: CSRF feasibility, CORS readback, JSONP callbacks, frame/load side channels, open redirects, and redirect-assisted server fetches.
- Web3 or wallet flows: seed/private-key handling, transaction authorization boundaries, reentrancy-shaped state updates, and front-end contract assumptions. Use test networks and explicit operator approval only.

## Solving Loop
- Pick the highest-signal family from current evidence, run the smallest baseline/probe pair, and classify the response class.
- If a primitive works, ask what it unlocks next: authentication, privileged route, source artifact, file parser, URL fetch, token forging, object write, or report proof.
- If a primitive stalls, write a closure note with the observed blocker and pivot to the next family from the surface ledger.
- End with a coverage matrix that separates validated weaknesses, candidates needing one more proof, negative evidence, and blocked lanes.

## Exclusions
No out-of-scope, destructive, persistence, DoS, credential-stuffing, or secret-disclosure actions.
