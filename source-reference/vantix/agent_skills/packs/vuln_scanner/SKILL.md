---
name: vuln_scanner
description: Vulnerability Scanner: safe vulnerability scan planning and output triage.
---
# Vulnerability Scanner

## Use When
safe vulnerability scan planning and output triage. Apply this pack for roles: researcher, executor.

## Operating Rules
- Follow SecHive shared scope, evidence, memory, and execution policy.
- Produce dense, machine-reviewable notes with fields: `obs`, `evidence`, `risk`, `next`, `blocked`.
- Mark uncertainty explicitly; do not promote scanner hits to findings without validation.
- If execution is allowed, propose the least intrusive action first with noise level and evidence path.

## Role Focus
Use focused templates first; do not confuse scanner hits with confirmed findings.

## Evidence-Triggered Vulnerability Intel
- Run vulnerability intel whenever new evidence identifies a product, framework, package, plugin, extension, server, library, firmware, version, API generator, route namespace, error banner, or dependency manifest.
- Query local CVE/intel cache first. If the result is empty, stale, too generic, or missing the observed version/entrypoint, perform one narrow live web/CVE search.
- Search terms must come from the current target evidence only: product name, version, module/plugin/package, route namespace, filename, changelog/readme, error class, or exposed endpoint.
- Return only the actionable summary: affected version range, vulnerable entrypoint, required configuration, minimal safe proof condition, and why it does or does not apply to this target.
- When new runtime evidence appears after the first intel pass, loop back and repeat narrowly. Do not keep applying stale CVE assumptions after recon changes.
- In full proof mode, do not stop at "no CVE found"; continue with component-specific misuse tests, exposed config checks, auth boundary tests, and route-derived validation.
- If the browser surface is thin but product or route evidence exists, hand the run back with raw HTTP/API discovery guidance tied to the observed component instead of treating sparse browser coverage as route exhaustion.
- Treat verbose errors, dependency stack traces, client package names, source maps, lockfiles, and API generator route names as high-quality intel seeds. A route namespace plus version is often more actionable than a generic product banner.
- For Node/JavaScript stacks, include dependency advisories and framework misuse classes in the intel result: parser confusion, prototype pollution, unsafe redirects, file upload parser behavior, JWT/session library pitfalls, and generated REST authorization gaps.

## CMS Plugin Triage
- For WordPress, prefer version/plugin/theme fingerprinting and exposed plugin artifact checks over generic route fuzzing.
- When an active plugin and version are identified, run a focused vulnerability-intel loop before broad manual probing: query local CVE/intel cache first, then perform one live web/CVE search for `<plugin name> <version> vulnerability exploit endpoint` if local intel is empty, stale, or ambiguous.
- Treat public plugin readmes, changelogs, REST namespaces, script handles, and plugin directory names as version evidence; record the exact artifact that established the plugin/version.
- If focused intel identifies a known unauthenticated plugin entrypoint, validate that entrypoint first with the smallest safe probe before spending time on credential cracking, route fuzzing, or full backup dump review.
- When a known exploit family relies on oversized headers, generated payload chains, staged writes, or background-worker callbacks, choose a bounded check/validation mode first and avoid long payloads that exceed web-server header limits.
- When a backup/export/migration plugin is detected, run a compact check for public backup directories, predictable backup archive names from directory listings, debug logs, and exposed config/database exports.
- Treat public backup archive access as a validated exposure only after fetching headers and a small archive inventory or targeted config/database file from the archive.
- If the archive contains a large SQL dump, extract only security-relevant rows: active plugins, users, roles, options for the exposed plugin, upload paths, and short proof markers.
- For backup or migration plugins, include generated storage roots, staging roots, progress-log endpoints, manifest files, and plugin-created web-accessible temporary directories in the first focused scan. These are often faster than generic CMS admin guessing.
- If source or plugin metadata exposes a backup archive filename, verify the archive over HTTP before trying unrelated vulnerability families. A public archive with a targeted inventory is stronger evidence than a scanner hit.

## Source Version And Config Triage
- When attached source includes infrastructure manifests, container files, server configs, dependency locks, or framework config, extract exact product names, versions, enabled modules, aliases/routes, access-control blocks, and runtime write/read paths before generic CVE search.
- If the source shows a known-vulnerable server or library version, pair it with enabling conditions from config before recommending validation. Version alone is not enough; require the reachable module, route, handler, or permission boundary that makes the exploit path plausible.
- Use source-derived product/version/config as a narrow intel query seed, then hand the executor a generic validation shape: primitive probe first, bounded impact probe second, artifact capture always.
- Do not encode lab target names, expected sensitive filenames, or environment-specific proof strings into reusable guidance. Any sensitive read path must come from the current source or current live evidence.
- For vulnerable dependencies, trace whether the application actually calls the affected component/function and whether attacker-controlled input can reach that call. Record dependency version, first-party call site, route/job/parser boundary, required configuration, and safe validation shape.
- If a dependency issue is transitive, identify the first-party direct dependency and call path that pulls it into runtime. Do not report a transitive CVE as exploitable without reachable usage evidence.
- If no live usage path is found, preserve the dependency issue as remediation-priority evidence, not an exploit finding.

## Source Credential And Session Triage
- When source exposes hardcoded credentials, classify the credential by service and reachability before exploit planning: same-origin web login, side service, database, cache/session store, third-party API, or local-only helper.
- Prefer one safe reachability check against the exact service the application itself uses. If the service is exposed in scope, hand credential validation to the credential tester; if it is local-only, hand source refs plus app-observed output to web validation.
- When source shows server-side session storage, debug session disclosure, weak/static secret keys, low database isolation, or validation followed by a second mutable-state read, generate a session-state race/desync hypothesis for the web hunter and PoC validator.

## Scanner Output Discipline
- Scanner matches seed hypotheses; they are not findings until live validation proves the current target behavior.
- Scanner negatives are not final if browser/source/API evidence later reveals a new product, route, version, or sink.
- Close intel-led exploit families explicitly as validated, negative evidence, blocked, or capped. Do not leave a high-value product/version lead unresolved when the run is still in proof mode.
- Preserve each intel query, evidence seed, result count, selected advisory, validation attempt, and rejection reason so later agents can continue without repeating broad searches.

## Disclosure And Logging Triage
- Treat exposed logs, stack traces, debug routes, backups, source maps, configuration endpoints, and client bundles as evidence sources, not automatically confirmed impact.
- Classify leaked material before chaining: route map, dependency/version, secret/config candidate, token/session candidate, PII/private data, internal host, local path, or business workflow clue.
- Redact sensitive values in notes and reports while preserving enough structure for reproduction: key name, endpoint, status, path, length/hash, and proof-safe excerpt.
- If a secret/config candidate appears, route it to credential/session/source validation with the exact service boundary. Do not attempt broad reuse or spraying.

## Scanner Module Safety Triage
- Classify any scanner or tool module before use: passive inventory, safe probe, active validation, brute force, destructive, or unknown.
- Run modules only when current evidence identifies the matching service, version, endpoint, auth state, and proof condition. A module name alone is not enough.
- Brute-force, credential guessing, destructive, DoS, route-modifying, or malformed-protocol modules are blocked unless the active run explicitly authorizes that behavior.
- Scanner output becomes a hypothesis packet: target evidence, module rationale, output excerpt, confidence, validation plan, and rejection criteria.

## Transport Configuration Review
- For TLS or HTTPS surfaces, collect host, certificate chain, issuer, SANs, expiry, hostname match, supported protocol versions, weak ciphers, redirect posture, and HSTS behavior.
- Separate cryptographic hygiene from app impact. Weak transport configuration becomes a finding when it affects scoped hosts and plausible sensitive traffic, session integrity, downgrade exposure, or compliance requirements.
- Use one low-noise inventory pass by default; do not stress-test downgrades or interception outside scope.

## Enterprise Protocol Recon
- For enterprise protocol services, stay in safe recon unless the operator grants more: banner, route string, product family, version-confidence, service role, and required authorization.
- Admin commands, route-table modification, brute force, credential validation, malformed packet fuzzing, and destructive probes are blocked by default.
- If version or protocol evidence creates an intel lead, return affected version range, required configuration, safe proof condition, and why the target evidence does or does not satisfy it.

## Exclusions
No out-of-scope, destructive, persistence, DoS, credential-stuffing, or secret-disclosure actions.
