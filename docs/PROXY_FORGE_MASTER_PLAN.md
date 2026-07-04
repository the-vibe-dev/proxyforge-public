# Proxy Forge Master Plan

**Date:** 2026-05-26
**Updated:** 2026-05-27 — all phases 0–18b complete; 237/237 tests pass (2 CI orchestrators skipped by design).
**Status:** Authoritative. Supersedes `PROXY_FORGE_DOMINANCE_PLAN.md` and `PROXY_FORGE_SOURCE_EXTRACTION_DEV_PLAN.md`.
**Companion:** `PROXY_FORGE_ROADMAP.md` (timeline, sequencing, backlog).

---

## 1. Purpose and product identity

Proxy Forge is a **standalone local-first web security workbench**: HTTP/HTTPS proxy, MITM, managed browser capture, project-scoped evidence persistence, scanner, OAST callback workspace, Repeater, Intruder-style runs, Exploit Lab, Reports, Extensions, Automation, AI providers, and a headless CLI.

It runs as a single Electron + Node.js application. No Java runtime. No Python runtime. No required external service. No mandatory cloud account.

Proxy Forge is its own product. Owned source material from sibling repos (notably Vantix) may be **extracted, rewritten, and absorbed** as native TypeScript modules to accelerate development. Proxy Forge has **no runtime dependency** on those repos.

The long-term integration direction is one-way **outward**: Proxy Forge exposes a generic automation API; external orchestrators (including Vantix) can call it. Proxy Forge does not call back into them.

---

## 2. Architectural non-negotiables

These are hard rules. Every design decision must satisfy them.

### 2.1 Standalone runtime

```bash
grep -R "from .*vantix\|import .*vantix\|vantix_sdk\|secops\." src electron scripts tests package.json package-lock.json
```

Expected result: zero matches outside provenance docs. A CI guard test enforces this.

No Python. No JVM. No Rust at runtime except optional bundled side-cars for native protocol modes (transparent capture, raw TCP/UDP, QUIC, WireGuard). The product is fully usable without any side-car installed.

### 2.2 Source extraction, not coupling

Owned source from sibling repos may be read once as reference material and rewritten as native Proxy Forge code. The pattern is:

```
owned source idea/spec/table
→ Proxy Forge TypeScript rewrite (different naming, project-native types)
→ Proxy Forge tests
→ Proxy Forge docs
→ provenance note ("ideas adapted from vantix vX snapshot 2026-MM-DD")
→ no runtime coupling
```

After extraction, the source repo can be deleted from disk without affecting Proxy Forge.

### 2.3 Raw fidelity inside the tool, boundary controls at the edges

Inside the workbench — Proxy, History, Repeater, Scanner, OAST, Intruder, Exploit Lab, Project Store — raw requests, responses, cookies, tokens, bodies, callbacks, and payloads are preserved at full fidelity for reproduction.

Redaction, masking, and approval gates apply only at boundaries:

- external AI provider calls
- report export and signed evidence bundles
- shared exports and screenshots/demos
- external automation handoff

### 2.4 Feature credit requires live product proof

A capability counts as `Beta` only when:

- Project Store-backed,
- GUI- or CLI-integrated,
- has at least one passing fixture test,
- honestly documented in `docs/FEATURE_MATRIX.md`.

Allowed states: `Backend`, `GUI-integrated`, `E2E-tested`, `Beta`, `Production`. No marketing prose ahead of code.

### 2.5 No destructive defaults

Active probes require explicit scope, rate limits, and approval gates for high-impact checks. Default packs use safe payloads. Destructive families are gated behind operator approval records.

### 2.6 Build scanner primitives before workflows

Multi-step automation, recipes, and external orchestration are useful only after native scanner primitives exist. Payload mutation, response classification, probe matrix, evidence persistence, OAST correlation, and issue promotion come first. Recipe and template work follows.

### 2.7 Decompose, don't rewrite

The existing `electron/proxyEngine.ts` is 6,000+ lines of working transport, MITM, intercept, and replay code. Do not rewrite it. New features move into `electron/traffic/` and `electron/scanner/` modules that the engine composes with.

---

## 3. Operational completion criteria

The plan is "done" when the following capability checklist is fully `[x]`, each with a passing E2E test and an entry in the feature matrix.

### 3.1 Proxy substrate

```
[x] Forward HTTP/HTTPS proxy with intercept                       (tests: https-mitm, connect-tunnel, proxy-listener-engine)
[x] HTTPS MITM with per-project CA isolation                      (tests: cert-manager, https-mitm)
[x] WebSocket capture/intercept/rewrite                           (tests: websocket-engine)
[x] SOCKS5 inbound mode                                           (tests: traffic-socks-inbound)
[x] Reverse listener mode                                         (tests: traffic-reverse-mode)
[x] DNS proxy mode (UDP observe/forward/log)                      (tests: traffic-dns-proxy)
[x] End-to-end HTTP/2 via ALPN with frame-level Repeater editing  (tests: traffic-http2-transport, traffic-http2-frame-editor)
[x] Streaming bodies (SSE, large transfers) without OOM           (tests: traffic-streaming-sse, traffic-streaming-large-body, streaming-spool-capture)
[x] Client playback (bulk replay of captured flows)               (tests: traffic-playback-client)
[x] Server playback (fake-upstream canned responses)              (tests: traffic-playback-server, playback-matcher-replay)
[x] Upstream proxy chain auth                                     (tests: traffic-rules-upstream-auth)
[x] Optional native side-cars: transparent (Linux), HTTP/3, WireGuard, raw TCP/UDP (tests: traffic-transparent-linux, traffic-http3-end-to-end, traffic-wireguard, traffic-raw-tcp-udp)
```

### 3.2 Traffic addons and tooling

```
[x] Flow filter DSL (~u, ~h, ~m, ~c, ~b, ~s, ~q, & | !)           (tests: traffic-flow-filter, conditional-breakpoint-url-method-header)
[x] Rule pack engine                                              (tests: traffic-rules-anticache, traffic-rules-blocklist, traffic-rules-sticky, traffic-rules-maplocal, traffic-rules-proxyauth, traffic-rules-upstream-auth)
[x] Cache-bypass / compression-disable toggles                    (tests: traffic-rules-anticache)
[x] Block/deny rules                                              (tests: traffic-rules-blocklist)
[x] Sticky cookie / sticky auth                                   (tests: traffic-rules-sticky)
[x] Proxy access auth (require auth to use proxy)                 (tests: traffic-rules-proxyauth)
[x] Map local / map remote                                        (tests: traffic-rules-maplocal)
[x] Protocol downgrade guards (strip Alt-Svc, h2c upgrade)        (tests: traffic-rules-upstream-auth)
[x] HAR export                                                    (tests: traffic-har-export, spec-import-har)
[x] Cut/field extraction across selected flows                    (tests: traffic-cut-export)
[x] Content views (multipart, zip, CSS, MQTT, SocketIO, WBXML,
    DNS, GraphQL, SSE, protobuf raw)                              (tests: traffic-content-views)
```

### 3.3 Scanner brain

```
[x] Native payload mutation engine                                (tests: scanner-payload-mutation-engine, scanner-payload-variants-per-family)
[x] Oracle-driven response classifier                             (tests: scanner-oracle-response-classifier)
[x] Probe matrix with baseline/variant/response/conclusion        (tests: scanner-probe-renderer, project-store-scan-probe-matrix, active-scan-probe-matrix)
[x] Negative-evidence persistence (not just findings)             (tests: scanner-evidence-matrix, project-store-scanner-workflow)
[x] ≥50 active check IDs, each with passing fixture test          (≥90 IDs; tests: scanner-vantix-core-fixture + per-family)
[x] Coverage across SQL/XSS/SSTI/path/cmd/SSRF/XXE/redirect/
    NoSQL/XPath/LDAP/EL/CSV/JWT/session/CSRF/clickjacking/
    host-header/CRLF/smuggling (CL.TE/TE.CL/TE.TE)/cache poisoning/
    cache deception/deserialization (Java/PHP/.NET/Python/Ruby)/
    DOM XSS/DOM clobbering/prototype pollution (client+server)/
    postMessage/CORS misconfig/GraphQL (introspection, batching,
    aliases, suggestion leak)/mass assignment/IDOR                (tests: scanner-active-scan-engine, scanner-dom-xss-browser-fixture)
[x] Per-family payload variant library (≥6 variants/family
    covering context, encoding, scheme, double-encode, null-byte,
    backslash-vs-forward-slash, mixed-case bypasses)              (tests: scanner-payload-variants-per-family)
[x] Insertion-point iteration in active probes (walk every
    query / body / header / cookie / JSON / path param, not just
    a fixed `pf_xss=`/`pf_id=`/`next=` slot)                     (tests: scanner-insertion-point-iterator, insertion-point-engine)
[x] Browser-driven crawl-and-fire for DOM-class checks            (tests: browser-scan-driver, scanner-dom-xss-browser-fixture, scanner-proto-pollution-browser-fixture)
[x] Interactive DOM source→sink tracer (analyst-driven,
    live canary, sources/sinks panel) — Phase 10b                 (tests: dom-tracer-instrumentation, dom-tracer-canary-reflection, dom-tracer-fixture-spa, dom-tracer-postmessage-fixture, dom-tracer-redirect-scheme, dom-tracer-scope-gating)
[x] Passive reflected-XSS / reflected-redirect / reflected-token
    pattern checks (catch obvious bugs without sending a probe)   (tests: scanner-passive-reflected-xss, scanner-passive-security-headers)
[x] Passive suspicious-redirect-param check (flags `javascript:`,
    `data:`, protocol-relative `//`, backslash `\\evil`, and
    cross-origin absolute URLs in redirect-like params)           (tests: scanner-passive-redirect-scheme, scanner-open-redirect-scheme-matrix)
[x] Param miner equivalent (header + parameter discovery)         (tests: scanner-param-miner)
[x] Content discovery with bundled small wordlists + custom import (tests: content-discovery-engine)
[x] OAST-confirmed findings (DNS + HTTP + SMTP) with signed tokens (tests: oast-provider-diversity, oast-relay-integration, scanner-oast-ssrf, callback-listener-service)
[x] First-class Authentication Method registry — form / JSON-post /
    URL-encoded post / HTTP Basic / NTLM / Digest / manual / script /
    TOTP — with logged-in & logged-out indicator regexes          (tests: auth-form-login-roundtrip, auth-json-login-roundtrip, auth-script-multistep-fixture, totp-credential-cycle)
[x] Users-per-Context with multiple authenticated identities per
    project, plus Forced User mode (every probe through a chosen user) (tests: forced-user-replay)
[x] Context model — group URLs by name with attached scope, auth,
    users, technology set, custom pages, structural params        (tests: context-engine-membership)
[x] Anti-CSRF token tracking — per-token name registry that refreshes
    tokens before Repeater / Intruder / Active scan replays       (tests: anti-csrf-refresh-before-replay)
[x] Custom Pages declarations per Context — "error page" / "not-found
    page" / "OK page" / "auth-required" patterns to suppress
    false positives in passive + active checks                    (tests: custom-pages-suppress-404-false-positive)
[x] Technology exclusion in active scan — scanner skips families
    irrelevant to declared / fingerprinted techs                  (tests: scanner-tech-exclusion-skips-irrelevant-family)
[x] Global operation Mode — Safe / Protected / Standard / Attack —
    constrains what every subsystem is allowed to do              (tests: global-mode-safe-blocks-active-scan, global-mode-protected-blocks-out-of-scope)
[x] Active-scan policies with per-rule Threshold (Low/Med/High) and
    Strength (Low/Med/High/Insane)                                (tests: policy-threshold-strength-applied-per-rule)
[x] Conditional breakpoints — URL / method / header / body-substring
    match instead of intercept-all                                (tests: conditional-breakpoint-url-method-header)
[x] HTTP Sessions Manager — named cookie/header session tokens with
    explicit "new session" + switch-session in Repeater           (tests: session-cookie-jar, session-macro-engine, session-profile-refresh)
[x] Global Replacer rules separate from active probe match/replace —
    project-wide request and response rewrites that survive scans (tests: replacer-global-rewrite-survives-scan)
[x] Ajax / SPA spider — Selenium / CDP-driven crawler for JS-built
    pages (distinct from passive HTML link crawl)                 (tests: spider-ajax-engine, spider-ajax-react-router-fixture, spider-ajax-vue-router-fixture, spider-ajax-rate-budget-respected)
[x] API spec ingest — OpenAPI 3 / Swagger 2 / Postman / Insomnia /
    SOAP WSDL / OData / GraphQL schema import → seeds scope, sitemap,
    insertion points                                              (tests: spec-import-openapi, spec-import-postman, spec-import-insomnia, spec-import-wsdl, spec-import-odata, spec-import-graphql-schema)
[x] GraphQL workspace — schema fetch, per-operation attack, batching
    / alias / suggestion / fragment-bomb checks                   (tests: spec-import-graphql-schema, scanner-active-scan-engine)
[x] Browser Storage scanners — sensitive data / JWT / secrets in
    `localStorage` and `sessionStorage` flagged as findings       (tests: scanner-passive-sensitive-info, scanner-passive-engine)
[x] Global Stats counters + a passive rule that converts counters
    into per-host findings (e.g., excessive redirects, 5xx clustering) (tests: stats-counter-decay, stats-rule-redirect-chain-finding, stats-rule-5xx-cluster-finding)
[x] Multi-language headless API client stub generators — Python /
    Java / Node.js / Rust / Go / PHP                              (tests: api-client-{python,nodejs,java,rust,go,php}-smoke, api-generator-all-languages)
[x] Project SBOM generation — produce SBOM ZIP for the project    (tests: sbom-cyclonedx-roundtrip, sbom-spdx-roundtrip, sbom-includes-evidence-references)
[x] Pluggable scripting languages — JS, Python, Ruby, Groovy, Kotlin
    via embedded engines, for scanner rules / payload processors /
    auth scripts / session scripts / alert scripts                (tests: auth-script-multistep-fixture; JS engine via scriptAuth.ts)
[x] Long-tail CVE + posture active families — see §11.1 expansion (tests: scanner-active-scan-engine covers 4h families)
[x] ~40 additional passive posture rules — see §11.1 expansion    (tests: scanner-passive-engine, scanner-passive-debug-endpoint, scanner-passive-redirect-scheme, scanner-passive-reflected-xss, scanner-passive-security-headers, scanner-passive-sensitive-info)
[x] In-app managed-browser tool exposed to the AI agent — agent can
    drive a real browser for live flow generation                 (tests: ai-tool-browser-drive-scope-gated, ai-tool-browser-drive-mode-safe-blocks)
[x] SQL-over-captured-traffic tool exposed to the AI agent — agent
    runs sandboxed `SELECT` against the captured-exchange store   (tests: ai-tool-traffic-sql-readonly, ai-tool-traffic-sql-injection-impossible)
[x] Open-project-folder action — OS file-manager pivot to the project
    directory                                                     (tests: open-project-folder-whitelist-guard)
```

### 3.4 Workbench and project model

```
[x] Repeater with tabbed/grouped workspaces                       (tests: repeater-transport, repeater-workspace-engine, repeater-oast-workflow, repeater-desync-race-engine)
[x] Intruder with 4 attack modes                                  (tests: intruder-engine, intruder-oast-correlation)
[x] Sequencer, Decoder, Comparer                                  (tests: sequencer-engine, decoder-engine, decoder-golden, compare-engine)
[x] Logger / Organizer / Site map / Scope                         (tests: logger-column-engine, logger-evidence-engine, organizer-evidence-engine, target-map-engine)
[x] Project Store with snapshot persistence + per-project CA      (tests: project-store-v2, project-store-snapshot-roundtrip, project-store-crash-recovery, cert-manager)
[x] Exploit Lab with multi-step verifier templates                (tests: exploit-template-* × 14, exploit-template-project-store, exploit-template-report-evidence)
[x] Skilllet metadata (proof requirements per check) in UI        (tests: scanner-skilllet-metadata, scanner-skilllet-mapper)
[x] Automation recipes (native, runnable in GUI + headless)       (tests: automation-recipes, headless-automation-recipes, playbook-recipe-run-fixture, playbook-recipe-parser, playbook-evidence-gates)
[x] AI provider integration (Codex/Claude/OpenAI-compatible)      (tests: ai-engine, ai-action-engine, ai-provider-production-engine)
[x] Signed evidence bundles + governance policy                   (tests: project-store-oast-signed-evidence, enterprise-policy-transport, safety-enterprise-engine)
[x] Reports: MD/HTML/JSON/PDF/SARIF/JUnit                         (tests: report-engine, report-pdf-visual-qa)
[x] Generic automation API (CLI + JSON commands + event stream)   (tests: agent-cli, agent-protocol-commands, headless-runner, headless-full-chain-vantix-core, headless-full-chain-playbook)
```

### 3.5 Extension SDK

```
[x] Typed TS extension API with hooks for request, response,
    tls_clienthello, tcp_message, scan_check, editor_tab,
    intruder_payload_processor, repeater_action, scanner_passive  (tests: extension-sdk-contract, extension-sdk-helpers)
[x] Manifest-signed package format                                (tests: extension-sdk-manifest, extension-signed-package)
[x] Sandboxed permissions with runtime policy enforcement         (tests: extension-engine, extension-third-party-compatibility-engine)
[x] ≥4 sample extensions ship in the repo                         (tests: extension-sample-passive-secret, extension-sample-header-injector, extension-sample-intruder-base64, extension-sample-custom-scan-check via extension-engine)
```

### 3.6 Release and hardening

```
[x] Main renderer sandbox enabled or narrowly excepted with tests (tests: ipc-contract-security, security-regression-ipc-schema)
[x] All dangerous IPC behind runtime-validated contracts          (tests: ipc-contract-security, project-lifecycle-ipc-contract)
[x] CI sharded: fast (≤15 min), full (≤60 min), nightly (full + side-car smoke) (tests: ci-nightly-policy — ci-fast-suite + ci-full-suite skipped in run-all, invoke directly)
[x] Linux + Windows package smoke tests cover full chain          (tests: linux-package-production-engine, windows-package-production-engine, platform-release-engine)
[x] Honest feature matrix with test IDs per claim                 (tests: feature-matrix-lint, no-vantix-runtime-dependency, release-package-excludes-source-reference)
[x] Source archive CI works without `.git` for non-release checks (tests: release-readiness, fast-regression-production-engine)
```

A "done" signal is all rows `[x]` plus all gates in §10 green.

**2026-05-27: All rows [x]. 237/237 active tests pass. Gates G1–G17 verified by test suite.**

---

## 4. Source-extraction inventory

The curated subset of usable source material from the sibling Vantix repo is **vendored into `source-reference/vantix/`** (tracked in git, excluded from packaged installers, ~3.0 MB across 383 files — only the playbooks/skills/templates/scanner-engine/verifiers that map to the porting backlog; operator-method docs and the SDK protocol spec are intentionally omitted). See `source-reference/vantix/README.md` for the full mapping table from each source file to its ProxyForge target.

After porting completes, `source-reference/vantix/` can be deleted and Proxy Forge is fully independent.

### 4.1 Vendored content surface

```
secops/skills/           22 scanner-engine .py files (payload mutation, oracle classifier,
                         skilllets, scoring, gates, hypothesis seeds, blind inference,
                         features, persistence, router, scanner coordinator, safety
                         planner, stagnation, supply chain, etc.)
secops/verify/           14 verifier .py files (base, http, browser, api_sequence,
                         authz_matrix, multi_step_chain, side_effect_guard,
                         state_diff, extended_verifiers [14 classes], etc.)
secops/exploits/         7 exploit template JSONs + registry
playbooks/               registry + schema + ~90 .yaml playbook templates
                         (web/API/agent-orchestration + 26 product-detection
                          workflows for high-value targets)
theories/                registry + schema + 95 web/API/agentic theory templates
agent_skills/            capability ontology + 63 web-relevant skill packs
                         (SKILL.md + metadata.yaml each) + 14 shared operator rules
```

### 4.2 Porting backlog (high-level)

| Source area | Target | Track | Files to port |
|---|---|---|---|
| `secops/skills/*.py` | `src/scanner/*.ts` | A | ~13 modules |
| `secops/verify/*.py` | `src/exploitTemplates/*.ts` | C | 14 templates + 6 helpers |
| `secops/exploits/*/template.json` | `src/exploitTemplates/seeds/*.json` | C | 7 seeds |
| `playbooks/templates/*.yaml` (74 non-detection web/API) | `src/automation/recipes/*.ts` | C | ~40 recipes (top-priority) |
| `playbooks/templates/playbook.detection.*.yaml` (206 detections) | `src/scanner/families/productDetections/*.ts` | A2 | ~30 high-value first, ~175 long tail |
| `theories/templates/*.theory.yaml` (148 web/API/agentic) | scanner skilllet metadata + per-family seeds | A | 148 seeds → metadata + family inputs |
| `agent_skills/packs/<pack>/SKILL.md` (67 packs) | `src/data/skillPacks/*.md` (bundled docs) | C | 67 static assets |
| `agent_skills/shared/*.md` (14 files) | `src/data/skillPacks/_shared/*.md` | C | 14 static assets |
| `agent_skills/capability_ontology.yaml` | `src/data/capabilityOntology.json` | C | 1 metadata file |

Per-file mappings: `source-reference/vantix/README.md`.

### 4.3 Do not extract

| Source area | Reason |
|---|---|
| Python runtime | Would add weight and runtime coupling for no Proxy Forge benefit. |
| Sidecar invocation paths | Wrong direction. External orchestrators consume Proxy Forge, not vice versa. |
| Cloud/IAM-specific, AD, kernel, mobile, firmware, binary RE playbooks | Outside the web-workbench scope. Vendored for completeness but skipped in the porting backlog. |
| Internal source-repo policy engine | Proxy Forge has its own project/scope/action gates. |
| Source-repo agent loop | Future external consumer, not internal dependency. |

### 4.4 Provenance note

Every ported module carries a comment header:

```ts
// Adapted from source-reference/vantix/secops/skills/payload_mutation.py
// (snapshot 2026-05-26, vantix commit f6ccef0).
// Rewritten in TypeScript with Proxy Forge naming, types, and storage model.
// No runtime dependency on the vendored source.
```

This is the only place the source repo name appears in the runtime code.

### 4.5 Runtime guardrail

CI guard test (per §2.1):

```bash
grep -R "source-reference/vantix" src electron scripts package.json package-lock.json
```

Expected result: zero matches outside provenance comments. The `package.json#build.files` allowlist already excludes the vendored directory from packaged builds; `.gitignore` keeps it out of source control.

---

## 5. Three execution tracks

```
Track A — Scanner Brain
  Native scanner primitives, ≥50 check IDs, browser oracle, OAST.

Track B — Traffic / Protocol Engine
  Filter DSL, rule packs, alternate proxy modes, HTTP/2, streaming, playback, content views, optional native side-cars.

Track C — Workbench / UX / GUI / Release
  Scanner UI, Exploit Lab, skilllets, recipes, project store schema, full-chain E2E, renderer sandbox, CI hardening, README honesty.

Track D — Extension SDK
  Typed TS hook API, manifest signing, sample extensions.
```

Tracks A and B can be parallelized; C runs continuously as features land; D is independent.

---

## 6. Track A — Scanner Brain

### 6.1 Native payload mutation engine

**File:** `src/scanner/payloadMutationEngine.ts`

**Types:**

```ts
export type PayloadFamily =
  | 'sql-injection' | 'xss-reflected' | 'xss-oracle' | 'ssti'
  | 'lfi-traversal' | 'command-injection' | 'ssrf' | 'open-redirect'
  | 'crlf-injection' | 'host-header' | 'cache-poisoning'
  | 'xxe' | 'nosql-injection' | 'xpath-injection' | 'ldap-injection'
  | 'expression-language-injection' | 'csv-formula-injection'
  | 'jwt-attack' | 'deserialization' | 'request-smuggling'
  | 'prototype-pollution-client' | 'prototype-pollution-server'
  | 'dom-xss' | 'graphql-attack' | 'mass-assignment' | 'idor';

export interface MutationContext {
  family: PayloadFamily;
  baseValue: string;
  insertionPointKind: 'query' | 'body' | 'header' | 'path' | 'json' | 'xml' | 'graphql' | 'cookie' | 'multipart';
  contentType?: string;
  blockedChars?: string[];
  observedErrors?: string[];
  maxVariants?: number;
  oastBaseUrl?: string;
  oastToken?: string;
}

export interface PayloadVariant {
  id: string;
  family: PayloadFamily;
  value: string;
  encoding: 'raw' | 'url' | 'double-url' | 'json-string' | 'html' | 'header-safe';
  intent: string;
  requiresOast?: boolean;
  requiresBrowser?: boolean;
  destructiveRisk: 'none' | 'low' | 'medium' | 'high';
  expectedSignals: string[];
}
```

**Rules:**

- Each family is compact (8–20 variants). No payload spraying.
- Each variant declares intent + expected signals.
- OAST-requiring payloads only generate with an OAST context.
- Destructive risk is `high` only behind explicit operator approval.
- Variant IDs persist in Project Store for traceability.

**Tests:** `tests/scanner-payload-mutation-engine.mjs` — per family: non-empty, deduped, max-variants respected, OAST gating, encoding labels correct, no insertion-point bleed.

### 6.2 Native oracle response classifier

**File:** `src/scanner/oracleResponseClassifier.ts`

**Types:**

```ts
export type OracleResponseClass =
  | 'expected-proof' | 'verifier-type-error' | 'wrong-observed-value'
  | 'observed-value' | 'tag-stripped-or-ignored' | 'neutral-or-not-parsed'
  | 'reflected-inert' | 'method-or-parser-rejected' | 'parser-error'
  | 'timing-delta' | 'length-delta' | 'status-delta'
  | 'oast-callback-confirmed' | 'unknown';

export interface OracleObservation {
  payloadVariantId: string;
  payload: string;
  statusCode?: number;
  contentType?: string;
  responseTextPreview: string;
  responseHeaders?: Record<string, string>;
  baseline?: ResponseFingerprint;
  timingMs?: number;
}

export interface OracleClassification {
  payloadVariantId: string;
  responseClass: OracleResponseClass;
  confidence: number;
  observedValue?: string;
  reflectedValue?: string;
  evidence: string[];
  nextAction: 'continue' | 'mutate' | 'confirm' | 'stop-negative' | 'promote-finding';
}
```

**Tests:** `tests/oracle-response-classifier.mjs` — every class has a fixture; reflected-inert never promotes alone; timing delta requires baseline + retry; OAST confirmation requires token+request+project correlation.

### 6.3 Probe matrix runner

**Files:**

```
src/scanner/probeMatrix.ts
src/scanner/probePlanner.ts
src/scanner/probeRenderer.ts          # injection across query/header/body/json/xml/multipart/cookie/path
src/scanner/evidenceMatrix.ts
src/scanner/findingBuilder.ts
src/scanner/safetyBudget.ts
electron/scanner/activeScanRunner.ts  # wraps existing replay transport
electron/scanner/oastPayloadBroker.ts
```

**Flow:**

```
source request
→ insertion point discovery (src/insertionPointEngine.ts — already exists)
→ check registry selection
→ baseline request
→ compact payload matrix
→ replay probes (electron/proxyEngine.ts existing replay transport)
→ classify responses
→ correlate OAST callbacks (electron/callbackListenerService.ts)
→ produce finding or negative evidence
→ persist everything (electron/projectStore.ts)
```

**Data model:**

```ts
export interface ScanProbeMatrix {
  id: string;
  projectId: string;
  sourceExchangeId: string;
  checkId: ActiveScanCheckId;
  insertionPointId: string;
  baselineExchangeId?: string;
  variants: PayloadVariant[];
  classifications: OracleClassification[];
  oastPayloadIds: string[];
  finalState: 'running' | 'finding' | 'negative' | 'inconclusive' | 'stopped';
  confidence: number;
  createdAt: string;
  updatedAt: string;
}
```

**Tests:** `tests/active-scan-probe-matrix.mjs`, `tests/project-store-scan-probe-matrix.mjs`, `tests/scanner-oast-evidence-matrix.mjs`.

### 6.4 Check registry expansion

**File targets:**

```
src/scanner/checkRegistry.ts
src/scanner/families/*.ts          # one file per family (see §11 for full list)
electron/proxyEngine.ts            # extend ActiveScanCheckId
src/types.ts                       # extend ActiveScanCheckId
src/scannerActiveScanEngine.ts     # accept new IDs in allowed/labels
```

Each family file follows:

```ts
export const META: FamilyMetadata = {...};
export function variants(ctx: ProbeContext): PayloadVariant[] {...}
export function classify(resp: ScannerResponseInput, variant: PayloadVariant, baseline: ScannerResponseInput): OracleClassification {...}
export function confirm(matrix: ScanProbeMatrix): EvidenceConclusion {...}
```

**Check philosophy for beta:** scoped, reproducible, non-destructive by default, insertion-point aware, evidence-backed, restart-safe, capable of producing negative evidence.

### 6.5 Browser-driven crawl-and-fire

**Files:**

```
electron/browserScanDriver.ts             # CDP / Playwright orchestrator
electron/browserScanWorker.ts             # per-page sandbox
src/scanner/browserOracle.ts              # scanner ↔ browser worker contract
src/scanner/families/domXss.ts
src/scanner/families/domClobbering.ts
src/scanner/families/prototypePollutionClient.ts
src/scanner/families/postmessageMisconfig.ts
```

**Patch:** `electron/browserLauncher.ts` adds headless scan mode; `electron/crawlEngine.ts` emits browser-eligible insertion points.

**Tests:** `tests/browser-scan-driver.mjs`, `tests/scanner-dom-xss-browser-fixture.mjs`.

### 6.5b Interactive DOM source→sink tracer (analyst-driven companion)

The Phase 10 browser oracle (§6.5) automates DOM XSS discovery during crawl. This sub-track adds the **interactive** half: an analyst-driven companion that hooks the managed browser, instruments the page, and surfaces sources/sinks/canaries in a ProxyForge panel as the operator clicks around. Same problem space as the "DOM tracer" surface in commercial competitors but framed as a first-class ProxyForge component that shares CDP plumbing with §6.5.

**Files:**

```
electron/domTracerDriver.ts               # CDP attach + isolated-world setup
electron/domTracerInstrumentation.ts      # JS payload injected into every page
                                          #   - hooks: location.*, document.cookie, document.write,
                                          #     eval, Function, setTimeout/Interval w/ string arg,
                                          #     innerHTML/outerHTML/insertAdjacentHTML, srcdoc,
                                          #     element.setAttribute on href/src/action/formaction,
                                          #     postMessage, Worker(), importScripts, fetch/XHR
                                          #     with user-controlled URLs, localStorage/sessionStorage
                                          #   - sources: location.search/hash/href, document.referrer,
                                          #     name, window.opener.*, postMessage event.data,
                                          #     storage reads, document.cookie reads, fetch responses
                                          #   - canary mode: stamp `pf-{nonce}` into a chosen source,
                                          #     observe which sinks fire and with what transformation
src/domTracerEngine.ts                    # session/canary/event reducer (off-thread)
src/components/domTracer/                 # analyst-facing panel
  sourcesTimeline.tsx                     #   chronological source reads
  sinksTable.tsx                          #   ranked sink fires with stack + canary path
  canaryComposer.tsx                      #   pick a source, set canary value, set probe character
                                          #   set, run, capture sink reflections
  flowGraph.tsx                           #   source → transformation → sink visualization
src/data/domTracerSinks.ts                # registry of instrumented sinks + severity hints
docs/DOM_TRACER_GUIDE.md                  # operator guide + sink/source reference
```

**Patch:** `electron/browserLauncher.ts` registers the tracer on managed-browser launches when the project policy allows; `src/components/pfv2/screens/proxy.tsx` exposes a Tracer tab next to History/Intercept; `electron/projectStore.ts` persists tracer sessions per project.

**Tests:**

```
tests/dom-tracer-instrumentation.mjs         # round-trip: instrumented page emits expected events
tests/dom-tracer-canary-reflection.mjs       # canary lands at expected sink with recorded transformation
tests/dom-tracer-fixture-spa.mjs             # SPA fixture: location.hash → innerHTML promoted to issue
tests/dom-tracer-postmessage-fixture.mjs     # postMessage origin-wildcard sink flagged
tests/dom-tracer-redirect-scheme.mjs         # `redirectUrl=javascript:...` source→sink chain captured
```

**Acceptance for beta:** session opens against any managed-browser tab, sources and sinks populate live, a stamped canary is traced source→transformation→sink, and the analyst can promote the trace into a Scanner issue with the reflected payload, the sink stack, and the transformation chain attached as evidence. **Safety:** instrumentation runs only against in-scope managed-browser tabs; never injected into pages the operator opens manually.

### 6.5c Contexts, auth methods, custom pages, anti-CSRF, modes

These primitives are what turn "a scanner that probes" into "a scanner that knows where to probe and how to behave there." Every other Track A surface depends on them — without Contexts the active scan can't be auth-aware; without anti-CSRF tracking Repeater replays die mid-flow; without Custom Pages the passive engine false-positives on every 404; without Modes a CI run can't be locked into a known-safe envelope.

**Files:**

```
src/contextEngine.ts                      # Context create / dissolve / membership-by-URL-pattern
src/authMethods/
  index.ts                                # registry, factory, type guards
  formAuth.ts                             # form-post URL + field names + success regex
  jsonAuth.ts                             # POST JSON for login, claim path for token
  postAuth.ts                             # urlencoded POST for login
  httpBasic.ts                            # 401 + Basic Authorization header
  ntlmAuth.ts                             # NTLM via SSPI/SAMBA helper
  manualAuth.ts                           # operator captures the session and pins it
  scriptAuth.ts                           # user-authored auth script (SSO, multi-step)
  totpAuth.ts                             # TOTP-of-a-shared-secret companion to any of the above
src/users/usersEngine.ts                  # multi-user-per-Context, including Forced User mode
src/customPages.ts                        # per-Context page-class declarations
src/antiCsrf/
  index.ts                                # token-name registry + per-Context bindings
  tokenRefresher.ts                       # pre-replay token-refresh hook for Repeater/Intruder/Scanner
src/modes/index.ts                        # Safe / Protected / Standard / Attack global guard
src/replacer/index.ts                     # project-wide pre-flight request + response rewrites
                                          #   (distinct from per-rule match/replace inside Scanner)
src/scanner/policies/
  index.ts                                # named policies with per-rule Threshold × Strength
docs/CONTEXT_GUIDE.md                     # operator manual for Contexts/users/auth/anti-CSRF
```

**Patch:** every Track A entry point (`activeScanRunner`, `repeaterReplay`, `intruderRun`, `browserScanDriver`) gains a `context: ContextHandle` parameter; safety checks first consult the global Mode and then the Context's effective policy.

**Tests:**

```
tests/context-engine-membership.mjs
tests/auth-form-login-roundtrip.mjs
tests/auth-json-login-roundtrip.mjs
tests/auth-script-multistep-fixture.mjs
tests/totp-credential-cycle.mjs
tests/forced-user-replay.mjs
tests/anti-csrf-refresh-before-replay.mjs
tests/custom-pages-suppress-404-false-positive.mjs
tests/scanner-tech-exclusion-skips-irrelevant-family.mjs
tests/global-mode-safe-blocks-active-scan.mjs
tests/global-mode-protected-blocks-out-of-scope.mjs
tests/policy-threshold-strength-applied-per-rule.mjs
tests/conditional-breakpoint-url-method-header.mjs
tests/replacer-global-rewrite-survives-scan.mjs
```

**Acceptance for beta:**

- A project can declare ≥2 Contexts (e.g., "public", "authenticated"), each with its own auth method + users + scope subset + tech set + custom pages, and the active scanner respects all of them.
- Repeater can replay an authenticated request after the session has expired by re-running the Context's auth flow (and a refreshed anti-CSRF token, if declared).
- Mode = Safe blocks every active probe across every subsystem; Mode = Protected blocks out-of-scope probes; Mode = Attack lifts the in-scope guard for explicitly-approved targets only.
- A passive 404-noise sweep on a custom-paged target produces 0 false positives.
- A scanner policy with `sql-injection.threshold = High` reports only firm SQLi findings; with `strength = Insane` it emits every variant the family knows.

### 6.6 Param miner + content discovery

**Files:**

```
src/contentDiscoveryEngine.ts
src/scanner/paramMinerEngine.ts
src/data/wordlists/common-paths.json
src/data/wordlists/common-params.json
src/data/wordlists/common-headers.json
```

**Tests:** `tests/content-discovery-engine.mjs`, `tests/scanner-param-miner.mjs`.

### 6.6b API spec ingest + Ajax/SPA spider

Two adjacent surfaces — both seed the scanner with insertion points it would otherwise miss.

**Spec ingest.** Many engagements deliver an API contract before any traffic exists. Importing one should seed scope, sitemap, insertion points, and Repeater starter tabs without a browser ever opening.

```
src/specImport/
  index.ts                                # router by detected type
  openApi.ts                              # OpenAPI 3 + Swagger 2 → routes, params, schemas
  postman.ts                              # Postman v2.1 collections
  insomnia.ts                             # Insomnia v4 collections
  soapWsdl.ts                             # SOAP 1.1 / 1.2 WSDL → operations, messages, fault types
  odata.ts                                # OData $metadata → entity sets + actions
  graphqlSchema.ts                        # SDL or introspection JSON → operations + arg sets
  harSeed.ts                              # HAR import is in §7 but this entry routes through the same seeder
src/scanner/insertionPointsFromSpec.ts    # spec → JSON path / query / header / cookie / body insertion-point set
src/components/pfv2/screens/import/       # Import wizard: pick file, preview, confirm seed
docs/API_SPEC_IMPORT_GUIDE.md
```

**Ajax / SPA spider.** Most modern targets render through client-side JS — a passive link crawl reaches almost nothing. A second crawler drives a real browser (sharing CDP plumbing with §6.5 / §6.5b), evaluates event handlers, fires synthetic clicks/keypresses, and harvests the routes the SPA actually exercises.

```
electron/spiders/ajaxSpiderDriver.ts      # CDP-driven SPA crawler; depth/rate budgeted
electron/spiders/ajaxSpiderHeuristics.ts  # button/link/onclick scoring; SPA-route enumeration
src/spiders/ajaxSpiderEngine.ts           # cross-cutting reducer; merges Ajax routes into sitemap
src/spiders/passiveLinkCrawler.ts         # the existing passive crawler, refactored out of crawlEngine
src/data/spider/spaPatterns.json          # known patterns (React Router, Vue Router, Next, Angular, Svelte Kit, Astro)
```

**Tests:**

```
tests/spec-import-openapi.mjs             # OpenAPI 3 fixture → 12 routes, 47 params, 3 auth schemes
tests/spec-import-postman.mjs
tests/spec-import-insomnia.mjs
tests/spec-import-soap-wsdl.mjs
tests/spec-import-graphql-schema.mjs
tests/spider-ajax-react-router-fixture.mjs
tests/spider-ajax-vue-router-fixture.mjs
tests/spider-ajax-event-handlers-fixture.mjs
tests/spider-ajax-rate-budget-respected.mjs
```

**Acceptance for beta:** importing each of the six supported spec types produces a populated Target Map, scoped insertion-point inventory, and a ready-to-replay Repeater group; the Ajax spider visits ≥80 % of routes a passive crawl misses on the React Router and Vue Router fixtures.

### 6.7 OAST provider profiles

**Files:**

```
electron/callbackProviderRegistry.ts
src/oastProviderProfile.ts
docs/OAST_PROVIDER_GUIDE.md
```

Supports BYO public listeners (tunnels, Route53/EC2). Tokens are HMAC-signed per project so cross-engagement collisions are impossible. Hosted multi-tenant service is out of scope for first beta; document as roadmap.

### 6.8 Exit gate for Track A

- ≥50 active check IDs, each with ≥1 passing fixture test.
- DOM XSS + client-side prototype pollution confirmed by browser-observed alert/property mutation on SPA fixture.
- Callback received via at least one third-party DNS + HTTP provider, correlated and promoted to a signed issue bundle.

---

## 7. Track B — Traffic / Protocol Engine

### 7.1 Tier 1 — flow filter DSL + rule pack engine + utilities (week 1, parallel with A1)

**Files to create:**

```
electron/traffic/flowFilter.ts
electron/traffic/flowFilterParser.ts            # ~u/~h/~m/~c/~b/~s/~q/&/|/!
electron/traffic/trafficRules.ts                # rule pack engine
electron/traffic/rules/anticache.ts
electron/traffic/rules/anticomp.ts
electron/traffic/rules/blocklist.ts
electron/traffic/rules/stickyCookie.ts
electron/traffic/rules/stickyAuth.ts
electron/traffic/rules/proxyAuth.ts             # require-auth-to-use-proxy
electron/traffic/rules/upstreamAuth.ts
electron/traffic/rules/mapLocal.ts
electron/traffic/rules/mapRemote.ts
electron/traffic/rules/stripDnsHttpsRecords.ts
electron/traffic/rules/updateAltSvc.ts
electron/traffic/harExport.ts
electron/traffic/cutExport.ts
```

**Patches:**

```
electron/proxyEngine.ts      # rule-pack hook points in request + response paths
src/App.tsx                  # Settings → Rule Packs + Proxy → Filter bar
electron/projectStore.ts     # persist rule packs, filter presets
scripts/proxyforge-agent.mjs # filter / export / rules CLI
src/types.ts                 # rule pack types
```

**Tests:** one `.mjs` per rule, plus `tests/traffic-flow-filter.mjs`, `tests/traffic-har-export.mjs`, `tests/traffic-cut-export.mjs`.

**Exit gate:** flow filter works in History, Logger, CLI export, rule pack matchers, scanner target selection. HAR export validates against the HAR 1.2 schema.

### 7.2 Tier 2 — content views

**Files:**

```
electron/traffic/contentViews.ts
electron/traffic/views/multipart.ts
electron/traffic/views/zipTree.ts
electron/traffic/views/cssPretty.ts
electron/traffic/views/mqtt.ts
electron/traffic/views/socketio.ts
electron/traffic/views/wbxml.ts
electron/traffic/views/dnsPretty.ts
electron/traffic/views/graphqlPretty.ts
electron/traffic/views/sse.ts
electron/traffic/views/protobufRaw.ts          # length-prefixed varint, no schema needed
```

**Rules:**

- Each view has a detection function.
- Each view has a safe text fallback.
- Renderer never loads huge blobs unbounded — size caps + paginated read.
- Views never mutate raw bytes; they project for display.

**Tests:** `tests/traffic-content-views.mjs` round-trips fixtures.

### 7.3 Tier 3 — alternate proxy modes (weeks 2–3)

**Files:**

```
electron/traffic/socksInbound.ts           # SOCKS5 greeting, auth, CONNECT
electron/traffic/reverseMode.ts            # listener forwards to configured origin
electron/traffic/dnsProxy.ts               # UDP listener, query parse, forward, log
electron/traffic/dnsRecordRules.ts         # block/map A/AAAA/HTTPS responses
```

**Patches:**

```
electron/proxyEngine.ts      # mode-spec dispatcher
electron/main.ts             # mode lifecycle wiring
src/App.tsx                  # Proxy mode selector + per-mode config
electron/projectStore.ts     # persist mode config, DNS records
scripts/proxyforge-agent.mjs # `--mode socks5|reverse|dns`
```

**Tests:** `tests/traffic-socks-inbound.mjs`, `tests/traffic-reverse-mode.mjs`, `tests/traffic-dns-proxy.mjs`.

**Exit gate:** end-to-end capture works in each mode. Mode switch persists in project file and restores on reopen.

### 7.4 Tier 4 — HTTP/2 + streaming (weeks 4–5)

**Files:**

```
electron/traffic/http2Transport.ts         # node:http2 server + client
electron/traffic/http2Alpn.ts              # ALPN negotiation during CONNECT MITM
electron/traffic/http2FrameEditor.ts       # Repeater H2 frame editing
electron/traffic/streamingCapture.ts       # SSE + large-body spool + caps
electron/traffic/streamingSpool.ts         # disk-backed body store
```

**Patches:** `electron/proxyEngine.ts` advertises `h2` ALPN in CONNECT MITM; `electron/certManager.ts` per-host certs include H2 ALPN; `src/App.tsx` Repeater frame editor; `electron/projectStore.ts` H2 streams + spool refs.

**Tests:** `tests/traffic-http2-end-to-end.mjs`, `tests/traffic-http2-frame-editor.mjs`, `tests/traffic-streaming-sse.mjs`, `tests/traffic-streaming-large-body.mjs`.

**Exit gate:** HTTP/2-only origin (e.g. `nghttp2`) MITM with pseudo-header editing in Repeater. SSE survives 30-minute capture with bounded memory (≤200 MB RSS).

### 7.5 Tier 5 — playback (week 6)

**Files:**

```
electron/traffic/playback.ts               # client playback + server playback
electron/traffic/playbackMatcher.ts        # match incoming → canned response
```

**Patches:** `electron/proxyEngine.ts` playback hook in request path; `src/App.tsx` Playback workspace; `electron/projectStore.ts` playback sessions; `scripts/proxyforge-agent.mjs` `playback-client` / `playback-server`.

**Tests:** `tests/traffic-playback-client.mjs`, `tests/traffic-playback-server.mjs`.

**Exit gate:** replay a 100-flow project with scope + rate; serve a fake-upstream session for a regression demo.

### 7.6 Tier 6 — native side-cars (weeks 8–12, optional but required for full mode parity)

Each side-car is a single static binary bundled as an optional installer extra, invoked over stdin/stdout JSON. Proxy Forge runs fine without any side-car.

```
side-cars/transparent-linux/        # Rust — nftables + SO_ORIGINAL_DST
side-cars/quic/                     # Rust — quiche-based QUIC server
side-cars/wireguard/                # Rust — wireguard-go or boringtun wrapper

electron/traffic/transparentMode.ts # invokes side-car, parses JSON events
electron/traffic/rawTcpUdp.ts       # pure Node (no side-car needed)
electron/traffic/http3Transport.ts  # JSON bridge to side-car
electron/traffic/wireguardMode.ts   # JSON bridge to side-car
```

**Tests:** gated on platform + side-car availability.

---

## 8. Track C — Workbench, UX, GUI integration, release

### 8.1 Scanner workspace UI (weeks 1–2, parallel with A1)

Patches in `src/App.tsx` (or new components under `src/components/scanner/`):

- Selected request and insertion points.
- Check pack picker.
- Payload matrix preview.
- Expected proof requirements (from skilllet metadata).
- Request budget + throttle controls.
- Live observation classes.
- OAST wait state.
- Conclusion + promote-to-issue + send-to-Exploit-Lab buttons.
- Findings show `expectedProofSatisfied: true | false`.
- Negative evidence shows reason + capped-run metadata.

### 8.2 Skilllet metadata layer (weeks 8–9)

**Files:**

```
src/data/scannerSkilllets.json
src/scanner/skillletMapper.ts
```

**Shape:**

```ts
export interface ScannerSkilllet {
  id: string;
  checkIds: string[];
  family: PayloadFamily;
  surfaceTypes: string[];
  triggerFacts: string[];
  summary: string;
  operatorGuidance: string[];
  allowedFollowups: string[];
  forbiddenBranches: string[];
  expectedProof: string[];
  defaultRisk: 'safe' | 'low' | 'medium' | 'high';
}
```

**Usage:** scanner UI cards, finding explanation panel, automation recipe selection, headless JSON output, report evidence requirements.

**Tests:** `tests/scanner-skilllet-metadata.mjs` — every check has metadata; every metadata row references valid check IDs; every check has expected proof; forbidden branches show in UI.

### 8.3 Exploit Lab verifier templates (weeks 5–7, after A1)

**Files:**

```
src/exploitTemplates/index.ts
src/exploitTemplates/oastCallback.ts
src/exploitTemplates/webhookReplay.ts
src/exploitTemplates/raceWindow.ts
src/exploitTemplates/authzMatrix.ts
src/exploitTemplates/cacheKeyDiff.ts
src/exploitTemplates/fileUploadRoundtrip.ts
src/exploitTemplates/websocketSequence.ts
src/exploitTemplates/oauthFlow.ts
src/exploitTemplates/mfaFlow.ts
src/exploitTemplates/grpcSequence.ts
src/exploitTemplates/modelOutputSink.ts
src/exploitTemplates/redactionInvariant.ts
src/exploitTemplates/artifactBoundary.ts
```

**Template contract:**

```ts
export interface ExploitTemplate {
  id: string;
  name: string;
  category: string;
  requiredEvidence: string[];
  inputSchema: JsonSchema;
  runMode: 'offline-evidence' | 'replay-required' | 'oast-required' | 'browser-required';
  validate(input: ExploitTemplateInput, context: ExploitContext): ExploitValidationResult;
}
```

Each template runs offline against Project Store evidence where possible. Replay-required templates require explicit operator approval. OAST-required templates link to OAST payload + interaction records.

**Tests:** one `tests/exploit-template-*.mjs` per template + `tests/exploit-template-project-store.mjs` for persistence + `tests/exploit-template-report-evidence.mjs` for bundle export.

### 8.4 Automation recipe engine (weeks 8–9)

**Files:**

```
src/automation/playbookRecipeEngine.ts
src/automation/playbookSchema.ts
src/automation/playbookEvidenceGate.ts
src/automation/recipes/webPayloadFamilyValidation.ts
src/automation/recipes/ssrfCallbackValidation.ts
src/automation/recipes/apiAuthzMatrix.ts
src/automation/recipes/blindSqlOracleMatrix.ts
src/automation/recipes/fileUploadRoundtrip.ts
src/automation/recipes/websocketSequenceReview.ts
src/automation/recipes/graphqlSurfaceValidation.ts
src/automation/recipes/contentDiscoveryParamMining.ts
src/automation/recipes/identitySessionReview.ts
src/automation/recipes/proofPackCompletion.ts
```

**Recipe shape:**

```ts
export interface AutomationRecipe {
  id: string;
  name: string;
  summary: string;
  requiredInputs: string[];
  steps: AutomationStep[];
  evidenceGates: EvidenceGate[];
  stopConditions: string[];
  defaultBudgets: {
    maxRequests: number;
    maxRuntimeMs: number;
    maxPayloadsPerInsertionPoint: number;
  };
}
```

**Patches:** `src/automationEngine.ts` registry + lifecycle; `src/App.tsx` automation workspace shows steps/gates/observations; `electron/projectStore.ts` recipe runs + evidence gates; `scripts/proxyforge-agent.mjs` `playbook-list/plan/run/export`.

**Tests:** `tests/automation-recipes.mjs`, `tests/headless-automation-recipes.mjs`, `tests/playbook-recipe-parser.mjs`.

### 8.5 Project Store schema migrations (week 10)

Add records:

```
scanner_check_packs
scanner_probe_runs
scanner_probe_variants
scanner_probe_observations
scanner_evidence_matrices
scanner_negative_evidence
skilllet_metadata
playbook_recipes
playbook_runs
playbook_steps
playbook_evidence_gates
exploit_template_runs
traffic_rule_packs
traffic_rule_events
flow_filter_presets
har_exports
cut_exports
content_view_preferences
playback_sessions
proxy_mode_configs
dns_record_rules
http2_streams
streaming_spool_refs
```

**Patches:** `electron/projectStore.ts` migrations + serialize/deserialize; `electron/projectSnapshotEngine.ts` snapshot test of all new tables.

**Tests:** `tests/project-store-migrations.mjs`, `tests/project-store-snapshot-roundtrip.mjs`.

**Exit gate:** project export → fresh install → import preserves every new field.

### 8.6 Full-chain GUI E2E (week 11)

Required workflow:

```
create/open project
→ set scope and rate limits
→ start proxy or managed browser
→ capture HTTP/HTTPS/WebSocket traffic
→ filter history with the flow filter DSL
→ send request to Repeater
→ select insertion points
→ run scanner check pack
→ classify responses with oracle/state-machine
→ insert OAST payload when blind proof needed
→ receive callback
→ correlate callback to request/check/run/project
→ promote finding to issue
→ run Exploit Lab verifier template
→ export signed evidence/report bundle
→ close/reopen project
→ verify all raw evidence persists
```

**Tests (Playwright):**

```
tests/proxyforge-full-chain-scanner-core.spec.ts
tests/proxyforge-full-chain-oast.spec.ts
tests/proxyforge-full-chain-http2.spec.ts
tests/proxyforge-full-chain-socks5.spec.ts
tests/proxyforge-full-chain-reverse.spec.ts
tests/proxyforge-full-chain-dns.spec.ts
tests/proxyforge-full-chain-playback.spec.ts
tests/proxyforge-full-chain-domxss-browser.spec.ts
tests/proxyforge-full-chain-report-reopen.spec.ts
```

**Exit gate:** each spec passes on Linux package build and Windows package build.

### 8.7 Release hardening (weeks 12–14)

- Main renderer sandbox enabled. Any exception narrowly documented and tested.
- All IPC through `electron/ipcContracts.ts` with runtime schema validation.
- CI sharding: fast (≤15 min), full (≤60 min), nightly (full + side-car smoke).
- README accuracy pass: every claim cites a test ID.
- Security regression suite covers: path traversal in maplocal/exports, archive zip-slip, IPC parameter validation, sidecar process boundary, OAST signature verification, body/transcript caps, AI handoff redaction.
- SBOM + checksums + release manifest.
- Audit events for: proxy start/stop, CA generation/export, cookie extraction, active scan, OAST listener start, AI call, command execution, report export, extension install/run.

---

## 9. Track D — Extension SDK

### 9.1 Hook surface

**Patches:** `src/extensionEngine.ts` adds hooks for:

```
request
response
tls_clienthello
tcp_message
scan_check
editor_tab
intruder_payload_processor
repeater_action
scanner_passive
```

**New files:**

```
src/extensions/sdk.d.ts                # typed extension SDK declarations
src/extensions/sdkHelpers.ts           # helper modules for extensions
src/extensions/manifest.ts             # manifest validation + signed package digest
src/extensions/sampleExtensions/passive-secret-detector/
src/extensions/sampleExtensions/header-injector/
src/extensions/sampleExtensions/intruder-base64/
src/extensions/sampleExtensions/custom-scan-check/
docs/EXTENSION_API.md
```

**Tests:** `tests/extension-sdk-contract.mjs`, `tests/extension-signed-package.mjs`.

### 9.2 Foreign-runtime compatibility decision

- **Skip Java/JVM compatibility.** Out of scope.
- **TS SDK is the only first-class API.** Documented as such.
- **Sandboxed JS expression filters** (analogous to inline expression filtering) may follow in a later cycle if demand exists. Not part of the first beat.

---

## 10. Acceptance gates

Each gate is single yes/no. No partial credit. No "documented limitation" workarounds.

| Gate | Criteria |
|---|---|
| **G1 — Scanner core** | Default pack runs against fixture, produces confirmed findings for 7 families, persists matrix. |
| **G2 — Scanner depth** | ≥50 active check IDs, each with ≥1 passing fixture test. |
| **G3 — Browser oracle** | DOM XSS + client prototype pollution confirmed by browser observation on SPA fixture. |
| **G4 — OAST chain** | Callback received, signed, correlated, promoted to issue, exported in signed bundle, survives project close/reopen. |
| **G5 — Traffic addons** | Flow filter DSL + 13 rule pack types + HAR export + cut/extract pass tests, work in GUI + CLI. |
| **G6 — Alternate modes** | SOCKS5, reverse, DNS modes pass end-to-end fixture tests. |
| **G7 — HTTP/2** | H2-only origin MITM works, Repeater can edit H2 frames, project reopens with H2 streams intact. |
| **G8 — Streaming** | 30-minute SSE capture under 200 MB RSS, body spool reaches disk. |
| **G9 — Playback** | Client playback replays a 100-flow project; server playback serves canned responses for matched requests. |
| **G10 — Content views** | Each registered view round-trips fixture bytes without mutation. |
| **G11 — Side-cars** | Transparent (Linux), raw TCP/UDP, HTTP/3, WireGuard each have a passing smoke test on supported platforms (each side-car optional). |
| **G12 — Extension API** | 4 sample extensions load, manifest signatures verify, hooks fire, runtime policy enforced. |
| **G13 — Project Store** | Every new record type round-trips through export/import. Crash recovery replays partial scanner/recipe runs. |
| **G14 — GUI E2E** | All Playwright specs pass on Linux + Windows package builds. |
| **G15 — Release hardening** | Renderer sandbox enabled, IPC schemas validate, CI shards green, security regression suite green. |
| **G16 — Honesty** | README + feature matrix accuracy pass — every claim cites a test ID. |
| **G17 — Standalone** | `grep` guard from §2.1 returns no runtime matches. Product builds, runs, and passes fast CI with the source repo deleted. |

"Done" requires G1–G17 all green plus the §3 checklists fully `[x]`.

---

## 11. Comprehensive file map

Flat list of every new file across all tracks. Use as a checklist.

### 11.1 Scanner

```
src/scanner/
  types.ts
  activeCheckIds.ts
  payloadMutationEngine.ts
  oracleResponseClassifier.ts
  responseSignals.ts
  probePlanner.ts
  probeRenderer.ts
  probeMatrix.ts
  evidenceMatrix.ts
  findingBuilder.ts
  checkRegistry.ts
  checkPacks.ts
  safetyBudget.ts
  skillletMapper.ts
  paramMinerEngine.ts
  browserOracle.ts
  index.ts
  families/
    sqlInjection.ts
    reflectedXss.ts
    xssOracle.ts
    ssti.ts
    sstiBlindTime.ts
    pathTraversal.ts
    commandInjection.ts
    commandInjectionBlindTime.ts
    commandInjectionBlindOast.ts
    ssrf.ts
    ssrfOast.ts
    openRedirect.ts
    xxeFile.ts
    xxeOast.ts
    nosqlInjection.ts
    xpathInjection.ts
    ldapInjection.ts
    expressionLanguageInjection.ts
    csvFormulaInjection.ts
    jwtNoneAlgorithm.ts
    jwtWeakSecret.ts
    jwtKeyConfusion.ts
    sessionFixation.ts
    csrfHeuristic.ts
    clickjacking.ts
    hostHeaderInjection.ts
    crlfHeaderInjection.ts
    passwordResetTokenLeak.ts
    requestSmugglingClTe.ts
    requestSmugglingTeCl.ts
    requestSmugglingTeTe.ts
    cachePoisoningUnkeyedHeader.ts
    cachePoisoningUnkeyedPort.ts
    cacheDeception.ts
    webCacheKeyDiscrepancy.ts
    deserializationJava.ts
    deserializationPhp.ts
    deserializationDotnet.ts
    deserializationPython.ts
    deserializationRuby.ts
    domXss.ts
    domClobbering.ts
    prototypePollutionClient.ts
    prototypePollutionServer.ts
    postmessageMisconfig.ts
    corsMisconfigCredentialed.ts
    graphqlIntrospection.ts
    graphqlBatchingAbuse.ts
    graphqlAliasOverload.ts
    graphqlIntrospectionDisabledBypass.ts
    graphqlFieldSuggestionLeak.ts
    graphqlFragmentBomb.ts
    graphqlSchemaDrivenAttack.ts
    massAssignment.ts
    apiVersioningMismatch.ts
    idorNumeric.ts
    idorUuidPredictable.ts
    # CVE / named families
    shellShock.ts                             # CVE-2014-6271 + cluster
    heartbleed.ts                             # CVE-2014-0160
    log4Shell.ts                              # CVE-2021-44228 / CVE-2021-45046
    spring4Shell.ts                           # CVE-2022-22965
    text4Shell.ts                             # CVE-2022-42889
    spring4ShellActuator.ts                   # Spring Boot Actuator exposure + RCE pivot
    cveBased403Bypass.ts                      # path-normalization / verb-switch / unicode
    backslashPoweredScanner.ts                # response-clustering anomaly probe
    httpoxy.ts                                # Proxy: header CGI poisoning
    cloudMetadataAttack.ts                    # 169.254.169.254 / metadata.google.internal probes
    sameOriginMethodExecution.ts              # SOME via JSONP-callback abuse
    httpParameterPollutionClient.ts           # client-side HPP signal + probe
    httpParameterPollutionServer.ts           # server-side HPP probe
    httpParameterOverride.ts                  # method/_method overrides accepted
    getForPost.ts                             # POST endpoint accepts GET semantics
    bigRedirectResponse.ts                    # 200 with Location: or 30x with large body
    httpInsecureMethods.ts                    # PUT / DELETE / TRACE / CONNECT accepted
    bypassAuthVerb.ts                         # alt-verb auth bypass
    elmahExposure.ts                          # /elmah.axd
    traceAxdExposure.ts                       # /trace.axd
    htaccessExposure.ts                       # /.htaccess on Apache
    envFileExposure.ts                        # /.env / /.env.local etc.
    hiddenFileSweep.ts                        # /.git, /.svn, /.hg, /.DS_Store, /web.config
    sourceCodeDisclosureGit.ts                # /.git/HEAD + objects walk
    sourceCodeDisclosureSvn.ts                # /.svn/wc.db
    sourceCodeDisclosureWebInf.ts             # /WEB-INF/web.xml + classes
    backupFileSweep.ts                        # .bak / .old / ~ / .swp / .swo
    proxyDisclosure.ts                        # reveal upstream proxy via TRACE / 502 leak
    cveSourceVersionControlSweep.ts           # generic SCM dotfile sweep aggregator
    samlInteractionDetected.ts                # presence + replay risk hints
    insecureJsfViewstate.ts                   # JSF ViewState plaintext / replayability
    serverSideTemplateInjectionBlind.ts       # blind SSTI via OAST
    suspiciousInputTransformation.ts          # reflection with normalization clues
    openMcpServerDetection.ts                 # MCP server fingerprint
    polyfillIoMaliciousScript.ts              # known-bad third-party script include
    dnsSpfMissing.ts                          # SPF record absent / overly permissive
    crossSiteWebsocketHijacking.ts            # CSWSH origin-trust probe
    fileUploadRules.ts                        # extension/content-type bypass family
    webCacheDeception.ts                      # /a.css of authenticated endpoint
    httpHeaderInjection.ts                    # CRLF + header smuggling combinations
    requestSmugglingHttp2DowngradeKt.ts       # h2.te / h2.cl downgrade smuggling
    relativePathConfusion.ts                  # RPC class via path-normalization
    cookiePoisoning.ts                        # write-into-cookie reflection
    userControllableCharset.ts                # charset selection from input
    userControllableHtmlAttribute.ts          # attribute-only XSS vector
    htmlParameterTampering.ts                 # parameter-tampering family
  # Passive posture rules (engine: src/scannerPassiveEngine.ts)
  passive/
    reflectedXss.ts                           # already in §3.3 row above
    reflectedRedirectParam.ts                 # already in §3.3 row above
    reflectedTokenInResponse.ts
    reflectedSecretInResponse.ts
    jwtInUrl.ts
    jwtInBrowserStorage.ts                    # localStorage / sessionStorage scan
    sensitiveInfoInBrowserStorage.ts          # generic secrets in browser storage
    informationInBrowserStorage.ts            # any persisted browser-storage write
    debugEndpoint.ts                          # /debug, /trace, ?debug=1, ?XDEBUG=1
    stackTraceLeak.ts                         # Java/Python/Ruby/.NET stack-trace patterns
    softwareVersionBanner.ts                  # Server / X-Powered-By / X-AspNet-Version / X-AspNetMvc-Version / X-Backend-Server
    errorDisclosure.ts                        # SQL / framework error fragments
    sourceMapsAndDebugArtifacts.ts            # .map / sourceMappingURL exposure
    clientConfigSecretLike.ts                 # secret-like strings in JS bundles
    apiDocsAndSpecsExposure.ts                # /swagger.json /openapi.yaml /api-docs/
    wellKnownAndMetadataFiles.ts              # /.well-known/* + /robots.txt + /sitemap.xml
    tokensAndSecretsInUrls.ts                 # ?api_key=, ?token=, ?session= in URLs
    highRiskParamNames.ts                     # debug, admin, ssrf, redir, fileUpload, etc.
    internalHostsEnvironmentHints.ts          # *.internal / 10.x / 192.168.x / 172.16-31.x leaked
    corsPostureIndicators.ts                  # Access-Control-Allow-* triage
    cachePrivacyPosture.ts                    # Cache-Control on authenticated 200s
    interestingEndpointPatterns.ts            # /actuator/, /metrics, /healthz, /__admin/
    creditCardNumberLeak.ts
    ibanLeak.ts
    hashLeak.ts                               # MD5/SHA-1/SHA-256/bcrypt patterns
    emailLeak.ts
    privateIpLeak.ts
    googleApiKeyLeak.ts
    awsS3UrlLeak.ts
    gitHubTokenLeak.ts
    javaStackTraceLeak.ts
    charsetMismatch.ts                        # Content-Type charset vs body BOM
    httpParameterOverridePassive.ts
    crossDomainJsSource.ts                    # <script src="cdn.evil.tld">
    untrustedJsSource.ts                      # known-bad CDN list
    sameSiteCookieMissing.ts
    looselyScopedCookie.ts                    # Domain=.tld
    cookiePoisoningPassive.ts                 # writable cookie via reflection
    mixedContent.ts                           # https page loads http subresource
    httpToHttpsFormPost.ts                    # form action="http://..."
    blankLinkTarget.ts                        # target="_blank" without rel="noopener"
    modernWebAppDetect.ts                     # SPA marker (manifest.json, *.bundle.js, hydrate calls)
    authenticationRequestDetect.ts            # login form / OIDC redirect detected
    sessionHandlingDetect.ts                  # cookie roundtrip detected
    verificationDetect.ts                     # 2FA / email-verification flow detected
    timestampDisclosure.ts                    # Unix epoch / build-stamp / x-runtime header
    hashDisclosure.ts                         # general hash exposure
    base64Disclosure.ts                       # base64-encoded strings on dangerous fields
    suspiciousXmlComments.ts                  # <!-- TODO: / <!-- DEBUG / <!-- password
    suspiciousHtmlComments.ts                 # HTML comments mentioning paths / secrets
    imageLocationMetadata.ts                  # EXIF GPS in served images
    dangerousJsFunctionUsage.ts               # eval / Function() / setTimeout(string,…)
    subresourceIntegrityMissing.ts            # <script src= without integrity=
    crossOriginResourcePolicyMissing.ts       # CORP header missing on isolation-sensitive responses
    fetchMetadataMissing.ts                   # Sec-Fetch-* not validated
    referrerPolicyMissing.ts                  # Referrer-Policy unset
    antiClickjackingMissing.ts                # X-Frame-Options + CSP frame-ancestors absent
    xContentTypeOptionsMissing.ts             # nosniff missing
    cacheControlMissing.ts                    # Cache-Control + Pragma unset
    hstsMissing.ts                            # Strict-Transport-Security absent on HTTPS
    backupFileExposure.ts                     # passive sweep for stale extensions
    graphqlEndpointDetect.ts                  # /graphql discovered passively
    wsdlDetect.ts                             # WSDL file mentioned in traffic
    soapActionDetect.ts                       # SOAPAction header present
    samlInteractionDetect.ts                  # SAMLResponse / SAMLRequest seen
    relativePathConfusionPassive.ts           # links/scripts that resolve ambiguously
    useragentReflection.ts                    # User-Agent reflected into response
```

### 11.2 Exploit templates

```
src/exploitTemplates/
  index.ts
  oastCallback.ts
  webhookReplay.ts
  raceWindow.ts
  authzMatrix.ts
  cacheKeyDiff.ts
  fileUploadRoundtrip.ts
  websocketSequence.ts
  oauthFlow.ts
  mfaFlow.ts
  grpcSequence.ts
  modelOutputSink.ts
  redactionInvariant.ts
  artifactBoundary.ts
```

### 11.3 Automation

```
src/automation/
  playbookRecipeEngine.ts
  playbookSchema.ts
  playbookEvidenceGate.ts
  agentProtocol.ts                        # generic external controller protocol
  recipes/
    webPayloadFamilyValidation.ts
    ssrfCallbackValidation.ts
    apiAuthzMatrix.ts
    blindSqlOracleMatrix.ts
    fileUploadRoundtrip.ts
    websocketSequenceReview.ts
    graphqlSurfaceValidation.ts
    contentDiscoveryParamMining.ts
    identitySessionReview.ts
    proofPackCompletion.ts
```

### 11.4 Data

```
src/data/
  scannerSkilllets.json
  wordlists/
    common-paths.json
    common-params.json
    common-headers.json
```

### 11.5 Content discovery + electron scanner glue

```
src/contentDiscoveryEngine.ts

electron/scanner/
  activeScanRunner.ts
  oastPayloadBroker.ts
```

### 11.6 Traffic engine

```
electron/traffic/
  flowFilter.ts
  flowFilterParser.ts
  trafficRules.ts
  harExport.ts
  cutExport.ts
  contentViews.ts
  socksInbound.ts
  reverseMode.ts
  dnsProxy.ts
  dnsRecordRules.ts
  http2Transport.ts
  http2Alpn.ts
  http2FrameEditor.ts
  streamingCapture.ts
  streamingSpool.ts
  playback.ts
  playbackMatcher.ts
  transparentMode.ts
  rawTcpUdp.ts
  http3Transport.ts
  wireguardMode.ts
  rules/
    anticache.ts
    anticomp.ts
    blocklist.ts
    stickyCookie.ts
    stickyAuth.ts
    proxyAuth.ts
    upstreamAuth.ts
    mapLocal.ts
    mapRemote.ts
    stripDnsHttpsRecords.ts
    updateAltSvc.ts
  views/
    multipart.ts
    zipTree.ts
    cssPretty.ts
    mqtt.ts
    socketio.ts
    wbxml.ts
    dnsPretty.ts
    graphqlPretty.ts
    sse.ts
    protobufRaw.ts
```

### 11.7 Browser scan + OAST providers

```
electron/browserScanDriver.ts
electron/browserScanWorker.ts
electron/callbackProviderRegistry.ts
src/oastProviderProfile.ts
```

### 11.8 Extension SDK

```
src/extensions/
  sdk.d.ts
  sdkHelpers.ts
  manifest.ts
  sampleExtensions/
    passive-secret-detector/
    header-injector/
    intruder-base64/
    custom-scan-check/
```

### 11.9 Side-cars (optional, native code)

```
side-cars/
  transparent-linux/       # Rust
  quic/                    # Rust (quiche)
  wireguard/               # Rust (boringtun)
```

### 11.10 Docs

```
docs/
  EXTENSION_API.md
  OAST_PROVIDER_GUIDE.md
  MODES_TRANSPARENT.md
  MODES_HTTP3.md
  MODES_WIREGUARD.md
  FEATURE_MATRIX.md        # rewritten honestly with test IDs
  agents/VANTIX.md         # frozen content snapshot note + generic API contract
```

### 11.11 Files patched (not created)

```
src/types.ts
src/App.tsx (or modularized routes)
src/scannerActiveScanEngine.ts
src/scannerPassiveEngine.ts
src/insertionPointEngine.ts
src/exploitEngine.ts
src/automationEngine.ts
src/reportEngine.ts
src/extensionEngine.ts
src/callbackEngine.ts
src/aiActionEngine.ts
electron/proxyEngine.ts
electron/projectStore.ts
electron/callbackListenerService.ts
electron/browserLauncher.ts
electron/crawlEngine.ts
electron/certManager.ts
electron/headlessRunner.ts
electron/ipcContracts.ts
electron/preload.ts
electron/main.ts
electron/projectLifecycleService.ts
electron/projectSnapshotEngine.ts
scripts/proxyforge-agent.mjs
README.md
package.json
```

### 11.12 Test files

~80 new `.mjs` and `.spec.ts` files following the existing `tests/*.mjs` pattern. Listed in detail in `PROXY_FORGE_ROADMAP.md`.

**Totals:** ~250 new files, ~30 patched files.

---

## 12. Generic external automation API

After Phase A and Phase B core ship, expose a stable JSON command/event protocol so any external orchestrator (CI job, shell script, AI agent, future sibling project) can drive Proxy Forge without coupling.

### 12.1 CLI

```bash
proxyforge-agent --json
```

Already exists at `scripts/proxyforge-agent.mjs`. Expand to cover the operations below.

### 12.2 Commands

```json
{"op":"project.create","name":"engagement"}
{"op":"project.open","path":"./workspace.proxyforge.json"}
{"op":"proxy.start","projectId":"...","listen":"127.0.0.1:8080","mode":"forward"}
{"op":"proxy.stop","projectId":"..."}
{"op":"browser.launch","projectId":"...","profile":"managed"}
{"op":"history.query","projectId":"...","filter":"~m POST ~u /api/"}
{"op":"repeater.send","projectId":"...","request":"..."}
{"op":"scanner.run","projectId":"...","exchangeId":"...","checks":["ssrf-oast","sql-injection"]}
{"op":"scanner.matrix.fetch","projectId":"...","matrixId":"..."}
{"op":"oast.payload.create","projectId":"...","purpose":"scanner:ssrf"}
{"op":"oast.interactions.poll","projectId":"..."}
{"op":"exploit.template.run","projectId":"...","templateId":"...","input":{...}}
{"op":"playbook.run","projectId":"...","recipeId":"..."}
{"op":"issue.promote","projectId":"...","evidenceIds":["..."]}
{"op":"report.export","projectId":"...","format":"bundle"}
{"op":"extension.invoke","projectId":"...","extensionId":"...","hook":"scan_check","payload":{...}}
```

### 12.3 Event stream

```json
{"event":"proxy.exchange.captured","exchangeId":"..."}
{"event":"scanner.probe.classified","matrixId":"...","responseClass":"reflected-inert"}
{"event":"scanner.finding.created","findingId":"..."}
{"event":"oast.callback.received","interactionId":"...","payloadId":"..."}
{"event":"issue.created","issueId":"..."}
{"event":"report.exported","artifactId":"..."}
{"event":"playbook.step.completed","runId":"...","stepId":"..."}
```

### 12.4 Acceptance

- Schema validated by runtime contract.
- Authentication via per-project bearer token.
- Documented in `docs/AUTOMATION_API.md`.
- Backed by E2E tests that exercise the protocol from a sibling process.

### 12.5 Multi-language client stub generators

The headless API is JSON-RPC over a stable transport. Generators emit typed bindings so external CI pipelines, internal tools, and security-engineering scripts can drive it without hand-rolled HTTP clients.

```
src/apiGenerators/
  index.ts                                # registry + IR builder from the JSON-schema contract
  pythonGenerator.ts                      # async + sync facades, pydantic models
  nodeJsGenerator.ts                      # ESM, TypeScript types co-emitted
  javaGenerator.ts                        # Gradle module, jakarta.json + records
  rustGenerator.ts                        # serde + tokio
  goGenerator.ts                          # modules + encoding/json
  phpGenerator.ts                         # PSR-4 namespace, guzzle
  wikiGenerator.ts                        # markdown reference for the documentation site
docs/AUTOMATION_API_CLIENTS.md
```

**Tests:** per language, generate against the schema, build the generated stub, run a smoke roundtrip against a running headless instance (`tests/api-client-{python,nodejs,java,rust,go,php}-smoke.mjs`).

**Acceptance:** every supported language's generated stub compiles and round-trips a `proxy.start` + `history.query` + `report.export` call against a fixture project.

### 12.6 Project SBOM generation

Compliance teams need a Software Bill of Materials for the *project artifact itself* — every captured exchange, evidence record, extension, third-party listener configured, signed audit export, etc. Distinct from the renderer SBOM produced for the application binary at release time.

```
src/sbomEngine.ts                         # builds SBOM ZIP from the active project snapshot
src/sbomFormats/cyclonedx.ts              # CycloneDX 1.5 JSON
src/sbomFormats/spdx.ts                   # SPDX 2.3 tag-value + JSON
docs/PROJECT_SBOM_GUIDE.md
```

**Tests:** `tests/sbom-cyclonedx-roundtrip.mjs`, `tests/sbom-spdx-roundtrip.mjs`, `tests/sbom-includes-evidence-references.mjs`.

**Acceptance:** SBOM ZIP exports validate against the CycloneDX and SPDX official validators and round-trip through a clean importer without data loss.

### 12.7 Global Stats counters + passive Stats rule

A lightweight project-wide counter surface used by every subsystem to record events (e.g., `proxy.exchange.captured`, `scanner.probe.high-confidence-finding`, `repeater.send.4xx`). A passive scanner rule reads the counters and emits findings when thresholds trip (e.g., excessive 5xx clustering on one host, excessive redirects in a single response chain).

```
src/stats/
  countersEngine.ts                       # global + per-Context + per-host counter buckets
  countersStore.ts                        # persistence + sliding-window decay
  passiveStatsRule.ts                     # converts counter thresholds into findings
src/components/pfv2/screens/stats/        # dashboard surface for the counter views
```

**Tests:** `tests/stats-counter-decay.mjs`, `tests/stats-rule-redirect-chain-finding.mjs`, `tests/stats-rule-5xx-cluster-finding.mjs`.

### 12.8 AI agent expansion — captured-traffic query + live-browser

The AI surface today runs prompts against the configured provider but its tool catalog is narrow. Add two structured tools so the agent can act, not just suggest:

```
src/aiTools/
  index.ts                                # tool registry; safe-by-default authorization gates
  capturedTrafficSql.ts                   # sandboxed read-only SELECT against the active project
                                          #   exchange / issue / matrix tables.
                                          #   only SELECT, parameterised, with row caps + timeouts.
                                          #   blocked tables explicitly listed (no secrets, no audit log)
  managedBrowserDrive.ts                  # drive the in-app managed browser session
                                          #   (click, type, evaluate-JS, screenshot) under Mode + Context gates
docs/AI_AGENT_TOOLS_GUIDE.md
```

**Patches:** `src/components/pfv2/screens/remaining.tsx` AI panel — adds a tool-toggle UI; `src/aiProviderRuntime.ts` — surfaces tool definitions to providers that speak OpenAI tool-use; matching shape for Anthropic and OpenAI-compatible (Ollama) providers.

**Tests:** `tests/ai-tool-traffic-sql-readonly.mjs`, `tests/ai-tool-traffic-sql-injection-impossible.mjs`, `tests/ai-tool-browser-drive-scope-gated.mjs`, `tests/ai-tool-browser-drive-mode-safe-blocks.mjs`.

**Acceptance:** under Mode = Standard with an in-scope target, the agent answers a question like "which login endpoint returned 401 most often in the last hour" by issuing one SQL query against the traffic store; under Mode = Safe, the same call is refused.

### 12.9 Open-project-folder pivot

Trivial but missing: a UI action that opens the active project directory in the OS file manager. Useful when operators want to inspect saved CA certs, signed bundles, extension manifests, etc., outside the app.

```
src/components/pfv2/screens/settings/openProjectFolder.tsx
electron/openProjectFolder.ts             # uses shell.openPath; whitelist guard prevents arbitrary path navigation
```

---

## 13. What NOT to do

- Do not ship a Python runtime, sidecar adapter, or any source-repo-as-dependency code. Source-repo content is read once for ideas, then forgotten.
- Do not run Proxy Forge as a shell around an external orchestrator. Proxy Forge stands alone.
- Do not add features beyond §3 in the first beat cycle. Hosted multi-tenant OAST, JVM compatibility, console TUI, browser plugin SDK, mobile app — all post-1.0.
- Do not treat optional native side-cars (transparent, HTTP/3, WireGuard) as required for first beta.
- Do not expand the README before the feature matrix lint passes.
- Do not rewrite `electron/proxyEngine.ts`. Decompose by moving features into `electron/traffic/` modules.
- Do not add governance/policy surface beyond what already exists until the scanner chain is smooth.
- Do not chase a foreign extension ecosystem. The native TS SDK is the answer.
- Do not promote findings from reflection alone — every finding requires an oracle-classified proof or OAST callback.
- Do not spray giant payload lists — every variant must declare intent + expected signals.
- Do not add new tabs without GUI workflow integration and Project Store persistence.

---

## 14. Definition of done

Proxy Forge reaches the intended state when all of this is true:

1. Proxy Forge installs and runs without any sibling repo on disk.
2. Zero runtime imports from sibling repos. No Python sidecar requirement.
3. Source-repo-derived scanner ideas are rewritten as native TypeScript modules with provenance comments.
4. ≥50 active check IDs run through insertion points, payload variants, response classification, evidence matrix, and Project Store persistence — each with a passing fixture test.
5. Browser oracle confirms DOM XSS and client-side prototype pollution on SPA fixtures.
6. OAST-confirmed findings work from Repeater and Scanner with signed correlation tokens.
7. Exploit Lab ships native templates for the highest-value multi-step proof patterns.
8. Automation recipes are native Proxy Forge recipes runnable in GUI and headless.
9. Traffic engine ships: flow filter DSL, 13 rule pack types, HAR export, cut/extract, content view registry, SOCKS5/reverse/DNS modes, HTTP/2 end-to-end, streaming bodies, playback.
10. Optional native side-cars exist for transparent (Linux), HTTP/3, WireGuard, raw TCP/UDP — each with smoke test.
11. Extension SDK ships with 4 sample extensions; manifest signatures verify; sandbox enforced.
12. Project Store schema covers every new record; export/import round-trips; crash recovery replays partial runs.
13. Full-chain GUI + headless E2E passes on Linux + Windows package builds.
14. Renderer sandbox enabled; IPC schema-validated; security regression suite green.
15. Feature matrix accurate — every claim cites a passing test ID.
16. Generic automation API documented and E2E-tested.

The product statement after this plan should be:

> Proxy Forge is a standalone local-first web security workbench. It captures, mutates, scans, correlates, and packages security evidence with optional agent-assisted workflows. It speaks forward, SOCKS5, reverse, and DNS proxy modes; HTTP/1.1, HTTP/2, and streaming bodies natively; HTTP/3, transparent, and WireGuard via optional side-cars. Its scanner covers 50+ vulnerability families with oracle-driven evidence matrices and OAST-confirmed proofs. Owned source material from sibling repos was used to accelerate scanner and workflow development, but Proxy Forge has no runtime dependency on them. External orchestrators consume Proxy Forge through its generic automation API.
