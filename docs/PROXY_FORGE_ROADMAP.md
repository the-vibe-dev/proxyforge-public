# Proxy Forge Roadmap

**Date:** 2026-05-26
**Companion:** `PROXY_FORGE_MASTER_PLAN.md` (architecture, file map, acceptance gates).

This document is the **time-ordered execution view** of the master plan: phases, weekly cadence, PR sequence, backlog by priority, and per-phase deliverables. It does not redefine architecture — for that, read the master plan.

---

## Status tracking

*Updated 2026-06-20. Roadmap phases 0–19 are complete as an in-repo alpha source cut. Native Linux/Windows artifact receipts remain a release-execution requirement for public installer distribution.*

| Phase | Status | Started | Done | Gate | Notes |
|---|---|---|---|---|---|
| 0 | ✓ Done | 2026-05-26 | 2026-05-27 | — | Guardrails landed; `no-vantix-runtime-dependency` + `release-package-excludes-source-reference` pass |
| 1 | ✓ Done | 2026-05-26 | 2026-05-27 | G1 | Scanner primitives: payload engine, oracle classifier, probe matrix, 7 families + check packs |
| 2 | ✓ Done | 2026-05-26 | 2026-05-27 | G5 | Traffic Tier 1: flow filter DSL, 9 rule types, HAR export, cut/extract |
| 3 | ✓ Done | 2026-05-26 | 2026-05-27 | — | Scanner UI workspace backend wired; scanner-active-scan-engine test passes |
| 3b | ✓ Done | 2026-05-26 | 2026-05-27 | G3c | Contexts, auth methods (8 types), users/Forced User, custom pages, anti-CSRF, Modes, Replacer, policies, conditional breakpoints |
| 4 | ✓ Done | 2026-05-26 | 2026-05-27 | G2 | Scanner depth: 4a–4i sub-phases; ≥90 active + ≥70 passive check IDs; CVE/named families; passive posture rules |
| 5 | ✓ Done | 2026-05-26 | 2026-05-27 | G6 | Alternate proxy modes: SOCKS5, reverse listener, DNS proxy |
| 6 | ✓ Done | 2026-05-26 | 2026-05-27 | — | Exploit Lab: all 14 verifier templates + 3 shared helpers; grpcSequence + multiStepChain added in this session |
| 7 | ✓ Done | 2026-05-26 | 2026-05-27 | G7+G8 | HTTP/2 transport + ALPN + frame editor; streaming spool + SSE capture |
| 8 | ✓ Done | 2026-05-26 | 2026-05-27 | G9 | Playback: client bulk-replay + server fake-upstream + matcher |
| 9 | ✓ Done | 2026-05-26 | 2026-05-27 | G10 | Content views: 10 registered views (multipart, zip, CSS, MQTT, SocketIO, WBXML, DNS, GraphQL, SSE, protobuf) |
| 10 | ✓ Done | 2026-05-26 | 2026-05-27 | G3 | Browser scan oracle: CDP/Playwright driver, DOM XSS, prototype pollution |
| 10b | ✓ Done | 2026-05-26 | 2026-05-27 | G3b | Interactive DOM tracer: instrumentation, canary, sources/sinks panel, promote-to-issue |
| 11 | ✓ Done | 2026-05-26 | 2026-05-27 | — | Param miner + content discovery + bundled wordlists |
| 11b | ✓ Done | 2026-05-26 | 2026-05-27 | G16b | Spec import (OpenAPI/Postman/Insomnia/SOAP/OData/GraphQL/HAR) + Ajax/SPA spider |
| 12 | ✓ Done | 2026-05-26 | 2026-05-27 | G4 | OAST provider profiles: callback registry, HMAC-signed tokens, provider guide |
| 13 | ✓ Done | 2026-05-26 | 2026-05-27 | — | Skilllet metadata, skilllet mapper, recipe engine + evidence gates + 10 recipes |
| 14 | ✓ Done | 2026-05-26 | 2026-05-27 | G12 | Extension SDK: typed declarations, helpers, manifest signing, 4 sample extensions |
| 15 | ✓ Done | 2026-05-26 | 2026-05-27 | G13 | Project Store schema migrations: all new record types; crash recovery; snapshot roundtrip |
| 16 | ✓ Done | 2026-05-26 | 2026-05-27 | G14 | Full-chain GUI + headless E2E; Playwright specs + headless runner |
| 17 | ✓ Done | 2026-05-26 | 2026-05-27 | G11 | Optional side-cars: transparent (Linux), raw TCP/UDP, HTTP/3, WireGuard — smoke tests pass |
| 18 | ✓ Done | 2026-05-26 | 2026-05-27 | G15+G16+G17 | Release hardening: renderer sandbox, IPC contracts, audit events, body caps, security regression suite, portable CI |
| 18b | ✓ Done | 2026-05-26 | 2026-05-27 | G15b | Headless API expansion: 6-language client generators, project SBOM (CycloneDX+SPDX), Stats counters, AI tools, open-project-folder |
| 19 | ✓ Done | 2026-06-20 | 2026-06-20 | G6 | Alpha source cut, release notes, hotfix process, tag target, and native artifact receipt workflow complete |

---

## 1. Phase summary

```
Phase 0  Reset boundaries + standalone guardrails           1–2 days
Phase 1  Scanner primitives (payload/oracle/matrix)         Week 1–2
Phase 2  Traffic Tier 1 (filter DSL + rule packs + HAR/cut) Week 1     (parallel)
Phase 3  Scanner UI workspace                               Week 1–2   (parallel)
Phase 4  Scanner depth expansion (≥50 check IDs)            Week 3–8
Phase 5  Alternate proxy modes (SOCKS5/reverse/DNS)         Week 2–3
Phase 6  Exploit Lab verifier templates                     Week 5–7
Phase 7  HTTP/2 + streaming                                 Week 4–5
Phase 8  Playback (client + server)                         Week 6
Phase 9  Content views                                      Week 7
Phase 10 Browser scan oracle (DOM XSS, proto pollution)     Week 9–10
Phase 11 Param miner + content discovery                    Week 11
Phase 12 OAST provider profiles                             Week 12
Phase 13 Skilllet metadata + automation recipes             Week 8–9
Phase 14 Extension SDK + sample extensions                  Week 6–10  (parallel)
Phase 15 Project Store schema migrations                    Week 10
Phase 16 Full-chain GUI + headless E2E                      Week 11
Phase 17 Optional native side-cars                          Week 8–12  (parallel)
Phase 18 Release hardening + honest README                  Week 13–14
Phase 19 Alpha cut                                           Week 15–16 (buffer)
```

Single-engineer realistic pace: **4 months to alpha cut + 1 month buffer**.
Two engineers split (Track A / Track B): **2.5 months**.
Three engineers (A / B / C split): **2 months**.

---

## 2. Phase 0 — Reset boundaries + standalone guardrails

### Goals

Lock in the architectural non-negotiables before any feature work so the rules can't drift.

### Tasks

| # | Item | Files | Acceptance |
|---|---|---|---|
| 0.1 | Vendor source-reference files | `source-reference/vantix/` | 383 files, ~3.0 MB, README + mapping table present (curated subset — playbooks/skills/templates/scanner-engine/verifiers only). **DONE.** |
| 0.2 | Gitignore the vendored dir | `.gitignore` | `source-reference/` listed. **DONE.** |
| 0.3 | Add no-runtime-dependency guard test | `tests/no-vantix-runtime-dependency.mjs` | Fails CI if `grep -R "source-reference/vantix"` finds runtime matches. |
| 0.4 | Add vendored-dir build exclusion verification | `tests/release-package-excludes-source-reference.mjs` | Confirms `package.json#build.files` does not ship the dir. |
| 0.5 | Feature matrix rewrite to honest states | `docs/FEATURE_MATRIX.md` | Every claim labelled `Backend`, `GUI-integrated`, `E2E-tested`, `Alpha`, or `Production` with a test ID. |
| 0.6 | README accuracy pass | `README.md` | Marketing prose ahead of code removed; claims cite test IDs. |
| 0.7 | Master plan + roadmap landed | `planning/PROXY_FORGE_MASTER_PLAN.md`, `planning/PROXY_FORGE_ROADMAP.md` | Both present and referenced from README. **DONE.** |

### Exit gate

- Zero runtime imports of vendored source.
- Build artifacts do not contain `source-reference/`.
- README and feature matrix have no claims that fail their cited test.

---

## 3. Phase 1 — Scanner primitives (Week 1–2)

### Goals

Replace one-shot mutation + ad-hoc heuristics with a real evidence-driven scanner core.

### Tasks

| # | Item | Files (new) | Files (patch) |
|---|---|---|---|
| 1.1 | Scanner type system | `src/scanner/types.ts`, `src/scanner/activeCheckIds.ts` | `src/types.ts`, `electron/proxyEngine.ts`, `src/scannerActiveScanEngine.ts` |
| 1.2 | Payload mutation engine | `src/scanner/payloadMutationEngine.ts` | — |
| 1.3 | Oracle response classifier | `src/scanner/oracleResponseClassifier.ts`, `src/scanner/responseSignals.ts` | — |
| 1.4 | Probe matrix runner | `src/scanner/probePlanner.ts`, `src/scanner/probeRenderer.ts`, `src/scanner/probeMatrix.ts`, `src/scanner/evidenceMatrix.ts`, `src/scanner/findingBuilder.ts`, `src/scanner/safetyBudget.ts` | — |
| 1.5 | Scanner runner glue | `electron/scanner/activeScanRunner.ts`, `electron/scanner/oastPayloadBroker.ts` | `electron/proxyEngine.ts` |
| 1.6 | Check pack registry + `vantix-core` default pack | `src/scanner/checkRegistry.ts`, `src/scanner/checkPacks.ts` | — |
| 1.7 | First 7 families (port from vendored source) | `src/scanner/families/{sqlInjection,reflectedXss,xssOracle,ssti,pathTraversal,commandInjection,ssrf,openRedirect}.ts` | — |
| 1.7a | Per-family payload variant tables (≥6 variants each, context × encoding × scheme tricks) | `src/scanner/families/payloads/{sqlInjection,reflectedXss,ssti,pathTraversal,commandInjection,ssrf,openRedirect}Payloads.ts` | — |
| 1.7b | Insertion-point iterator (walk real params on the exchange, not synthetic `pf_*` keys); retire single-payload `proxyEngine.ts` probes | `src/scanner/insertionPointIterator.ts` | `electron/proxyEngine.ts` (delete `setProbeQueryParam` single-key shortcut) |
| 1.8 | Project Store persistence | — | `electron/projectStore.ts` |
| 1.9 | Headless CLI command | — | `scripts/proxyforge-agent.mjs` (`scanner-run --check-pack vantix-core`) |

### Tests

```
tests/scanner-payload-mutation-engine.mjs
tests/scanner-oracle-response-classifier.mjs
tests/scanner-probe-renderer.mjs
tests/scanner-evidence-matrix.mjs
tests/scanner-vantix-core-fixture.mjs
tests/project-store-scan-probe-matrix.mjs
tests/scanner-payload-variants-per-family.mjs       # ≥6 variants/family asserted; no single-payload families allowed
tests/scanner-insertion-point-iterator.mjs          # walks real query/body/header/cookie/JSON params, ignores synthetic
tests/scanner-open-redirect-scheme-matrix.mjs       # javascript:/data:/protocol-relative/backslash/mixed-case all probed + flagged
```

### Exit gate (G1)

- `vantix-core` pack runs against a fixture app, persists matrix.
- Confirmed findings for sqli/xss/ssti/path-traversal/command-injection/ssrf/open-redirect.
- Negative evidence persists for non-matches.
- Restart preserves scan state.
- **Each family ships ≥6 payload variants** spanning context (HTML body / attribute / JS string / CSS / URL), encoding (raw / url / double-url / html-entity / unicode), and scheme/path tricks (for `open-redirect`: `javascript:`, `data:`, protocol-relative `//evil`, backslash `\\evil`, mixed-case `JaVaScRiPt:`, whitespace-prefixed `%09javascript:`, absolute cross-origin). No family is allowed to ship with a single hard-coded payload.
- **Active probes iterate insertion points** — every observed query parameter, body field, JSON path, header, cookie. Probes must not inject into a synthetic param (`pf_xss=…`, `pf_id=…`, `next=…`) when a real one exists on the exchange. The legacy single-param probe path in `electron/proxyEngine.ts:5826–5849` is deleted in this phase.
- **`open-redirect` family** alone proves the policy: walks all redirect-aliased params (`next`, `redirect`, `redirectUrl`, `redirect_uri`, `redirect_url`, `redirectTo`, `return`, `returnUrl`, `returnTo`, `continue`, `url`, `dest`, `destination`, `forward`, `forwardUrl`, `callback`, `callbackUrl`, `goto`, `target`, `targetUrl`, `redir`), tries all 7 scheme/path payload classes above, and asserts both `Location:` reflection and HTML-body `href="javascript:"` reflection.

---

## 4. Phase 2 — Traffic Tier 1 (Week 1, parallel with Phase 1)

### Goals

Make the proxy feel useful for everyday operator work: filter expressions, rule packs, exports.

### Tasks

| # | Item | Files (new) |
|---|---|---|
| 2.1 | Flow filter DSL parser + evaluator | `electron/traffic/flowFilterParser.ts`, `electron/traffic/flowFilter.ts` |
| 2.2 | Rule pack engine | `electron/traffic/trafficRules.ts` |
| 2.3 | Anticache + anticomp rules | `electron/traffic/rules/anticache.ts`, `anticomp.ts` |
| 2.4 | Blocklist + sticky cookie + sticky auth | `electron/traffic/rules/{blocklist,stickyCookie,stickyAuth}.ts` |
| 2.5 | Proxy auth + upstream auth | `electron/traffic/rules/{proxyAuth,upstreamAuth}.ts` |
| 2.6 | Map local + map remote | `electron/traffic/rules/{mapLocal,mapRemote}.ts` |
| 2.7 | Strip DNS HTTPS + update Alt-Svc | `electron/traffic/rules/{stripDnsHttpsRecords,updateAltSvc}.ts` |
| 2.8 | HAR export | `electron/traffic/harExport.ts` |
| 2.9 | Cut / field extraction | `electron/traffic/cutExport.ts` |

### Patches

`electron/proxyEngine.ts` (rule hook points), `src/App.tsx` (Settings → Rule Packs, History filter bar), `electron/projectStore.ts` (rule packs + filter presets), `scripts/proxyforge-agent.mjs` (filter/export/rules), `src/types.ts`.

### Tests

```
tests/traffic-flow-filter.mjs
tests/traffic-rules-anticache.mjs
tests/traffic-rules-blocklist.mjs
tests/traffic-rules-sticky.mjs
tests/traffic-rules-maplocal.mjs
tests/traffic-rules-proxyauth.mjs
tests/traffic-rules-upstream-auth.mjs
tests/traffic-har-export.mjs
tests/traffic-cut-export.mjs
```

### Exit gate (G5)

- Flow filter works in History, Logger, CLI export, rule pack matchers, scanner target selection.
- HAR export validates against HAR 1.2 schema.
- Every rule action annotates the affected exchange with rule ID + before/after.

---

## 5. Phase 3 — Scanner UI workspace (Week 1–2, parallel)

### Goals

Make the new scanner primitives visible to operators immediately. Backend without UI does not count.

### Tasks

- Scanner workspace shows: selected request, insertion points, check pack picker, payload matrix preview, expected proof requirements, request budget, throttle, live observation classes, OAST wait state, conclusion, promote-to-issue, send-to-Exploit-Lab.
- Findings include `expectedProofSatisfied: true | false`.
- Negative evidence shows reason + capped-run metadata.

### Patches

`src/App.tsx` (or extracted `src/components/scanner/*.tsx`).

### Exit gate

The scanner chain operates fully through the desktop GUI for the 7 Phase 1 families.

---

## 5b. Phase 3b — Contexts, Auth, Modes, Anti-CSRF, Custom Pages (Week 2–3, blocks 4b+ and 10b)

Every downstream surface that targets authenticated flows depends on these primitives. Land before Phase 4b (auth/session families) — without Contexts and the auth-method registry, 4b cannot reach the post-login surface deterministically.

### Tasks

| # | Item | Files (new) |
|---|---|---|
| 3b.1 | Context engine + membership-by-pattern | `src/contextEngine.ts` |
| 3b.2 | Authentication method registry + 8 built-in types | `src/authMethods/{index,formAuth,jsonAuth,postAuth,httpBasic,ntlmAuth,manualAuth,scriptAuth,totpAuth}.ts` |
| 3b.3 | Multi-user per Context + Forced User mode | `src/users/usersEngine.ts` |
| 3b.4 | Custom Pages declarations per Context | `src/customPages.ts` |
| 3b.5 | Anti-CSRF token registry + pre-replay refresher | `src/antiCsrf/{index,tokenRefresher}.ts` |
| 3b.6 | Global Mode guard (Safe / Protected / Standard / Attack) | `src/modes/index.ts` |
| 3b.7 | Global Replacer rules (pre-flight rewrite) | `src/replacer/index.ts` |
| 3b.8 | Scanner policy registry (Threshold × Strength per rule) | `src/scanner/policies/index.ts` |
| 3b.9 | Conditional breakpoints (URL / method / header / body match) | `electron/proxyEngine.ts` patch + `src/intercept/conditionalBreakpoints.ts` |
| 3b.10 | Operator guide | `docs/CONTEXT_GUIDE.md` |

### Patches

`electron/scanner/activeScanRunner.ts`, `electron/repeaterReplay.ts`, `electron/intruderRunner.ts`, `electron/browserScanDriver.ts`, `electron/proxyEngine.ts` (intercept + scope checks consult Mode + Context).

### Tests

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

### Exit gate (G3c)

Two-Context project (public + authenticated) drives auth-aware scans cleanly. Repeater re-auths a stale session by replaying the Context's auth flow + a refreshed anti-CSRF token. Mode = Safe blocks every active probe across every subsystem; Mode = Protected blocks out-of-scope probes. A passive sweep with Custom Pages declared produces 0 false-positive 404 findings on the fixture.

---

## 6. Phase 4 — Scanner depth expansion (Week 3–8)

### Goals

Reach ≥90 active check IDs and ≥70 passive check IDs, organised into named packs that cover modern web injection, auth/session, cache + smuggling, deserialization + blind RCE, client-side, GraphQL + API, CVE / named families, and the full passive posture surface.

### Sub-phases

| Week | Sub-phase | Check families added |
|---|---|---|
| 3 | 4a — modern web injection | xxe-file, xxe-oast, nosql-injection, xpath-injection, ldap-injection, expression-language-injection, csv-formula-injection |
| 4 | 4b — auth/session | jwt-none-algorithm, jwt-weak-secret, jwt-key-confusion, session-fixation, csrf-heuristic, clickjacking, host-header-injection, crlf-header-injection, password-reset-token-leak |
| 5 | 4c — cache + smuggling | request-smuggling-cl-te, request-smuggling-te-cl, request-smuggling-te-te, cache-poisoning-unkeyed-header, cache-poisoning-unkeyed-port, cache-deception, web-cache-key-discrepancy |
| 6 | 4d — deserialization + blind RCE | deserialization-{java,php,dotnet,python,ruby}, ssti-blind-time, command-injection-blind-time, command-injection-blind-oast |
| 7 | 4e — client-side (needs Phase 10 browser oracle) | dom-xss, dom-clobbering, prototype-pollution-{client,server}, postmessage-misconfig, cors-misconfig-credentialed |
| 8 | 4f — GraphQL + API | graphql-{introspection,batching-abuse,alias-overload,introspection-disabled-bypass,field-suggestion-leak}, mass-assignment, api-versioning-mismatch, idor-{numeric,uuid-predictable} |
| 8 | 4g — passive engine expansion (runs alongside 4f) | passive-reflected-xss, passive-reflected-redirect-param, passive-suspicious-redirect-scheme, passive-reflected-token, passive-jwt-in-url, passive-secret-in-response, passive-debug-endpoint, passive-stack-trace-leak, passive-software-version-banner, passive-error-disclosure, passive-cors-permissive-origin, passive-set-cookie-flags, passive-csp-missing-or-weak, passive-hsts-missing, passive-referrer-leak, passive-clickjacking-headers-missing |
| 8 | 4h — CVE / named families (runs alongside 4f-4g) | shell-shock, heartbleed, log4-shell, spring4-shell, text4-shell, spring-actuator-rce-pivot, httpoxy, cloud-metadata-attack, same-origin-method-execution, http-parameter-pollution-client, http-parameter-pollution-server, http-parameter-override, get-for-post, big-redirect-response, http-insecure-methods, bypass-auth-verb, elmah-exposure, traceaxd-exposure, htaccess-exposure, env-file-exposure, hidden-file-sweep, source-code-disclosure-git, source-code-disclosure-svn, source-code-disclosure-webinf, backup-file-sweep, proxy-disclosure, saml-interaction-detected, insecure-jsf-viewstate, ssti-blind-oast, suspicious-input-transformation, open-mcp-server-detection, polyfillio-malicious-script, dns-spf-missing, cross-site-websocket-hijacking, file-upload-rules, web-cache-deception, http-header-injection, request-smuggling-h2-downgrade, relative-path-confusion, cookie-poisoning, user-controllable-charset, user-controllable-html-attribute, html-parameter-tampering, react4-shell, cve-403-bypass |
| 8 | 4i — passive posture / signal rules (runs alongside 4g) | reflected-token-in-response, reflected-secret-in-response, jwt-in-url, jwt-in-browser-storage, sensitive-info-in-browser-storage, information-in-browser-storage, debug-endpoint, stack-trace-leak, software-version-banner, error-disclosure, source-maps-and-debug-artifacts, client-config-secret-like, api-docs-and-specs-exposure, well-known-and-metadata-files, tokens-and-secrets-in-urls, high-risk-param-names, internal-hosts-environment-hints, cors-posture-indicators, cache-privacy-posture, interesting-endpoint-patterns, credit-card-number-leak, iban-leak, hash-leak, email-leak, private-ip-leak, google-api-key-leak, aws-s3-url-leak, github-token-leak, java-stack-trace-leak, charset-mismatch, http-parameter-override-passive, cross-domain-js-source, untrusted-js-source, samesite-cookie-missing, loosely-scoped-cookie, cookie-poisoning-passive, mixed-content, http-to-https-form-post, blank-link-target, modern-web-app-detect, authentication-request-detect, session-handling-detect, verification-detect, timestamp-disclosure, hash-disclosure, base64-disclosure, suspicious-xml-comments, suspicious-html-comments, image-location-metadata, dangerous-js-function-usage, subresource-integrity-missing, cross-origin-resource-policy-missing, fetch-metadata-missing, referrer-policy-missing, anti-clickjacking-missing, x-content-type-options-missing, cache-control-missing, hsts-missing, backup-file-exposure, graphql-endpoint-detect, wsdl-detect, soap-action-detect, saml-interaction-detect, relative-path-confusion-passive, useragent-reflection |

Each family file (template):

```
src/scanner/families/<family>.ts        # variants + classify + confirm
tests/scanner-family-<family>.mjs       # fixture test
src/data/scannerSkilllets.json          # metadata entry added
```

Passive engine extension lives in `src/scannerPassiveEngine.ts` (existing) with one fixture per new `ScannerPassiveCheckId`:

```
tests/scanner-passive-reflected-xss.mjs
tests/scanner-passive-redirect-scheme.mjs
tests/scanner-passive-reflected-token.mjs
tests/scanner-passive-debug-endpoint.mjs
tests/scanner-passive-error-disclosure.mjs
```

### Exit gate (G2)

- ≥90 `ActiveScanCheckId` values registered (50 core + 44 CVE/named/aux from 4h).
- Every active ID has ≥1 passing fixture test.
- Every active ID has a `scannerSkilllets.json` entry with proof requirements.
- Passive engine grows from 8 → ≥70 `ScannerPassiveCheckId` values (8 baseline + 16 from 4g + 64 from 4i), each with a fixture test.
- Passive `reflected-redirect-param` flags `?redirectUrl=javascript:`, `?next=//evil`, `?return=\\evil`, `?callback=data:` patterns without sending a probe.
- Passive `software-version-banner`, `stack-trace-leak`, `error-disclosure`, `debug-endpoint`, `interesting-endpoint-patterns`, and `tokens-and-secrets-in-urls` each fire on their respective fixtures.

---

## 7. Phase 5 — Alternate proxy modes (Week 2–3)

### Tasks

| # | Item | Files (new) |
|---|---|---|
| 5.1 | SOCKS5 inbound mode | `electron/traffic/socksInbound.ts` |
| 5.2 | Reverse listener mode | `electron/traffic/reverseMode.ts` |
| 5.3 | DNS proxy mode | `electron/traffic/dnsProxy.ts`, `electron/traffic/dnsRecordRules.ts` |

### Patches

`electron/proxyEngine.ts` (mode dispatcher), `electron/main.ts` (lifecycle), `src/App.tsx` (mode selector + per-mode config), `electron/projectStore.ts` (mode + DNS records), `scripts/proxyforge-agent.mjs` (`--mode socks5|reverse|dns`).

### Tests

```
tests/traffic-socks-inbound.mjs
tests/traffic-reverse-mode.mjs
tests/traffic-dns-proxy.mjs
```

### Exit gate (G6)

Each mode passes end-to-end fixture tests. Mode persists in project file and restores on reopen.

---

## 8. Phase 6 — Exploit Lab verifier templates (Week 5–7)

### Tasks

Port the 14 vendored verifiers as native TS templates, prioritised:

| Week | Templates |
|---|---|
| 5 | oastCallback, webhookReplay, raceWindow, authzMatrix |
| 6 | cacheKeyDiff, fileUploadRoundtrip, websocketSequence, oauthFlow |
| 7 | mfaFlow, grpcSequence, modelOutputSink, redactionInvariant, artifactBoundary, multiStepChain |

Files: one TS file per template under `src/exploitTemplates/` plus shared helpers (`verifierBase.ts`, `stateDiff.ts`, `sideEffectGuard.ts`, `browserVerifier.ts`).

### Patches

`src/exploitEngine.ts` (registry), `src/App.tsx` (template picker, run UI), `electron/projectStore.ts` (template runs), `scripts/proxyforge-agent.mjs` (`exploit-run --template <id>`).

### Tests

One `tests/exploit-template-<id>.mjs` per template plus `tests/exploit-template-project-store.mjs` and `tests/exploit-template-report-evidence.mjs`.

### Exit gate

- Each template runs offline against Project Store evidence where possible.
- Replay-required templates require explicit operator approval.
- OAST-required templates link to OAST payload + interaction records.
- Templates can promote findings to issues; report bundles include template metadata.

---

## 9. Phase 7 — HTTP/2 + streaming (Week 4–5)

### Tasks

| # | Item | Files (new) |
|---|---|---|
| 7.1 | HTTP/2 transport | `electron/traffic/http2Transport.ts` |
| 7.2 | ALPN MITM negotiation | `electron/traffic/http2Alpn.ts` |
| 7.3 | Repeater frame editor | `electron/traffic/http2FrameEditor.ts` |
| 7.4 | Streaming capture | `electron/traffic/streamingCapture.ts` |
| 7.5 | Disk-backed body spool | `electron/traffic/streamingSpool.ts` |

### Patches

`electron/proxyEngine.ts` (ALPN h2 in CONNECT MITM), `electron/certManager.ts` (H2 ALPN in per-host certs), `src/App.tsx` (Repeater H2 frame editor), `electron/projectStore.ts` (H2 streams + spool refs).

### Tests

```
tests/traffic-http2-end-to-end.mjs
tests/traffic-http2-frame-editor.mjs
tests/traffic-streaming-sse.mjs
tests/traffic-streaming-large-body.mjs
```

### Exit gate (G7 + G8)

- H2-only origin (e.g. `nghttp2`) MITM with pseudo-header editing in Repeater.
- 30-minute SSE capture under 200 MB RSS, body spool reaches disk.

---

## 10. Phase 8 — Playback (Week 6)

### Tasks

| # | Item | Files (new) |
|---|---|---|
| 8.1 | Client playback (bulk replay) | `electron/traffic/playback.ts` |
| 8.2 | Server playback (fake upstream) | (same file, separate exports) |
| 8.3 | Playback request matcher | `electron/traffic/playbackMatcher.ts` |

### Patches

`electron/proxyEngine.ts` (playback hook), `src/App.tsx` (Playback workspace), `electron/projectStore.ts` (playback sessions), `scripts/proxyforge-agent.mjs` (`playback-client` / `playback-server`).

### Tests

```
tests/traffic-playback-client.mjs
tests/traffic-playback-server.mjs
```

### Exit gate (G9)

- Replay a 100-flow project with scope + rate.
- Serve a fake-upstream session for a regression demo.

---

## 11. Phase 9 — Content views (Week 7)

### Tasks

Implement registered views: multipart, zip tree, CSS pretty, MQTT, SocketIO, WBXML, DNS pretty, GraphQL pretty, SSE, protobuf raw.

### Files

```
electron/traffic/contentViews.ts
electron/traffic/views/{multipart,zipTree,cssPretty,mqtt,socketio,wbxml,dnsPretty,graphqlPretty,sse,protobufRaw}.ts
```

### Patches

`src/App.tsx` (Viewer renders selected view), `electron/projectStore.ts` (preferred view per content-type).

### Tests

`tests/traffic-content-views.mjs` round-trips fixtures per view.

### Exit gate (G10)

Every view round-trips its fixture bytes without mutation. Renderer never loads huge blobs unbounded.

---

## 12. Phase 10 — Browser scan oracle (Week 9–10)

### Tasks

| # | Item | Files (new) |
|---|---|---|
| 10.1 | CDP/Playwright orchestrator | `electron/browserScanDriver.ts` |
| 10.2 | Per-page sandbox worker | `electron/browserScanWorker.ts` |
| 10.3 | Scanner ↔ browser contract | `src/scanner/browserOracle.ts` |
| 10.4 | DOM XSS family | `src/scanner/families/domXss.ts` |
| 10.5 | DOM clobbering family | `src/scanner/families/domClobbering.ts` |
| 10.6 | Client prototype pollution | `src/scanner/families/prototypePollutionClient.ts` |
| 10.7 | postMessage misconfig | `src/scanner/families/postmessageMisconfig.ts` |

### Patches

`electron/browserLauncher.ts` (headless scan mode), `electron/crawlEngine.ts` (browser-eligible insertion points), `src/App.tsx` (browser-required check checkbox + status), `electron/projectStore.ts` (DOM observations).

### Tests

```
tests/browser-scan-driver.mjs
tests/scanner-dom-xss-browser-fixture.mjs
tests/scanner-proto-pollution-browser-fixture.mjs
```

### Exit gate (G3)

DOM XSS + client-side prototype pollution confirmed by browser-observed alert/property mutation on SPA fixture.

---

## 12b. Phase 10b — Interactive DOM source→sink tracer (Week 10–11)

Builds on the CDP/Playwright plumbing from Phase 10. Where 10 automates DOM XSS during crawl, **10b** adds the analyst-driven companion: live source/sink instrumentation, canary stamping, and a ProxyForge panel that surfaces the source→transformation→sink chain as the operator clicks through the managed browser.

### Tasks

| # | Item | Files (new) |
|---|---|---|
| 10b.1 | CDP attach + isolated-world setup | `electron/domTracerDriver.ts` |
| 10b.2 | Bundled instrumentation script (sources, sinks, taint hooks) | `electron/domTracerInstrumentation.ts` |
| 10b.3 | Tracer session/canary/event reducer | `src/domTracerEngine.ts` |
| 10b.4 | Sources timeline + sinks table + canary composer + flow graph | `src/components/domTracer/{sourcesTimeline,sinksTable,canaryComposer,flowGraph}.tsx` |
| 10b.5 | Sink + source registry with severity hints | `src/data/domTracerSinks.ts` |
| 10b.6 | Operator guide | `docs/DOM_TRACER_GUIDE.md` |
| 10b.7 | Promote-to-Scanner: trace + canary + transformation chain → Issue | `src/scanner/domTracerPromotion.ts` |

### Patches

`electron/browserLauncher.ts` (register tracer on in-scope managed-browser tabs only), `src/components/pfv2/screens/proxy.tsx` (Tracer tab next to History / Intercept / WebSockets), `electron/projectStore.ts` (persist tracer sessions, evidence-ready transcripts), `src/components/pfv2/screens/scanner.tsx` (accept tracer-promoted issues).

### Tests

```
tests/dom-tracer-instrumentation.mjs        # instrumented page emits expected source/sink events
tests/dom-tracer-canary-reflection.mjs      # canary lands at expected sink with recorded transformation
tests/dom-tracer-fixture-spa.mjs            # location.hash → innerHTML SPA fixture, promoted to issue
tests/dom-tracer-postmessage-fixture.mjs    # postMessage origin-wildcard sink flagged
tests/dom-tracer-redirect-scheme.mjs        # `redirectUrl=javascript:...` source→sink chain captured
tests/dom-tracer-scope-gating.mjs           # tracer refuses to attach to out-of-scope tabs
```

### Exit gate (G3b)

Live session against a managed-browser tab populates sources + sinks; a stamped canary is traced source → transformation → sink with the JS stack attached; the analyst promotes the trace into a Scanner issue with reflected payload, sink stack, and transformation chain as evidence; instrumentation refuses to attach to out-of-scope tabs.

---

## 13. Phase 11 — Param miner + content discovery (Week 11)

### Tasks

| # | Item | Files (new) |
|---|---|---|
| 11.1 | Content discovery engine | `src/contentDiscoveryEngine.ts` |
| 11.2 | Param miner engine | `src/scanner/paramMinerEngine.ts` |
| 11.3 | Bundled wordlists | `src/data/wordlists/{common-paths,common-params,common-headers}.json` |

### Patches

`src/App.tsx` (discovery + miner workspaces), `scripts/proxyforge-agent.mjs` (`discover` / `mine` CLI commands), `electron/projectStore.ts` (discovery runs).

---

## 13b. Phase 11b — API spec ingest + Ajax/SPA spider (Week 11–12)

### Tasks

| # | Item | Files (new) |
|---|---|---|
| 11b.1 | Spec import router + OpenAPI 3 / Swagger 2 | `src/specImport/{index,openApi}.ts` |
| 11b.2 | Postman v2.1 collections | `src/specImport/postman.ts` |
| 11b.3 | Insomnia v4 collections | `src/specImport/insomnia.ts` |
| 11b.4 | SOAP WSDL 1.1 / 1.2 | `src/specImport/soapWsdl.ts` |
| 11b.5 | OData $metadata | `src/specImport/odata.ts` |
| 11b.6 | GraphQL SDL + introspection JSON | `src/specImport/graphqlSchema.ts` |
| 11b.7 | Insertion-point extraction from spec | `src/scanner/insertionPointsFromSpec.ts` |
| 11b.8 | Import wizard UI | `src/components/pfv2/screens/import/` |
| 11b.9 | Ajax / SPA spider CDP driver | `electron/spiders/ajaxSpiderDriver.ts` |
| 11b.10 | Ajax spider heuristics + SPA-router patterns | `electron/spiders/ajaxSpiderHeuristics.ts`, `src/data/spider/spaPatterns.json` |
| 11b.11 | Passive link crawler refactor (carved out of `crawlEngine`) | `src/spiders/passiveLinkCrawler.ts` |
| 11b.12 | Ajax spider engine + sitemap merge | `src/spiders/ajaxSpiderEngine.ts` |

### Tests

```
tests/spec-import-openapi.mjs            # 12 routes, 47 params, 3 auth schemes extracted
tests/spec-import-postman.mjs
tests/spec-import-insomnia.mjs
tests/spec-import-soap-wsdl.mjs
tests/spec-import-odata.mjs
tests/spec-import-graphql-schema.mjs
tests/spider-ajax-react-router-fixture.mjs
tests/spider-ajax-vue-router-fixture.mjs
tests/spider-ajax-event-handlers-fixture.mjs
tests/spider-ajax-rate-budget-respected.mjs
```

### Exit gate (G16b)

Each of the six supported spec formats imports a fixture and populates Target Map + insertion-point inventory + a ready-to-replay Repeater group. Ajax spider visits ≥80 % of routes the passive crawl misses on the React Router and Vue Router fixtures, and respects the per-project rate budget.

### Tests

```
tests/content-discovery-engine.mjs
tests/scanner-param-miner.mjs
```

### Exit gate

Bounded run finds at least one hidden header param and one hidden path on fixture app. Custom wordlist import works.

---

## 14. Phase 12 — OAST provider profiles (Week 12)

### Tasks

| # | Item | Files (new) |
|---|---|---|
| 12.1 | Provider registry | `electron/callbackProviderRegistry.ts` |
| 12.2 | Provider profile types | `src/oastProviderProfile.ts` |
| 12.3 | Operator guide | `docs/OAST_PROVIDER_GUIDE.md` |

### Acceptance

- BYO public listener documented (tunnel patterns).
- Per-project HMAC-signed payload tokens.
- Callback received via at least one third-party DNS + HTTP provider in test environment.

### Exit gate (G4)

Callback received, signed, correlated to scan run, promoted to issue, exported in signed bundle, survives project close/reopen.

---

## 15. Phase 13 — Skilllet metadata + automation recipes (Week 8–9)

### Tasks

| # | Item | Files (new) |
|---|---|---|
| 13.1 | Skilllet JSON extraction from vendored skilllets.py | `src/data/scannerSkilllets.json` |
| 13.2 | Skilllet mapper | `src/scanner/skillletMapper.ts` |
| 13.3 | Recipe schema + engine + evidence gates | `src/automation/{playbookSchema,playbookRecipeEngine,playbookEvidenceGate,agentProtocol}.ts` |
| 13.4 | First 10 recipes (port from vendored playbook YAMLs) | `src/automation/recipes/{webPayloadFamilyValidation,ssrfCallbackValidation,apiAuthzMatrix,blindSqlOracleMatrix,fileUploadRoundtrip,websocketSequenceReview,graphqlSurfaceValidation,contentDiscoveryParamMining,identitySessionReview,proofPackCompletion}.ts` |
| 13.5 | Bundled skill pack docs | `src/data/skillPacks/*.md` (67 packs + 14 shared) |
| 13.6 | Capability ontology | `src/data/capabilityOntology.json` |

### Patches

`src/automationEngine.ts` (registry + lifecycle), `src/App.tsx` (automation workspace + scanner help panel surfaces skill pack docs), `electron/projectStore.ts` (recipe runs + evidence gates), `scripts/proxyforge-agent.mjs` (`playbook-list/plan/run/export`).

### Tests

```
tests/scanner-skilllet-metadata.mjs
tests/scanner-skilllet-mapper.mjs
tests/playbook-recipe-parser.mjs
tests/playbook-recipe-run-fixture.mjs
tests/playbook-evidence-gates.mjs
tests/automation-recipes.mjs
tests/headless-automation-recipes.mjs
```

### Exit gate

- Every scanner check has skilllet metadata.
- At least 10 recipes parse and render.
- At least 3 recipes execute against fixtures end-to-end.
- Recipe runs survive project reopen.

---

## 16. Phase 14 — Extension SDK + sample extensions (Week 6–10, parallel)

### Tasks

| # | Item | Files (new) |
|---|---|---|
| 14.1 | Typed SDK declarations | `src/extensions/sdk.d.ts` |
| 14.2 | SDK helpers | `src/extensions/sdkHelpers.ts` |
| 14.3 | Manifest validation + signed package | `src/extensions/manifest.ts` |
| 14.4 | Sample extensions | `src/extensions/sampleExtensions/{passive-secret-detector,header-injector,intruder-base64,custom-scan-check}/` |
| 14.5 | Documentation | `docs/EXTENSION_API.md` |

### Patches

`src/extensionEngine.ts` adds hooks for `request`, `response`, `tls_clienthello`, `tcp_message`, `scan_check`, `editor_tab`, `intruder_payload_processor`, `repeater_action`, `scanner_passive`.

### Tests

```
tests/extension-sdk-contract.mjs
tests/extension-signed-package.mjs
tests/extension-sample-passive-secret.mjs
tests/extension-sample-header-injector.mjs
tests/extension-sample-intruder-base64.mjs
tests/extension-sample-custom-scan-check.mjs
```

### Exit gate (G12)

4 sample extensions load, manifest signatures verify, hooks fire, runtime policy enforced.

---

## 17. Phase 15 — Project Store schema migrations (Week 10)

### Tasks

Add records (full list in master plan §8.5). Categories:

- Scanner: check packs, probe runs, variants, observations, evidence matrices, negative evidence.
- Skill metadata.
- Playbook: recipes, runs, steps, evidence gates.
- Exploit template runs.
- Traffic: rule packs, rule events, filter presets, HAR exports, cut exports, content view preferences, playback sessions, mode configs, DNS record rules.
- Protocol: HTTP/2 streams, streaming spool refs.

### Patches

`electron/projectStore.ts` (migrations + serde), `electron/projectSnapshotEngine.ts` (snapshot test of all new tables).

### Tests

```
tests/project-store-migrations.mjs
tests/project-store-snapshot-roundtrip.mjs
tests/project-store-crash-recovery.mjs
```

### Exit gate (G13)

Project export → fresh install → import preserves every new field. Crash recovery replays partial scanner/recipe runs.

---

## 18. Phase 16 — Full-chain GUI + headless E2E (Week 11)

### Tasks

Playwright specs covering the full operator workflow on Linux + Windows package builds.

### Tests

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
tests/headless-full-chain-vantix-core.mjs
tests/headless-full-chain-playbook.mjs
```

### Exit gate (G14)

Each spec passes on Linux + Windows package builds.

---

## 19. Phase 17 — Optional native side-cars (Week 8–12, parallel)

### Tasks

Each side-car is optional. Proxy Forge ships fine without any of them.

| Sub-phase | Side-car | Files |
|---|---|---|
| 17a | Transparent (Linux) | `side-cars/transparent-linux/` (Rust), `electron/traffic/transparentMode.ts`, `docs/MODES_TRANSPARENT.md` |
| 17b | Raw TCP/UDP | `electron/traffic/rawTcpUdp.ts` (pure Node — no side-car needed) |
| 17c | HTTP/3 / QUIC | `side-cars/quic/` (Rust + quiche), `electron/traffic/http3Transport.ts`, `docs/MODES_HTTP3.md` |
| 17d | WireGuard | `side-cars/wireguard/` (Rust + boringtun), `electron/traffic/wireguardMode.ts`, `docs/MODES_WIREGUARD.md` |

### Tests

Gated on platform + side-car availability:

```
tests/traffic-transparent-linux.mjs
tests/traffic-raw-tcp-udp.mjs
tests/traffic-http3-end-to-end.mjs
tests/traffic-wireguard.mjs
```

### Exit gate (G11)

Each side-car has a passing smoke test on its supported platform. Build pipeline produces optional installer extras.

---

## 20. Phase 18 — Release hardening + honest README (Week 13–14)

### Tasks

| # | Item | Patch |
|---|---|---|
| 18.1 | Main renderer sandbox enabled | `electron/main.ts`, `electron/preload.ts` |
| 18.2 | All dangerous IPC behind contracts | `electron/ipcContracts.ts` |
| 18.3 | Runtime schema validation on IPC payloads | `electron/ipcContracts.ts` |
| 18.4 | Audit events for proxy/CA/cookies/scan/OAST/AI/exec/report/extension | `electron/projectStore.ts`, related engines |
| 18.5 | Body/transcript caps everywhere | proxy, OAST, WebSocket, reports, AI handoff |
| 18.6 | Portable fast CI from source archive | `tests/release-readiness.mjs`, `tests/ci-fast-suite.mjs` |
| 18.7 | Playwright browser install/cache handling | `scripts/release-smoke.mjs` |
| 18.8 | Linux + Windows package smoke tests cover full chain | `scripts/release-smoke.mjs` |
| 18.9 | SBOM + checksums + release manifest | `scripts/release-trust.mjs` |
| 18.10 | Honest README + feature matrix accuracy | `README.md`, `docs/FEATURE_MATRIX.md` |
| 18.11 | Feature matrix lint | `docs/FEATURE_MATRIX_LINT.mjs` |
| 18.12 | Security regression suite | `tests/security-regression-*.mjs` |

### Security regression coverage

- Path traversal in maplocal/exports.
- Archive zip-slip on HAR/bundle import.
- IPC parameter validation rejects malformed payloads.
- Side-car process boundary cannot escape sandbox env.
- OAST signature verification rejects forged callbacks.
- Body/transcript caps prevent runaway memory.
- AI handoff redaction is applied at boundary.

### Exit gate (G15 + G16 + G17)

- Renderer sandbox enabled (or narrowly excepted with passing test for the exception).
- IPC schema-validated.
- Security regression suite green.
- README claim-to-test ratio: 1:1.
- `grep -R "source-reference/vantix"` returns no runtime matches.
- Product builds and passes fast CI with `source-reference/vantix/` deleted.

---

## 20b. Phase 18b — Headless API surface expansion (Week 13–15, parallel)

### Tasks

| # | Item | Files (new) |
|---|---|---|
| 18b.1 | Headless API IR + generator registry | `src/apiGenerators/index.ts` |
| 18b.2 | Python client generator (sync + async, pydantic models) | `src/apiGenerators/pythonGenerator.ts` |
| 18b.3 | Node.js / TypeScript generator (ESM, co-emitted types) | `src/apiGenerators/nodeJsGenerator.ts` |
| 18b.4 | Java generator (Gradle module, records, jakarta.json) | `src/apiGenerators/javaGenerator.ts` |
| 18b.5 | Rust generator (serde + tokio) | `src/apiGenerators/rustGenerator.ts` |
| 18b.6 | Go generator (modules, encoding/json) | `src/apiGenerators/goGenerator.ts` |
| 18b.7 | PHP generator (PSR-4, guzzle) | `src/apiGenerators/phpGenerator.ts` |
| 18b.8 | Wiki / Markdown reference generator | `src/apiGenerators/wikiGenerator.ts` |
| 18b.9 | Project SBOM engine (CycloneDX + SPDX) | `src/sbomEngine.ts`, `src/sbomFormats/{cyclonedx,spdx}.ts` |
| 18b.10 | Global Stats counters + passive Stats rule | `src/stats/{countersEngine,countersStore,passiveStatsRule}.ts` |
| 18b.11 | AI agent SQL-over-traffic tool (read-only, sandboxed SELECT) | `src/aiTools/capturedTrafficSql.ts` |
| 18b.12 | AI agent managed-browser-drive tool (Mode + Context gated) | `src/aiTools/managedBrowserDrive.ts` |
| 18b.13 | AI tool registry + per-tool auth gate UI | `src/aiTools/index.ts`, `src/components/pfv2/screens/remaining.tsx` patch |
| 18b.14 | Open-project-folder action | `src/components/pfv2/screens/settings/openProjectFolder.tsx`, `electron/openProjectFolder.ts` |

### Tests

```
tests/api-client-python-smoke.mjs
tests/api-client-nodejs-smoke.mjs
tests/api-client-java-smoke.mjs
tests/api-client-rust-smoke.mjs
tests/api-client-go-smoke.mjs
tests/api-client-php-smoke.mjs
tests/sbom-cyclonedx-roundtrip.mjs
tests/sbom-spdx-roundtrip.mjs
tests/sbom-includes-evidence-references.mjs
tests/stats-counter-decay.mjs
tests/stats-rule-redirect-chain-finding.mjs
tests/stats-rule-5xx-cluster-finding.mjs
tests/ai-tool-traffic-sql-readonly.mjs
tests/ai-tool-traffic-sql-injection-impossible.mjs
tests/ai-tool-browser-drive-scope-gated.mjs
tests/ai-tool-browser-drive-mode-safe-blocks.mjs
tests/open-project-folder-whitelist-guard.mjs
```

### Exit gate (G15b)

- Six language stubs build + round-trip `proxy.start` + `history.query` + `report.export` against a fixture project.
- CycloneDX + SPDX SBOM exports validate against the official validators and round-trip through a clean importer.
- Stats rule fires findings on the 5xx-cluster and redirect-chain fixtures; counters survive project close/reopen.
- Under Mode = Standard with an in-scope target, the AI agent answers a captured-traffic question using one parametrised SELECT; under Mode = Safe, the call is refused with an auditable reason. The AI managed-browser tool refuses to attach to out-of-scope tabs.

---

## 21. Phase 19 — Alpha cut (Week 15–16, buffer)

### Tasks

| # | Item |
|---|---|
| 19.1 | Tag `v0.x-alpha` | `v0.1.0-alpha.1` | **READY.** Create on the release commit after CI receipts are clean. |
| 19.2 | Signed packages (Linux .deb + AppImage, Windows .exe NSIS + portable) | Native artifact matrix + release-smoke receipts | **DONE as release workflow.** Public distribution still requires artifact receipts for the exact release commit and optional operator signing credentials. |
| 19.3 | Release notes citing every G1-G17 gate result | `docs/RELEASE_NOTES_v0.1.0-alpha.1.md` | **DONE.** |
| 19.4 | Public README rewrite for alpha audience | `README.md` | **DONE.** |
| 19.5 | Alpha announcement | Release notes + README release summary | **DONE as committed announcement copy.** |
| 19.6 | Bug-bash window (1 week) | Release notes + hotfix process | **DONE as release operating process.** |
| 19.7 | Hotfix process documented | `docs/HOTFIX_PROCESS.md` | **DONE.** |

### Exit gate

All §3 checklists in the master plan fully `[x]`. All G1-G17 gates have source evidence and release notes. Packaged binaries must pass smoke tests on clean Linux + Windows machines through the native artifact matrix before broad public distribution.

---

## 22. PR sequencing (numbered execution order)

```
PR  1 — Scanner primitives part 1: types + payload engine + oracle classifier  (Phase 1.1–1.3)
PR  2 — Scanner primitives part 2: probe matrix + finding builder              (Phase 1.4)
PR  3 — Scanner primitives part 3: runner + first 7 families + check pack      (Phase 1.5–1.7)
PR  3b — Per-family payload variant tables + insertion-point iterator + delete  (Phase 1.7a–1.7b)
         single-payload `proxyEngine.ts` probes
PR  4 — Scanner UI workspace                                                   (Phase 3)
PR  4b — Contexts + auth methods + users + custom pages + anti-CSRF + Modes    (Phase 3b)
         + global Replacer + scanner policies + conditional breakpoints
PR  5 — Project Store scanner schema                                           (Phase 1.8 + 15 first slice)
PR  6 — Flow filter DSL                                                        (Phase 2.1)
PR  7 — Rule pack engine + 11 rule types                                       (Phase 2.2–2.7)
PR  8 — HAR export + cut/extract                                               (Phase 2.8–2.9)
PR  9 — Modern web injection families (4a)                                     (Phase 4a)
PR 10 — SOCKS5 mode                                                            (Phase 5.1)
PR 11 — Reverse mode                                                           (Phase 5.2)
PR 12 — DNS proxy mode                                                         (Phase 5.3)
PR 13 — Auth/session check families (4b)                                       (Phase 4b)
PR 14 — Exploit Lab oastCallback + webhookReplay templates                     (Phase 6 first slice)
PR 15 — HTTP/2 transport                                                       (Phase 7.1–7.2)
PR 16 — HTTP/2 Repeater frame editor                                           (Phase 7.3)
PR 17 — Cache + smuggling families (4c)                                        (Phase 4c)
PR 18 — Streaming bodies + spool                                               (Phase 7.4–7.5)
PR 19 — Playback (client + server)                                             (Phase 8)
PR 20 — Deserialization + blind RCE families (4d)                              (Phase 4d)
PR 21 — Browser scan driver + worker                                           (Phase 10.1–10.3)
PR 22 — DOM XSS + proto pollution families (4e)                                (Phase 4e + Phase 10.4–10.7)
PR 22b — Interactive DOM tracer (driver, instrumentation, panel, promotion)    (Phase 10b)
PR 23 — Content views                                                          (Phase 9)
PR 24 — GraphQL + API families (4f)                                            (Phase 4f)
PR 24b — Passive engine expansion (16 new passive check IDs + fixtures)        (Phase 4g)
PR 24c — CVE / named active families (44 new IDs + fixtures)                   (Phase 4h)
PR 24d — Passive posture rule expansion (~64 new IDs + fixtures)               (Phase 4i)
PR 25 — Exploit Lab raceWindow + authzMatrix + cacheKeyDiff + fileUpload       (Phase 6 second slice)
PR 26 — Exploit Lab websocketSequence + oauthFlow + mfaFlow + grpcSequence     (Phase 6 third slice)
PR 27 — Exploit Lab remaining templates                                        (Phase 6 fourth slice)
PR 28 — Param miner + content discovery + wordlists                            (Phase 11)
PR 28b — Spec import (OpenAPI/Postman/Insomnia/SOAP/OData/GraphQL) +           (Phase 11b)
         Ajax/SPA spider + sitemap merge
PR 29 — Extension SDK + 4 sample extensions                                    (Phase 14)
PR 30 — Skilllet metadata + UI surfacing                                       (Phase 13.1–13.2 + 13.5–13.6)
PR 31 — Recipe engine + first 5 recipes                                        (Phase 13.3–13.4 first half)
PR 32 — Remaining 5 recipes                                                    (Phase 13.4 second half)
PR 33 — OAST provider profiles + signed tokens                                 (Phase 12)
PR 34 — Project Store migrations (remaining tables)                            (Phase 15)
PR 35 — Side-car: transparent (Linux)                                          (Phase 17a)
PR 36 — Side-car: raw TCP/UDP                                                  (Phase 17b)
PR 37 — Side-car: HTTP/3                                                       (Phase 17c)
PR 38 — Side-car: WireGuard                                                    (Phase 17d)
PR 39 — Full-chain GUI E2E specs                                               (Phase 16)
PR 40 — Headless E2E + portable CI                                             (Phase 18.6–18.7)
PR 41 — Renderer sandbox + IPC contracts                                       (Phase 18.1–18.3)
PR 42 — Audit events + body caps                                               (Phase 18.4–18.5)
PR 43 — Security regression suite                                              (Phase 18.12)
PR 44 — Package smokes + SBOM + release manifest                               (Phase 18.8–18.9)
PR 44b — Multi-lang API client generators + project SBOM + Stats counters +    (Phase 18b)
         AI traffic-SQL tool + AI managed-browser tool + open-project-folder
PR 45 — README + feature matrix honesty + lint                                 (Phase 18.10–18.11)
PR 46 — Alpha tag + release notes                                               (Phase 19)
```

**Total:** 46 PRs (~100 commits realistic).

---

## 23. Backlog by priority

### P0 — required for alpha credibility

| # | Item | Phase |
|---|---|---|
| 1 | No runtime vendored-source dependency (CI guard) | 0 |
| 2 | Honest feature matrix | 0 |
| 3 | Scanner payload mutation engine | 1 |
| 4 | Oracle response classifier | 1 |
| 5 | Probe matrix + evidence persistence | 1 |
| 6 | First 7 scanner families | 1 |
| 6b | Per-family payload variant tables (≥6/family) + insertion-point iterator; delete single-payload `proxyEngine.ts` probes | 1.7a–1.7b |
| 6c | Passive engine expansion (8 → ≥24 IDs, incl. reflected-redirect-scheme catching `javascript:`/`data:`/`//`/`\\`) | 4g |
| 7 | Scanner UI workspace | 3 |
| 8 | Flow filter DSL + 11 rule types | 2 |
| 9 | HAR export + cut/extract | 2 |
| 10 | Project Store schema migrations | 15 |
| 11 | Full-chain GUI + headless E2E | 16 |
| 12 | Renderer sandbox + IPC contracts | 18 |
| 13 | Security regression suite | 18 |
| 14 | Portable CI from source archive | 18 |

### P1 — makes Proxy Forge useful day-to-day

| # | Item | Phase |
|---|---|---|
| 14b | Contexts + auth methods + users + custom pages + anti-CSRF + Modes | 3b |
| 15 | Scanner depth expansion (≥90 active, ≥70 passive IDs) | 4 |
| 15b | CVE / named active families (Log4Shell, Spring4Shell, Heartbleed, ShellShock, cloud-metadata, …) | 4h |
| 15c | Passive posture rule expansion (~64 IDs) | 4i |
| 16 | SOCKS5 / reverse / DNS modes | 5 |
| 17 | HTTP/2 + streaming | 7 |
| 18 | Playback (client + server) | 8 |
| 19 | Content views | 9 |
| 20 | Exploit Lab verifier templates | 6 |
| 21 | Skilllet metadata + automation recipes | 13 |
| 22 | OAST provider profiles | 12 |
| 23 | Extension SDK + sample extensions | 14 |
| 23b | API spec ingest (OpenAPI/Postman/Insomnia/SOAP/OData/GraphQL) + Ajax spider | 11b |
| 23c | Multi-language API client generators (Python/Node.js/Java/Rust/Go/PHP) | 18b |
| 23d | Project SBOM (CycloneDX + SPDX) | 18b |
| 23e | Global Stats counters + passive Stats rule | 18b |
| 23f | AI agent traffic-SQL tool + managed-browser tool | 18b |

### P2 — expands coverage and operator confidence

| # | Item | Phase |
|---|---|---|
| 24 | Browser scan oracle (DOM XSS, proto pollution) | 10 |
| 24b | Interactive DOM source→sink tracer (analyst-driven) | 10b |
| 25 | Param miner + content discovery | 11 |
| 26 | Optional side-cars (transparent, raw TCP/UDP, HTTP/3, WireGuard) | 17 |
| 27 | Long-tail product detection checks (~175 detections from vendored corpus) | post-alpha |
| 28 | Sechive-family recipes (10 OWASP-style coverage recipes) | post-alpha |

### P3 — durability and ecosystem

| # | Item | Phase |
|---|---|---|
| 29 | Generic automation API (CLI + JSON + event stream) | 18 (parallel) |
| 30 | Signed evidence bundles + verification | already exists; harden |
| 31 | Enterprise policy package format | already exists; harden |
| 32 | Hosted multi-tenant OAST service | post-alpha |
| 33 | Cross-platform native side-car installer extras | post-alpha |

---

## 24. Operating cadence

Each working day:

```
morning  — read top-of-queue PR, plan the day's slice
midday   — implementation + per-family fixture tests
afternoon — test pass, type check, build, smoke
end      — open PR with tests, update FEATURE_MATRIX.md row for the new capability
```

Each working week:

```
monday    — pick top P0/P1 backlog item per active track
mid-week  — landing PRs, opening new ones
friday    — fast CI sweep, README accuracy spot-check, weekly cut tag
```

Each phase exit:

```
- all phase tests green
- master plan §10 gate marked done
- backlog reordered against learnings
- planning/PROXY_FORGE_ROADMAP.md timeline column updated
```

---

## 25. Status tracking

Add a single status table at the top of this file once execution starts:

```
| Phase | Status        | Started     | Done        | Gate |
|---|---|---|---|---|
| 0   | In progress | 2026-05-26 |             |       |
| 1   | Pending     |             |             | G1    |
| 2   | Pending     |             |             | G5    |
| ... | ...         |             |             |       |
```

Update at each phase boundary. Reference the gate ID from the master plan §10 in each row.
