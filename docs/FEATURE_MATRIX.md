# ProxyForge Feature Matrix

> Last updated: 2026-06-20
> Test IDs reference files in `tests/`.
> **Status key:** `Backend` = code + unit tests, no GUI wiring. `GUI-integrated` = wired into the renderer. `E2E-tested` = full end-to-end with proxy/project-store. `Production` = packaged, cross-platform verified.

## Phase 0 — Guardrails

| Feature | Status | Test |
|---------|--------|------|
| No vantix runtime dependency | Backend | tests/no-vantix-runtime-dependency.mjs |
| Release excludes source-reference/ | Backend | tests/release-package-excludes-source-reference.mjs |

## Phase 1 — Scanner Primitives

| Feature | Status | Test |
|---------|--------|------|
| Payload mutation engine (8+ families) | Backend | tests/scanner-payload-mutation-engine.mjs |
| Oracle response classifier | Backend | tests/scanner-oracle-response-classifier.mjs |
| Probe renderer | Backend | tests/scanner-probe-renderer.mjs |
| Evidence matrix | Backend | tests/scanner-evidence-matrix.mjs |
| ≥50 active check IDs | Backend | — |
| 17+ family payload files | Backend | — |

## Phase 2 — Traffic Tier 1

| Feature | Status | Test |
|---------|--------|------|
| HAR export | Backend | tests/traffic-har-export.mjs |
| Cut export | Backend | tests/traffic-cut-export.mjs |
| Content views | Backend | tests/traffic-content-views.mjs |
| Flow filter DSL | Backend | tests/traffic-flow-filter.mjs |
| Rule packs (anticache, blocklist) | Backend | tests/traffic-rules-anticache.mjs, tests/traffic-rules-blocklist.mjs |

## Phase 3 — Scanner UI Workspace

| Feature | Status | Test |
|---------|--------|------|
| Active scan engine (IPC wiring) | Backend | tests/scanner-active-scan-engine.mjs |
| Live calibration | Backend | tests/scanner-live-calibration.mjs |

## Phase 3b — Contexts, Auth, Modes

| Feature | Status | Test |
|---------|--------|------|
| Context engine membership | Backend | tests/context-engine-membership.mjs |
| Session macro engine | Backend | tests/session-macro-engine.mjs |
| Anti-CSRF refresh before replay | Backend | tests/anti-csrf-refresh-before-replay.mjs |
| Global safe-mode blocks active scan | Backend | tests/global-mode-safe-blocks-active-scan.mjs |

## Phase 4 — Scanner Depth

| Feature | Status | Test |
|---------|--------|------|
| Passive scanner engine | Backend | tests/scanner-passive-engine.mjs |
| Passive redirect scheme rule | Backend | tests/scanner-passive-redirect-scheme.mjs |
| Passive reflected XSS rule | Backend | tests/scanner-passive-reflected-xss.mjs |
| Passive debug endpoint rule | Backend | tests/scanner-passive-debug-endpoint.mjs |
| Retest engine | Backend | tests/scanner-retest-engine.mjs |

## Phase 5 — Alternate Proxy Modes

| Feature | Status | Test |
|---------|--------|------|
| SOCKS5 inbound proxy | Backend | tests/traffic-socks-inbound.mjs |
| Reverse proxy mode | Backend | tests/traffic-reverse-mode.mjs |
| DNS proxy | Backend | tests/traffic-dns-proxy.mjs |
| CONNECT tunnel | E2E-tested | tests/connect-tunnel.mjs |

## Phase 6 — Exploit Lab Templates

| Feature | Status | Test |
|---------|--------|------|
| Exploit engine | Backend | tests/exploit-engine.mjs |
| Authz matrix template | Backend | tests/exploit-template-authz-matrix.mjs |
| OAST callback template | Backend | tests/exploit-template-oast-callback.mjs |
| Report evidence template | Backend | tests/exploit-template-report-evidence.mjs |
| Webhook replay template | Backend | tests/exploit-template-webhook-replay.mjs |
| Race window template | Backend | tests/exploit-template-race-window.mjs |
| Cache key diff template | Backend | tests/exploit-template-cache-key-diff.mjs |
| File upload roundtrip template | Backend | tests/exploit-template-file-upload.mjs |
| WebSocket sequence template | Backend | tests/exploit-template-websocket-sequence.mjs |
| OAuth flow template | Backend | tests/exploit-template-oauth-flow.mjs |
| MFA flow bypass template | Backend | tests/exploit-template-mfa-flow.mjs |
| Model output sink template | Backend | tests/exploit-template-model-output-sink.mjs |
| Redaction invariant template | Backend | tests/exploit-template-redaction-invariant.mjs |
| Artifact boundary template | Backend | tests/exploit-template-artifact-boundary.mjs |
| gRPC sequence template | Backend | tests/exploit-template-grpc-sequence.mjs |
| Multi-step chain template | Backend | tests/exploit-template-multi-step-chain.mjs |
| State diff helpers | Backend | (via index exports) |
| Side-effect guard helpers | Backend | (via index exports) |
| Browser verifier helpers | Backend | (via index exports) |

## Phase 7 — HTTP/2 + Streaming + Playback

| Feature | Status | Test |
|---------|--------|------|
| HTTP/2 transport | Backend | tests/traffic-http2-transport.mjs |
| HTTP/2 frame editor | Backend | tests/traffic-http2-frame-editor.mjs |
| Streaming large body | Backend | tests/traffic-streaming-large-body.mjs |
| Streaming SSE | Backend | tests/traffic-streaming-sse.mjs |
| Playback client | Backend | tests/traffic-playback-client.mjs |
| Playback server | Backend | tests/traffic-playback-server.mjs |

## Phase 8 — Skilllet Metadata + Automation Recipes

| Feature | Status | Test |
|---------|--------|------|
| Skilllet metadata | Backend | tests/scanner-skilllet-metadata.mjs |
| Automation engine | Backend | tests/automation-engine.mjs |
| Automation recipes | Backend | tests/automation-recipes.mjs |

## Phase 9 — Extension SDK

| Feature | Status | Test |
|---------|--------|------|
| Extension engine | Backend | tests/extension-engine.mjs |
| SDK contract | Backend | tests/extension-sdk-contract.mjs |
| Signed package | Backend | tests/extension-signed-package.mjs |
| Third-party compatibility | Backend | tests/extension-third-party-compatibility-engine.mjs |

## Phase 10 — Browser Scan Oracle

| Feature | Status | Test |
|---------|--------|------|
| DOM tracer canary reflection | Backend | tests/dom-tracer-canary-reflection.mjs |
| DOM tracer SPA fixture | Backend | tests/dom-tracer-fixture-spa.mjs |

## Phase 11 — Param Miner + Content Discovery

| Feature | Status | Test |
|---------|--------|------|
| Param miner | Backend | tests/scanner-param-miner.mjs |
| Content discovery engine | Backend | tests/content-discovery-engine.mjs |

## Phase 12 — Automation API + SBOM + Stats

| Feature | Status | Test |
|---------|--------|------|
| SBOM CycloneDX 1.5 round-trip | Backend | tests/sbom-cyclonedx-roundtrip.mjs |
| SBOM SPDX 2.3 round-trip | Backend | tests/sbom-spdx-roundtrip.mjs |
| SBOM includes evidence references | Backend | tests/sbom-includes-evidence-references.mjs |
| Stats counter decay | Backend | tests/stats-counter-decay.mjs |
| Stats rule: 5xx cluster finding | Backend | tests/stats-rule-5xx-cluster-finding.mjs |
| Stats rule: redirect chain finding | Backend | tests/stats-rule-redirect-chain-finding.mjs |
| OAST SSRF end-to-end | E2E-tested | tests/scanner-oast-ssrf.mjs |
| Callback listener service | E2E-tested | tests/callback-listener-service.mjs |

## Phase 13 — Proxy Browser / Proxy-Chain Diversity

| Feature | Status | Test |
|---------|--------|------|
| Proxy browser/proxy-chain diversity checkpoint | Backend | tests/proxy-browser-proxy-chain-diversity.mjs |
| external live-host diversity | Backend | tests/proxy-browser-proxy-chain-diversity.mjs |
| proxyforge-proxy-browser-proxy-chain-diversity-package | Backend | tests/proxy-browser-proxy-chain-diversity.mjs |

## Phase 14 — Agent Option Audit

| Feature | Status | Test |
|---------|--------|------|
| MVP Agent Option Audit | Backend | tests/agent-option-audit.mjs |
| Agent option audit gate | Backend | tests/agent-option-audit.mjs |

## Phase 17 — Optional Native Side-Cars

| Feature | Status | Test |
|---------|--------|------|
| Transparent proxy (TPROXY / Linux tproxy side-car stub) | Backend | tests/traffic-transparent-linux.mjs |
| Raw TCP/UDP transport (Node.js builtins stub) | Backend | tests/traffic-raw-tcp-udp.mjs |
| HTTP/3 / QUIC transport (quiche/quinn side-car stub) | Backend | tests/traffic-http3-end-to-end.mjs |
| WireGuard capture mode (boringtun side-car stub) | Backend | tests/traffic-wireguard.mjs |

## Phase 18 — Release Hardening

| Feature | Status | Test |
|---------|--------|------|
| Path traversal prevention (IPC project root validation) | Backend | tests/security-regression-path-traversal.mjs |
| Zip-slip / archive path escape prevention (HAR/bundle import) | Backend | tests/security-regression-zip-slip.mjs |
| IPC parameter validation rejects malformed/injected payloads | Backend | tests/security-regression-ipc-schema.mjs |
| OAST signature verification rejects forged callbacks | Backend | tests/security-regression-oast-forgery.mjs |
| Body/transcript caps prevent runaway memory (StreamCapture + capBodySize) | Backend | tests/security-regression-body-caps.mjs |
| AI handoff boundary redaction blocks PII/credential leakage | Backend | tests/security-regression-ai-redaction.mjs |

## Gates Status

| Gate | Status | Criteria |
|------|--------|----------|
| G1 — Scanner core | Complete | Payload engine, oracle, evidence matrix, insertion points, and active scanner tests pass. |
| G2 — Traffic Tier 1 | Complete | HAR, cut/export, filters, rule packs, HTTP/2, streaming, playback, and content-view tests pass. |
| G3 — OAST loop | Complete | Callback listener, provider diversity, relay isolation, scanner SSRF, and signed OAST evidence tests pass. |
| G4 — SBOM | Complete | CycloneDX, SPDX, evidence-reference SBOM, and release trust tests pass. |
| G5 — Packaging | Complete | Linux/Windows package production schema gates, non-publishing build scripts, Electron fuse policy, and native artifact workflow are present. |
| G6 — Alpha cut | Complete | `v0.1.0-alpha.1` tag target, release notes, README alpha copy, bug-bash/hotfix process, and native artifact receipt workflow are complete. |
