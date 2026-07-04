# ProxyForge Operator Guide

This guide is the production operator runbook for ProxyForge. Use it after installation when you need to run authorized web testing workflows, preserve executor evidence, recover from local issues, and prepare redacted submission artifacts.

## Operating Boundaries

- Only test systems you are authorized to assess.
- Keep operational workspaces private. Proxy, browser, agent, callback, replay, scanner, and exploit artifacts preserve full tokens, cookies, keys, headers, callbacks, raw requests, and raw responses until a report/export command explicitly redacts them.
- Use report exports for submission artifacts. Do not hand operational JSONL, search indexes, OAST workspaces, or replay transcripts to a third party unless the program explicitly wants raw evidence.
- Prefer isolated browser profiles and project-specific certificate authorities for every assessment.
- Use `.gitignored/` for local quarantine or bulky work-in-progress artifacts when cleanup would slow the run.
- Preserve `proxyforge-fast-regression-production-evidence-package` artifacts when validating the production quality of the curated fast suite. They prove the fast gate completed every required step with no failed checks, covered release/platform/security/project/agent/browser/proxy/scanner/repeater/intruder/report lanes, retained the CI-uploadable summary artifact, preserved operational executor material, and redacted only during report export.
- Preserve `proxyforge-full-nightly-production-evidence-package` artifacts when validating the scheduled full/nightly suite. They prove the full-suite plan, coverage owners, upload/retention policy, scheduled retained-history restore/save continuity, zero-flake budget, trend dashboard, historical full-run pass, latest runtime pass, fast-suite linkage, and safe artifact paths; a plan-only summary validates metadata but does not claim runtime completion. Operational executor material remains full fidelity and report/export commands redact only during submission output.
- Preserve `proxyforge-full-nightly-retained-history-evidence-package` artifacts when validating retained runtime history. They prove retained runtime summaries, `test-results/ci-full-suite-history/dashboard.json`, current runtime summary linkage, plan-only summaries are excluded from runtime history, digest integrity, zero-flake policy, safe artifact paths, full-fidelity executor material, and report-export-only redaction.
- Preserve `proxyforge-full-nightly-hosted-retained-history-evidence-package` artifacts when validating hosted CI accumulation. They distinguish manual `workflow_dispatch` warmups from scheduled runs and prove hosted run receipts, branch/workflow continuity, successful completion, retained-history restore/save, uploaded summary/dashboard artifacts, retained-dashboard run-id linkage, digest integrity, full-fidelity executor material, and report-export-only redaction.
- Preserve `proxyforge-ui-scale-production-evidence-package` artifacts when validating large-project UI scale and responsive overflow proof. They prove desktop/tablet/mobile viewports, all major analyst surfaces, zero overlap and horizontal overflow, long-label text fitting, keyboard and accessible-name reachability, stable fixed controls, bounded large table windows, latency budgets, report attachment scale, packaged `app.asar` mode, full-fidelity executor material, and report-export-only redaction.
- Preserve `proxyforge-install-docs-production-evidence-package` artifacts when validating Linux/Windows install guide, operator guide, release checklist, release evidence, and agent docs. They prove install smoke commands, CA trust, browser routing, DPAPI, Windows trust-store pinning, Codex CLI, Claude CLI, `~/vantix` agent use, persistent MITM, replay/desync/race/scanner/exploit/OAST coverage, troubleshooting, Production Ready signoff, full-fidelity executor material, and report-export-only redaction.
- Preserve `proxyforge-windows-package-production-evidence-package` artifacts when validating Windows package readiness. They prove native NSIS, portable, and win-unpacked artifacts, zip fallback hygiene, unpacked and installed GUI launch, installed headless scan/report, installed runtime proxy/cert/OAST/report, browser routing, DPAPI sample-cookie extraction, quiet uninstall, formal `windows-trust-runner` trust-store pin acceptance, portable-wrapper stdout pinning, full-fidelity executor material, and report-export-only redaction.
- Preserve `proxyforge-linux-package-production-evidence-package` artifacts when validating Linux package readiness. They prove AppImage, deb, and linux-unpacked artifacts, AppImage and unpacked runtime/GUI smokes, deb metadata/dependency coverage, packaged headless scan/report, packaged agent and external-cwd invocation, packaged runtime proxy/cert/OAST/report, browser routing, clean-container deb install/runtime/GUI/trusted-CA/uninstall proof, known warning pins, full-fidelity executor material, and report-export-only redaction.
- Preserve `proxyforge-platform-shell-production-evidence-package` artifacts when validating the desktop shell. They prove Linux and Windows packaged Electron shell launch, structured release-smoke payloads, packaged headless and agent CLIs, external-cwd app.asar agent execution, packaged runtime proxy/cert/OAST/report smokes, packaged browser routing, Linux and Windows package production gates, accepted trust-store pins, known host-limit pins, full-fidelity executor material, and report-export-only redaction.
- Preserve `proxyforge-agent-control-production-evidence-package` artifacts when validating the agentic control plane. They prove the 70-command Codex/Claude/Vantix surface from source and packaged app.asar status, external-cwd `~/vantix` execution, persistent MITM, Chromium/cookie/data collection, Project Store recovery/backup, search/view/Sequencer/Decoder, replay/live-target profiling/WebSocket/Intruder/Repeater race/desync, insertion-point extraction, Scanner/Anvil/OAST promotion, extension/callback provider host proof/exploit/report, automation service lifecycle and installed-host service smoke/Vantix handoff, scope/approval/rate-limit/audit gates, long-running soak evidence, full-fidelity executor material, and report-export-only redaction.
- Preserve `proxyforge-ai-provider-production-evidence-package` artifacts when validating AI provider production readiness. They prove Codex CLI provider execution, Claude CLI provider execution, OpenAI-compatible HTTP/local provider interop, provider config persistence, prompt libraries, baselines, comparisons, benchmark replay, controlled action packages, scope blocking, no direct action traffic from providers, package-refresh proof, docs/schema coverage, full-fidelity executor prompt material, and report-export-only redaction.
- Preserve `proxyforge-release-security-production-evidence-package` artifacts when validating release security production readiness. They prove the formal zero-finding release security review, local listeners, full-fidelity executor material, report/export redaction, exploit controls, agent controls, AI provider controls, platform pins, signed trust, production CI gates, clean Linux/Windows runtime evidence, artifact hygiene, package refresh, and report-export-only redaction.
- Preserve `proxyforge-platform-release-parity-evidence-package` artifacts when validating platform or release parity. They prove dense React/Vite navigation, Linux and Windows Electron shell launch, Linux and Windows package artifacts, packaged headless and agent CLIs, packaged runtime proxy/cert/OAST/report smokes, packaged browser routing, Linux install/trust/uninstall proof, Windows install/uninstall proof, explicit Windows trust-store pinning, fast/full release gates, install/operator docs, security review, full-fidelity executor material, and report-export-only redaction.
- Keep `test-results/ci-full-suite-plan.json`, `test-results/ci-full-suite-summary.json`, `test-results/ci-full-suite-history/`, `test-results/ci-full-suite-history/dashboard.json`, `test-results/playwright-artifacts/`, and retained trend history from full/nightly runs. Scheduled CI restores `test-results/ci-full-suite-history/` from the branch-local `proxyforge-full-suite-history-*` cache before execution and saves the refreshed history after runtime runs; plan-only dispatches do not save history. Playwright browser artifacts are isolated under `test-results/playwright-artifacts/` so browser cleanup cannot remove retained runtime summaries. The refreshed plan must include Platform/Release, Platform Shell production, Agent Control production, AI Provider production, Release Security production, Fast Regression production, Full/Nightly production, Full/Nightly retained history, Install Docs production, Windows Package production, Linux Package production, Safety/Enterprise, Project, Proxy listener, Scanner passive, Repeater workspace/desync, Logger parity, Organizer parity, Viewer, Exploit, AI action, and agent CLI evidence before the full/nightly row can move toward Production Ready.
- Preserve `proxyforge-safety-enterprise-parity-evidence-package` artifacts when validating policy parity. They prove scope gates, throttles, request caps, approval gates, override audit, signed governance, SSO mapping/federation fixtures, remote policy transport, backend soak, remote audit retention, full-fidelity executor material, and report-export-only redaction.

## First-Run Checklist

1. Build or install from the current release artifacts described in [INSTALL_LINUX_WINDOWS.md](INSTALL_LINUX_WINDOWS.md).
2. Run `npm run test:ci:fast` before packaging or before trusting a fresh checkout; keep the resulting `test-results/ci-fast-suite-summary.json` with the fast-regression production evidence package.
3. Start ProxyForge and create or open a project.
4. Confirm scope allowlists before any command that sends traffic.
5. Start a loopback proxy listener and capture one HTTP request.
6. Generate a project CA, import it into the isolated browser trust store, and capture one HTTPS request.
7. Launch a managed Chromium/Chrome/Edge/Firefox profile through ProxyForge and confirm browser-routed traffic appears in Proxy history.
8. Export a report preview and confirm submission artifacts redact secrets while operational artifacts remain full fidelity.

## Install And Runtime Proof

Linux operators should keep these commands handy:

```bash
npm run dist:linux
npm run release:smoke:linux
node scripts/release-smoke.mjs --platform linux --artifact release/linux-unpacked/proxyforge --browser-routing --out test-results/release-smoke-linux-browser-routing.json
node scripts/release-smoke.mjs --platform linux --artifact release/linux-unpacked/proxyforge --browser-routing --browser-trust-store --out test-results/release-smoke-linux-browser-trust.json
PROXYFORGE_DOCKER="sudo -n docker" scripts/release-deb-container-smoke.sh --gui --browser-trust
```

Windows operators should keep these commands handy:

```powershell
npm run dist:win
npm run release:smoke:windows
node scripts\release-smoke.mjs --platform windows --artifact release\win-unpacked\ProxyForge.exe --browser-routing --dpapi-cookie --out test-results\release-smoke-windows-browser-dpapi.json
node scripts\release-smoke.mjs --platform windows --artifact "release\ProxyForge Setup 0.1.0-alpha.1.exe" --uninstall --out test-results\release-smoke-windows-installer.json
```

A Windows test runner can provide Windows install, browser-routing, and DPAPI sample-cookie evidence. If that lane rejects temporary current-user Root certificate-store mutation with `ERROR_NOT_SUPPORTED`, record the blocked trusted-CA lane as nonfailed and continue production hardening.

For parity promotion, keep the ignored Platform/Release package from `node tests/platform-release-engine.mjs` under `.gitignored/test-artifacts/platform-release-engine/`. It is the compact handoff for UI QA, package artifacts, release smokes, CI gates, docs, platform pins, and release security review before the final Production Ready host pass. Keep the ignored UI Scale package from `node tests/ui-scale-production-engine.mjs` under `.gitignored/test-artifacts/ui-scale-production-engine/` when reviewing long-project usability; it records responsive overflow checks, stable controls, bounded row windows, and large evidence attachment handling.

For fast-suite production checks, keep the ignored package from `node tests/fast-regression-production-engine.mjs` under `.gitignored/test-artifacts/fast-regression-production-engine/`. It is the compact handoff proving the curated gate itself is broad, current, artifact-backed, and still respecting the full-fidelity executor secret boundary.

For install-docs production checks, keep the ignored package from `node tests/install-docs-production-engine.mjs` under `.gitignored/test-artifacts/install-docs-production-engine/`. It is the compact handoff proving the packaged Linux/Windows install guide, operator guide, release checklist, release evidence, and Codex/Claude/Vantix agent docs match current command surfaces, artifact paths, replay/desync/race/scanner/exploit/OAST workflows, troubleshooting, signoff boundaries, and the report-phase-only redaction rule.

For Windows package production checks, keep the ignored package from `node tests/windows-package-production-engine.mjs` under `.gitignored/test-artifacts/windows-package-production-engine/`. It is the compact handoff proving the Windows NSIS, portable, win-unpacked, installed runtime, browser-routing, DPAPI, uninstall, trust-store pin, and portable-wrapper stdout lanes without reopening the blocked `windows-trust-runner` certificate-store mutation lane.

For Linux package production checks, keep the ignored package from `node tests/linux-package-production-engine.mjs` under `.gitignored/test-artifacts/linux-package-production-engine/`. It is the compact handoff proving AppImage, deb, linux-unpacked, deb metadata/dependencies, packaged headless/agent/runtime/browser lanes, clean-container install/runtime/GUI/trusted-CA/uninstall lanes, and known warning pins.

For Platform Shell production checks, keep the ignored package from `node tests/platform-shell-production-engine.mjs` under `.gitignored/test-artifacts/platform-shell-production-engine/`. It is the compact handoff proving Linux and Windows packaged Electron shell launch, `PROXYFORGE_RELEASE_SMOKE=1` structured payloads, packaged headless and agent CLIs, `~/vantix` style external-cwd app.asar agent execution, packaged runtime proxy/cert/OAST/report lanes, packaged browser routing, Linux and Windows package production gate inputs, accepted trust-store pins, known host-limit pins, and the full-fidelity executor secret boundary.

For Agent Control production checks, keep the ignored package from `node tests/agent-control-production-engine.mjs` under `.gitignored/test-artifacts/agent-control-production-engine/`. It is the compact handoff proving the current 70-command source and packaged command surface, app.asar and external-cwd `~/vantix` runtime behavior, persistent MITM, Chromium/cookie capture, Project Store recovery/backup, Decoder chains, replay, live target profiling, WebSocket list/replay/fuzz/transcript export, Intruder, Repeater desync/race, insertion-point extraction, scanner, Scanner OAST promotion, Anvil, callbacks including provider host proof, exploits, reports, automations including service lifecycle plans and installed-host service smoke, Vantix handoff, policy/audit gates, and long-running soak evidence.

For full/nightly checks, run `npm run test:ci:full -- --plan-only` after changing suite membership and `npm run test:ci:full` before a Production Ready claim. Use `--skip-browser` only for triage; it is not proof that the full browser workflow passed.

## Proxy And Certificate Workflow

- Keep listeners bound to loopback unless the operator intentionally exposes a lab network listener.
- Record proxy port, certificate mode, and project CA fingerprint in assessment notes.
- For HTTP, route the browser or tool to `127.0.0.1:<proxy-port>` and confirm the request appears in Proxy history.
- For base HTTP listener proof, preserve the `proxyforge-proxy-http-listener-capture-package` with raw request and response bytes, method/status counts, body capture, and operational secret signals before any report-phase redaction.
- For advanced history triage, export the `proxyforge-proxy-history-filter-set-package` before relying on saved filters. It should preserve saved predicates, status/method/source/risk/mime/tag coverage, annotation lane counts, raw request/response samples, and operational secret signals until report export.
- For streamed or chunked responses, verify the Proxy history row includes `streamed-response`, `chunked-response` when applicable, captured body samples, total response byte length, and any `capture-truncated` tag before relying on long-lived traffic evidence.
- For HTTP/2 review, keep both the fidelity report and `proxyforge-proxy-http2-multiplexing-report`; verify pseudo-headers, ALPN or h2c markers, stream-id coverage, multiplexed authority buckets, trailers, warning counts, and downgrade/proxy-chain notes before promotion.
- For WebSocket capture, preserve the `proxyforge-websocket-capture-evidence-package` with the 101 upgrade exchange id, bidirectional client/server frame counts, text and binary payload byte accounting, connection summaries, full payload samples, and operational secret signals until report export.
- For WebSocket intercept/rewrite/replay, preserve the `proxyforge-websocket-intercept-rewrite-replay-evidence-package` with client and server intercept decisions, edited-forward frames, dropped frames, live replay frames, saved replay payloads, rewrite rule ids, rewritten replay proof, and full operational payloads until report export.
- For WebSocket state and transcript work, preserve the `proxyforge-websocket-state-transcript-evidence-package` with state graph/filter/export metadata, truncation counts, connection clusters, JSON/Markdown transcript exports, restored transcript frames, large-transcript import counts, and full operational payload samples until report export.
- For Proxy handoff, preserve the `proxyforge-proxy-cross-tool-handoff-package` before switching tools. It should include Repeater raw requests, Scanner candidates with insertion points/check hints, Reports attachment fingerprints, stable exchange ids, and full operational tokens/cookies/keys until report export.
- Before promoting Proxy/HTTPS as parity-ready for agents, preserve the `proxyforge-proxy-edge-profile-package`. It links listener capture, CONNECT tunnel metadata, HTTPS MITM, intercept controls, match/replace, HTTP/2 fidelity and multiplexing, cross-tool handoff, WebSocket edge packages, browser-routing/proxy-chain evidence, package-refresh digests, full-fidelity executor secrets, and report-export-only redaction.
- Before treating browser/proxy-chain diversity as covered, preserve the `proxyforge-proxy-browser-proxy-chain-diversity-package`. It should prove Chromium, Chrome, Edge, and Firefox profiles across Linux and Windows; upstream-auth, CONNECT chain, PAC, and direct proxy modes; project-CA, trusted-CA, manual-import, and pinned-nonblocking certificate modes; HTTP/2, CONNECT, and WebSocket coverage; isolated profile and cookie stores; preserved upstream `Proxy-Authorization` and operational tokens; stale-package checks; and report-export-only redaction.
- For request or response interception, preserve the raw held message, edited message, decision action, synthetic drop response, match/replace rule id, and exported `proxyforge-proxy-intercept-evidence-package` before promoting the exchange into Reports.
- For match/replace libraries, export the `proxyforge-proxy-match-replace-rule-library` package before broad engagement reuse; verify active rule count, direction counts, regex/case-sensitive settings, sample before/after rewrites, and large-rule-set warnings.
- For pass-through CONNECT tunnels, verify the Proxy history row includes client-to-server bytes, server-to-client bytes, total tunnel bytes, tunnel duration, and close reason before treating the capture as parity evidence.
- For upstream proxy-chain work, run or record `mitm-start --upstream-proxy ... --upstream-proxy-authorization ...` and verify HTTP absolute-form requests plus CONNECT pass-through rows include `proxy-chain`, `upstream-proxy:<host>`, preserved `Proxy-Authorization`, byte accounting, and report-export-only redaction.
- For HTTPS, import the project CA into the isolated browser profile trust store. On Linux Chromium lanes, prefer the `--browser-trust-store` smoke so trust is created in a per-run NSS database. On Windows, only mutate `Cert:\CurrentUser\Root` on hosts that permit temporary import and cleanup.
- Do not use `--ignore-certificate-errors` as production trust proof. It is acceptable only as a compatibility or debugging lane.
- If certificate trust fails, export the project CA again, confirm the browser profile path, restart the managed profile, and rerun browser-routing smoke before touching global trust stores.

## Browser And Session Operations

- Use managed browser profiles for capture so ProxyForge controls proxy flags, profile path, and certificate notes.
- Use Chromium/Chrome/Edge for browser-routing evidence and Firefox when validating proxy preference coverage.
- Use cookie extraction only for authorized accounts and assessment-owned profiles.
- Treat extracted cookie headers as executor secrets until report export.
- Refresh authenticated session profiles before replay/scanner work when target state changes.
- Keep profile paths in project notes so agents and operators can resume a capture lane without guessing.
- Preserve `proxyforge-project-parity-evidence-package` artifacts when validating project-level parity. They prove local save/restore, `.proxyforge.json` import/export, schema migration, legacy proxy XML/HAR/JSONL/raw HTTP project imports, session profile restore, managed Linux/Windows browser launch profiles, browser cookie extraction/decryption readiness, full-fidelity executor raw material, and report-export-only redaction.
- Preserve `proxyforge-project-import-compatibility-evidence-package` artifacts when validating imported history from other tools. They prove large mixed legacy proxy XML, HAR, raw HTTP, JSONL, and ProxyForge v1 corpora, merge manifests, duplicate and conflict diagnostics, parser source summaries, package refresh proof, full-fidelity executor raw material, and report-export-only redaction.
- Preserve `proxyforge-project-customer-scale-interop-evidence-package` artifacts when validating customer-scale imported workspaces. They prove 3,000-plus imported exchanges, host/route diversity, duplicate/conflict diagnostics, Search/Viewer/Logger/Target scale, Repeater/Scanner/Intruder handoff counts, report attachment scale, Project Store backup/reopen profile budgets, package refresh proof, full-fidelity executor samples, and report-export-only redaction.
- Preserve `proxyforge-project-customer-workspace-restore-interop-package` artifacts when validating restored customer workspaces. They prove four imported workspace profiles, mixed legacy proxy XML/HAR/raw HTTP/JSONL/ProxyForge corpora, Project Store backup/reopen proof, restored-exchange integrity, Search/Viewer/Logger/Target/Repeater/Scanner/Intruder/report restore counts, full-fidelity raw samples, and report-export-only redaction.

## Traffic Search And Viewing

- Use structured search for high-signal triage: `risk>=medium`, `status:5xx`, `has:secret`, `has:graphql`, `source:repeater`, `tag:authz`.
- Use `semantic:"authz bypass"` or agent `search-index --soak` for large projects where repeated lookup needs a persistent full-fidelity index. Use `search-index --provider-url <rank-endpoint> --execute --scope <provider-host>` only for authorized live semantic/rerank providers; preserve the resulting `proxyforge-agent-search-live-provider-invocation-package` because it contains provider credentials, raw provider request/response material, and the full operational search corpus until report export.
- Use `sequencer-analyze --soak` for captured token corpora that need large-sample reliability, entropy, collision, bit, and position evidence.
- Use the raw view for exact evidence, pretty views for JSON/HTML/GraphQL/JWT triage, and binary/image views when response rendering matters.
- Evidence pins should reference stable exchange ids and report-ready snippets, not screenshots alone.
- Preserve `proxyforge-sequencer-parity-evidence-package` artifacts when validating Sequencer parity. They prove manual, traffic, and browser-preview token collection; cookie/form/custom location extraction; live capture persistence; entropy/collision/position/character/bit/FIPS-style tests; chart backing data; profile comparisons; report-ready exports; 5,000-sample reliability gates; 20,000-sample FIPS-ready cap behavior; full-fidelity token samples; and report-export-only redaction.
- Preserve `proxyforge-search-parity-evidence-package` artifacts when validating Search parity. They prove full-text metadata/body/raw search, structured predicates, negation, OR queries, semantic ranking, provider score merge, persistent local index restore/reuse, large-project soak proof, search-index/view handoff, full-fidelity operational samples, and report-export-only redaction. Preserve `proxyforge-agent-search-live-provider-invocation-package` artifacts when agents use a live provider for ranked lookup.
- Preserve `proxyforge-viewer-parity-evidence-package` artifacts when validating Viewer parity. They prove raw, Pretty JSON, HTML, JWT, GraphQL, image, and binary/hex views, source-aware snapshots, persistent evidence pins, replay comparison exports, report attachment handoff, full-fidelity operational samples, and report-export-only redaction.
- Preserve `proxyforge-logger-parity-evidence-package` artifacts when validating Logger parity. They prove tool-generated traffic capture, capture presets, saved filters/facets, custom column linkage, raw HTTP/HAR/legacy proxy XML/project/plain-text archive imports, mapping presets, conflict/dedupe review, merge strategies, replay receipts, signed provenance, report attachments, redaction policies, full-fidelity raw material, and report-export-only redaction. Preserve `proxyforge-logger-custom-column-compatibility-fixtures` when agents depend on custom Logger columns; it includes the current helper API list, URL/base64/body/JSON helper coverage, package-refresh digests, and operational secret signals without report-phase redaction.
- Preserve `proxyforge-organizer-parity-evidence-package` artifacts when validating Organizer parity. They prove multi-tool collections, notes, statuses, highlights, reviewer assignments, due dates, reviewer SLA exports, CSV/share links, plain and passphrase-sealed packages, HMAC signatures, trust policy review, import diff review, duplicate/conflict routes, all merge modes, conflict audit trails, full-fidelity raw material, operational passphrase/signing-secret preservation, and report-export-only redaction.
- Preserve `proxyforge-analysis-tool-refresh-evidence-package` artifacts when validating Search, Logger, Organizer, Viewer, Sequencer, Decoder, and Comparer together. They link all seven parity packages with package-refresh digests, stale-package checks, full-fidelity raw request/response/token/key material, operational secret samples, and report-export-only redaction.
- Preserve `proxyforge-decoder-parity-evidence-package` and `proxyforge-decoder-golden-corpus-package` artifacts when validating Decoder parity. They prove encode/decode/hash/format transforms, repeatable transform-chain golden cases, recursive recipes, JWT/JWS signing preview, direct AES-GCM JWE decrypt/edit/re-encrypt, binary/hex inspection, transform-library export, report handoff, full-fidelity operational samples, and report-export-only redaction.
- Preserve `proxyforge-comparer-parity-evidence-package` artifacts when validating Comparer parity. They prove line/unified diff, word diff, byte diff, structured HTTP diff, binary/hex comparison, normalization presets, replay/baseline delta review, saved comparison libraries, report-path evidence handoff, full-fidelity operational samples, and report-export-only redaction.

Agent example:

```bash
node scripts/proxyforge-agent.mjs search-index --project ./workspace.proxyforge.json --query authz --out ./artifacts/search-index.json --soak --soak-out ./artifacts/search-soak.json --json
node scripts/proxyforge-agent.mjs sequencer-analyze --sample-file ./tokens.txt --soak --min-samples 5000 --min-reliability reliable --json
node scripts/proxyforge-agent.mjs view --project ./workspace.proxyforge.json --request-id hx-1 --mode raw --json
```

## Replay, Desync, Race, And Intruder

- Start with Repeater plans and single-request replays before bulk or race execution.
- Preserve the `proxyforge-repeater-parity-evidence-package` when validating core Repeater parity. It should prove manual request editing/send, tab groups/workspaces, saved request libraries, snapshots/diffs, session profile injection, authorization matrices, transport controls, bulk replay handoff, linked package-refresh digests, stale-package checks, operational tokens/cookies/headers, and report-export-only redaction.
- For transport-sensitive replay, set `--redirect manual|follow`, `--max-redirects`, `--connection default|close|keep-alive`, and `--timeout` so agents capture the same behavior an operator sees in Repeater.
- For bulk replay, use `bulk-replay --soak` when agents need high-volume proof for concurrency, result retention, request-rate telemetry, and full-fidelity operational response capture.
- For desync testing, run `repeater-desync-plan` first and review parser-differential `queued-followup` evidence, then `repeater-desync-probe --execute` only when scope, target, and request caps are set.
- For race testing, use `repeater-race-run --execute` with bounded `--count`, explicit `--scope`, and recorded synchronization mode. Add `--soak`, `--min-requests`, and release-window budgets when agents need high-concurrency proof.
- Preserve the `proxyforge-repeater-race-desync-production-package` when validating Repeater desync/race hardening. It links parser-differential framing, socket-backed single-connection probes, last-byte race proof, single-packet soak proof, scope-blocked execution, release-skew/race-window budgets, response order, raw transcripts, operational tokens/cookies/keys, package-refresh digests, and report-export-only redaction.
- Preserve raw request/response transcripts, release skew, response order, jitter, and race-window metadata.
- For live target profiling, use `live-target-profile --manifest ./live-targets.json --execute` before broad Scanner/Intruder hardening. Preserve `proxyforge-agent-live-target-profile-package` artifacts when proving scoped host/route/status diversity, Scanner candidates, Intruder marked raw requests, replay handoff commands, bearer tokens, cookies, API keys, and full raw responses.
- For Intruder-style runs, review the dry attack-mode and payload-transformation matrices, then define insertion points, caps, throttles, resource-pool concurrency, checkpoint size, and retained-result windows before launching high-volume jobs. Preserve `proxyforge-intruder-checkpoint-resume-package` artifacts when proving pause/resume queue state, checkpoint offsets, resource-pool state, payload-rule state, and full-fidelity retained result windows. Preserve `proxyforge-intruder-grep-extract-comparison-package` artifacts when triaging grep/extract matches, baseline/candidate deltas, clustered response signatures, statistical rankings, and Scanner promotion context. Preserve `proxyforge-intruder-live-target-profile-package` artifacts when proving live-target diversity, high-volume streaming, checkpoint linkage, grep/extract triage, authz differential status classes, payload transforms, package refresh, and resource-pool concurrency in one profile. Use `intruder-run --soak` when agents need proof that streamed chunks, request-rate telemetry, and bounded result windows held under load.

Agent examples:

```bash
node scripts/proxyforge-agent.mjs replay-run --project ./workspace.proxyforge.json --request-id hx-1 --scope app.example.test --redirect follow --connection keep-alive --timeout 10000 --execute --json
node scripts/proxyforge-agent.mjs bulk-replay --project ./workspace.proxyforge.json --scope app.example.test --limit 50 --concurrency 5 --soak --execute --json
node scripts/proxyforge-agent.mjs live-target-profile --manifest ./live-targets.json --scope app.example.test --execute --json
node scripts/proxyforge-agent.mjs intruder-run --project ./workspace.proxyforge.json --request-id hx-1 --scope app.example.test --payloads admin,user --concurrency 3 --soak --execute --json
node scripts/proxyforge-agent.mjs repeater-desync-probe --project ./workspace.proxyforge.json --request-id hx-1 --scope app.example.test --execute --json
node scripts/proxyforge-agent.mjs repeater-race-run --project ./workspace.proxyforge.json --request-id hx-1 --scope app.example.test --count 12 --sync single-packet --soak --min-requests 12 --max-release-skew-ms 100 --execute --json
```

## Scanner And Crawl Workflow

- Build crawl/content-discovery candidates from captured traffic before active scanning.
- Use `content-discovery-run --execute --soak` for bounded scoped path probing with inherited executor headers, concurrency/throttle telemetry, and full-fidelity response evidence.
- Run `target-access-review` before active authorization claims so role lanes, overexposed/underexposed route decisions, raw exchange ids, and Repeater/Scanner verification commands are captured.
- Run `target-map-compare` when a crawler, import, or role run changes the Target map so added/removed/changed routes, affected parameters, and authz-sensitive deltas are packaged for agents.
- Preserve the `proxyforge-target-parity-evidence-package` when validating Target parity. It should prove URL tree hosts/routes, crawl-path lineage/depth/source, scoped crawler start/scope/request totals, authenticated session profile reuse, refreshed cookies, technology inventory, query/form/path/header/cookie/body insertion points, content-discovery handoff, access-control lanes, site-map comparison, Reports attachment ids, package-refresh digests for every linked Target package, operational secret signals, and report-export-only redaction.
- Keep scanner scope, throttle, max request count, and authorization notes with each run.
- Retest findings after changing scanner calibration or target state.
- Treat noisy error pages, reflected headers, and missing hardening headers as confidence-sensitive findings that need evidence and false-positive notes.
- Preserve the `proxyforge-scanner-passive-dedupe-parity-package` when validating passive Scanner parity. It should prove security headers, cookie flags, CORS, cache controls, mixed content, information disclosure, authz metadata, server errors, exact duplicate and route-variant dedupe, confidence summaries, severity policy normalization, false-positive suppressions, report attachments, active Scanner handoff, full-fidelity raw exchanges, operational secret signals, and report-export-only redaction.
- Preserve the `proxyforge-active-scan-check-pack-evidence-package` when validating built-in Scanner checks or operator check packs. It should prove scope blocking, throttle/max-request controls, supported and unsupported check accounting, all built-in check families, authz two-leg comparison, finding dedupe/confidence, tuning metadata, full-fidelity raw probes, operational secret signals, and report-export-only redaction.
- Preserve the `proxyforge-crawl-audit-insertion-evidence-package` when auditing Target crawler output. It should prove query/form/path insertion coverage, duplicate merge accounting, out-of-scope skips, active Scanner handoff, scope/throttle/max-insertion controls, raw probe samples, operational secret signals, and report-export-only redaction.
- Use `scanner-run --soak` when agents need live calibration evidence with false-positive controls, suppressed-finding counts, dedupe keys, and full-fidelity seed exchange material.
- Preserve the `proxyforge-scanner-retest-evidence-delta-package` when validating remediation. It should link the issue, baseline proof, retest proof, fixed/regressed/still-vulnerable/inconclusive outcome history, request edits, runner controls, raw exchange samples, operational secret signals, and report-export-only redaction.
- Preserve the `proxyforge-anvil-custom-check-parity-package` when validating Anvil custom scan checks. It should link the plain-text `.anvil` definition, reusable rule library, positive/negative fixtures, fixture validation, custom-only headless run, signed package review, Scanner finding handoff, Reports attachments, full-fidelity raw samples, operational secret signals, and report-export-only redaction.
- Preserve the `proxyforge-scanner-active-scan-evidence-package` when promoting active checks. It links the scan plan, insertion-point review, authenticated-state matrix, replay-derived checks, CI/headless command, report attachment manifest, active/suppressed finding status, raw request/response samples, and operational secret signals; redaction is report-export-only.
- Preserve the `proxyforge-scanner-live-target-profile-package` when validating Scanner production-hardening evidence. It links passive dedupe, insertion inventory, active scan evidence, OAST issue promotion, Anvil compatibility, retest deltas, calibration soak packages, target host/route/status diversity, check-family coverage, false-positive tuning controls, package-refresh digests, stale-package checks, full-fidelity executor material, and report-export-only redaction.
- Export active-scan evidence packages into reports only after verifying issue confidence and affected assets.

Agent examples:

```bash
node scripts/proxyforge-agent.mjs content-discovery-plan --project ./workspace.proxyforge.json --scope app.example.test --json
node scripts/proxyforge-agent.mjs content-discovery-run --project ./workspace.proxyforge.json --scope app.example.test --limit 40 --concurrency 4 --soak --execute --json
node scripts/proxyforge-agent.mjs target-access-review --project ./workspace.proxyforge.json --roles customer,support_admin --json
node scripts/proxyforge-agent.mjs target-map-compare --project ./workspace.proxyforge.json --baseline hx-1 --candidate hx-1,hx-2 --json
node scripts/proxyforge-agent.mjs crawl-run --target https://app.example.test --scope app.example.test --depth 2 --pages 20 --execute --json
node scripts/proxyforge-agent.mjs scanner-plan --project ./workspace.proxyforge.json --scope app.example.test --check-pack full-active --json
node scripts/proxyforge-agent.mjs scanner-run --project ./workspace.proxyforge.json --scope app.example.test --check-pack full-active --max-requests 13 --execute --soak --min-requests 13 --min-findings 1 --json
```

`status.data.scannerCatalog` is the agent-facing source of truth for active Scanner checks and packs. Use `--check-pack baseline` for low-noise hardening checks, `--check-pack input-attacks` for reflected XSS, SQL injection, path traversal, open redirect, and command injection probes, and `--check-pack full-active --max-requests 13` only when the operator has approved the full built-in pack.

## Automations And CI

- Use `automation-list` before running macros or scheduled workflows so agents can inspect workflow ids, scope, request caps, approval requirements, and scheduler queue state.
- Use `automation-run --execute` only with explicit scope; state-changing workflow steps must either have an approval artifact or remain blocked.
- Use `automation-scheduler-tick --execute` for agent-driven scheduler service runs. Preserve queue leases, completion/block receipts, heartbeat metadata, and restored state when handing off long-running automation work.
- Use `automation-ci-export` to produce GitHub Actions, GitLab CI, Azure Pipelines, and Jenkins headless scanner presets with SARIF, JUnit, report bundle, artifact upload, and secret environment handling.
- Use `automation-service-plan` to generate Linux systemd user and Windows Task Scheduler service lifecycle packages before installing a durable background scheduler. Preserve install/start/status/stop/uninstall commands, manifests, scheduler tick commands, durable state/log paths, and secret environment names.
- Use `automation-service-smoke --execute` after lifecycle planning or host setup to prove an installed-host detached Node runner can start, produce durable status/state/log files, tick the scheduler, answer status, and stop cleanly. Preserve PID lifecycle evidence, JSONL log lines, scheduler state, and operational token/cookie/key samples until report export.
- Preserve `proxyforge-automation-parity-evidence-package`, `proxyforge-agent-automation-parity-evidence-package`, `proxyforge-automation-service-lifecycle-package`, or `proxyforge-automation-service-installed-host-smoke-package` artifacts when validating Automation parity. They prove macro recording, scheduled/on-tag/CI workflows, scoped execution, approval blocking, durable scheduler queues, lease recovery, scheduler restore, service lifecycle states, OS service lifecycle plans, installed-host service start/status/stop smoke, CI/headless provider presets, full-fidelity operational raw material, and report-export-only redaction.

Agent examples:

```bash
node scripts/proxyforge-agent.mjs automation-list --project ./workspace.proxyforge.json --json
node scripts/proxyforge-agent.mjs automation-run --project ./workspace.proxyforge.json --workflow wf-nightly --scope app.example.test --execute --json
node scripts/proxyforge-agent.mjs automation-scheduler-tick --project ./workspace.proxyforge.json --scope app.example.test --execute --json
node scripts/proxyforge-agent.mjs automation-ci-export --project ./workspace.proxyforge.json --workflow wf-nightly --provider github-actions,gitlab-ci,azure-pipelines,jenkins --json
node scripts/proxyforge-agent.mjs automation-parity-export --project ./workspace.proxyforge.json --out ./artifacts/automation-parity.json --json
node scripts/proxyforge-agent.mjs automation-service-plan --project ./workspace.proxyforge.json --workflow wf-nightly --out ./artifacts/automation-service-lifecycle.json --json
node scripts/proxyforge-agent.mjs automation-service-smoke --project ./workspace.proxyforge.json --workflow wf-nightly --service-dir ./.gitignored/automation-service-smoke --execute --json
```

## AI Providers And Actions

- Configure Codex and Claude providers as CLI integrations and the local provider as an OpenAI-compatible `/v1/chat/completions` endpoint. Provider runs must keep the full prompt context, raw request and response material, scope, stream telemetry, token/cost accounting, and suggested Repeater/Scanner/Exploit/Report actions available for executor use.
- Preserve `proxyforge-ai-provider-production-evidence-package` artifacts when validating AI provider production readiness. They prove Codex CLI provider, Claude CLI provider, OpenAI-compatible HTTP provider, provider config persistence, streaming telemetry, token/cost accounting, prompt library, baseline/comparison/benchmark coverage, controlled actions, scope blocking, no direct action traffic, package refresh, long-run profiling, docs/schemas, full-fidelity operational samples, and report-export-only redaction.
- Preserve `proxyforge-ai-parity-evidence-package` artifacts when validating AI parity. They prove Codex provider coverage, Claude provider coverage, OpenAI-compatible local provider coverage, CLI and HTTP execution, streaming telemetry, prompt evaluations, templates, baselines, comparisons, benchmark replay, token/cost accounting, controlled actions, scope blocking, full-fidelity operational samples, and report-export-only redaction.
- Treat `proxyforge-ai-action-execution` packages as UI-controlled execution receipts. They can stage Repeater workspaces, replay matrices, Scanner queue items, Exploit Lab dry-run reviews, automation handoffs, and report drafts, but they do not send traffic directly; scoped backends execute later with their own gates.

## Extensions

- Use signed or local manifests for extension workspaces and keep dependency review metadata with each run.
- Run compatibility fixtures before trusting migrated legacy proxy-compatible extensions in scanner, editor, or listener workflows.
- Preserve request listener, response listener, scanner check, insertion-point provider, editor tab, context menu, session token refresh, helper transform, third-party SDK edge, and policy-denied callback evidence until report export.
- Preserve `proxyforge-extension-parity-evidence-package` artifacts when validating Extensions parity. They prove catalog and local manifest installs, enable/disable run logs, sandboxed request/response/editor/scanner/headless hooks, legacy compatibility fixtures, third-party extension SDK edge packages, dependency review, headless CI evidence, signed manifests, signed updates, runtime diagnostics, evidence handoffs, full-fidelity raw material, and report-export-only redaction.
- Preserve `proxyforge-extension-third-party-sdk-compatibility-package` artifacts when validating broader third-party extension SDK compatibility. They prove extension package/local/agent profile diversity, `IHttpRequestResponse` mutation and annotations, `IExtensionHelpers` transforms, multi-message context menus, session token refresh, scanner insertion points, editor/state lifecycle cleanup, fail-closed unsupported APIs, manifest/dependency migration edges, package refresh digests, full-fidelity operational secrets, and report-only redaction.

Agent example:

```bash
node scripts/proxyforge-agent.mjs extension-fixtures --project ./workspace.proxyforge.json --manifest ./extension.json --request-id hx-1 --json
```

## Collaborator And OAST

- Use local DNS/HTTP/SMTP listeners for controlled callback proof when possible.
- Keep payload ownership, listener binding, public relay plan, interaction ids, and retention window in the callback workspace.
- Prune expired interactions with a retention-prune manifest before archiving.
- Use callback replay to link observed interactions back to Repeater, Scanner, or Exploit Lab evidence.
- Use `callback-provider-probe` when an external OAST provider is authorized; include the provider host in scope and preserve signed poll raw requests/responses plus bearer tokens until report export.
- Do not redact callback tokens from operational replay manifests; report export handles submission redaction.
- Preserve `proxyforge-collaborator-parity-evidence-package` artifacts when validating OAST parity. They prove DNS/HTTP/SMTP payload generation, signed poll batches, OAST workspace ownership, signed callback evidence, local listener backend planning, public relay soak, signed tenant-isolated external relay packages, external provider diversity packages, callback report round-trip packages, retention pruning, callback replay execution across Repeater/Scanner/Exploit Lab, report-package persistence, full-fidelity callback tokens/keys, and report-export-only redaction.
- Preserve `proxyforge-collaborator-package-refresh-evidence-package` artifacts when validating OAST package freshness. They link Collaborator parity, signed polling, replay correlation, replay execution, lifecycle/retention, CI handoff, public relay soak, signed external relay, provider diversity, scoped provider-host proof, and report round-trip packages with package-refresh digests, stale-package checks, full-fidelity callback/provider secrets, and report-export-only redaction.

Agent examples:

```bash
node scripts/proxyforge-agent.mjs callback-poll --workspace ./callbacks.json --json
node scripts/proxyforge-agent.mjs callback-provider-probe --providers ./oast-providers.json --scope callbacks.example.test --execute --json
node scripts/proxyforge-agent.mjs callback-relay-plan --workspace ./callbacks.json --public-base callbacks.example.test --json
node scripts/proxyforge-agent.mjs callback-relay-soak --workspace ./callbacks.json --public-base callbacks.example.test --json
node scripts/proxyforge-agent.mjs callback-retention-prune --workspace ./callbacks.json --retention-hours 72 --json
node scripts/proxyforge-agent.mjs callback-replay --workspace ./callbacks.json --target repeater,scanner,exploit-lab --scope app.example.test --json
```

## Exploit Lab Safety

- Use previews for exploit validation planning.
- Live exploit execution requires explicit approval JSON, target scope match, request cap, stop-on-proof behavior, and audit output.
- Keep destructive-class actions excluded unless an operator adds an approved, program-specific bypass artifact.
- Callback-assisted exploit validation must prove callback ownership before linking evidence into reports.
- Preserve `proxyforge-exploit-parity-evidence-package` artifacts when validating Exploit Lab parity. They prove PoC templates, non-destructive previews, approval/scope/stop-on-proof gates, saved chains, callback-assisted validation, report-ready packages, digest review/compare/import, Repeater backend execution, full-fidelity operational raw material, and report-export-only redaction.
- Preserve `proxyforge-exploit-package-refresh-evidence-package` artifacts when validating Exploit Lab freshness. They link parity, backend execution, saved chain, report package, review/import, comparison, and callback-validation proof with stale-package checks, destructive-class exclusion, full-fidelity operational material, and report-export-only redaction.

Agent example:

```bash
node scripts/proxyforge-agent.mjs exploit-preview --project ./workspace.proxyforge.json --request-id hx-1 --json
node scripts/proxyforge-agent.mjs exploit-run --project ./workspace.proxyforge.json --request-id hx-1 --scope app.example.test --approve ./approval.json --execute --json
```

## Reporting And Submission

- Build reports from verified findings, evidence pins, replay transcripts, OAST interactions, scanner evidence, and exploit packages.
- Generate JSON, Markdown, HTML, PDF, and signed bundle outputs when the program or customer needs different formats.
- Use report exports for redaction. Operational artifacts are intentionally full fidelity and are not submission-safe by default.
- Verify bundle signatures before handoff and keep bundle verification output with release evidence.
- Confirm generated PDFs are nonblank, page breaks are sane, and large evidence sections remain readable.
- Preserve the `proxyforge-report-parity-evidence-package` when validating report readiness. It proves Markdown/HTML/JSON/PDF/bundle rendering, signed bundle verification and tamper rejection, executive/technical/remediation/evidence/appendix coverage, custom operator template rendering, cross-tool evidence attachment inclusion, PDF render QA metadata, and report-phase-only redaction of executor secrets.
- Preserve the `proxyforge-report-production-readiness-package` before promoting Reports toward production. It proves renderer comparison, local and external signed-bundle verification, JSON-stable bundle canonicalization, semantic PDF accessibility/tag readiness, long-project report scale, large-PDF warnings, full-fidelity executor inputs before export, and report-export redaction.
- Preserve the `proxyforge-report-external-bundle-diversity-package` when sharing evidence across portals, customer GRC systems, partner MSSPs, or remediation boards. It proves four external recipient/channel/key/template profiles, digest-only no-secret review, canonical JSON round trips, tamper rejection, cross-tool attachment diversity, and report-phase-only redaction while executor artifacts remain full fidelity before report export.
- Preserve the `proxyforge-report-template-library-interop-package` when importing or exporting operator report templates. It proves template library export, import, duplicate conflict review with renamed imports, built-in and custom template rendering, variable resolution, Markdown/HTML/bundle render hashes, and report-phase-only redaction.
- Decoder and Comparer parity packages are operational evidence, not submission artifacts. Keep tokens, cookies, keys, JWE material, raw requests, raw responses, and comparison bodies intact there; redaction starts only when report export or bundle commands generate submission material.

Agent examples:

```bash
node scripts/proxyforge-agent.mjs report-preview --project ./workspace.proxyforge.json --json
node scripts/proxyforge-agent.mjs report-export --project ./workspace.proxyforge.json --format markdown --out ./reports --json
node scripts/proxyforge-agent.mjs bundle-sign --project ./workspace.proxyforge.json --out ./reports --json
node scripts/proxyforge-agent.mjs bundle-verify --bundle ./reports/proxyforge-bundle.json --json
```

## Agentic Operation

Codex CLI, Claude CLI, and Vantix agents should use `scripts/proxyforge-agent.mjs` rather than scraping the GUI. The CLI emits a stable `proxyforge-agent-result` envelope with `status`, `mode`, `safety`, `data`, `artifacts`, and `audit`.

- Use `status`, `inventory`, `evidence-list`, and `findings-list` for read-only polling.
- Use `mitm-start --ensure-ca --upstream-tls strict|relaxed`, `mitm-status`, `mitm-export`, and `mitm-stop` for persistent capture, and preserve the returned project-CA fingerprint, root certificate path, and upstream TLS mode in the operator notes.
- Use `chromium-capture`, `cookie-capture`, `proxy-import`, `crawl-run`, `content-discovery-plan`, and `content-discovery-run` for gathering. `proxy-import` accepts ProxyForge JSONL/project exports, HAR, legacy proxy XML history, and raw HTTP text archives with full headers, cookies, tokens, API keys, and raw request/response bodies intact until report export.
- Use `target-access-review` and `target-map-compare` for role visibility, access-control lane review, and baseline/candidate Target drift before launching active authz probes.
- Use `search`, `search-index --soak`, `sequencer-analyze --soak`, and `view` for triage.
- Use replay, Intruder, scanner, callback, and exploit commands only with explicit scope and approvals where required.
- Use `vantix-sync`, `vantix-intel-export`, and `vantix-report-import` for `~/vantix/` handoff.

External runner example:

```bash
cd ~/vantix
node ~/proxyforge/scripts/proxyforge-agent.mjs status --project ~/proxyforge/workspace.proxyforge.json --json
node ~/proxyforge/scripts/proxyforge-agent.mjs chromium-capture --project ~/proxyforge/workspace.proxyforge.json --target https://app.example.test --scope app.example.test --json
```

## Recovery And Troubleshooting

Proxy listener does not receive traffic:

- Confirm the browser/tool proxy is set to `127.0.0.1:<proxy-port>`.
- Confirm the listener is bound and not blocked by another process.
- Restart the managed browser profile after changing proxy settings.
- Check whether a VPN, PAC file, or OS proxy setting is overriding the isolated profile.

HTTPS shows certificate errors:

- Confirm the project CA was generated for the current project.
- Reimport the CA into the isolated browser trust store.
- Restart the browser profile and clear cached certificate decisions.
- On Windows, record a blocked trusted-CA lane if current-user Root mutation is unsupported, then continue with browser-routing and DPAPI proof.

Scanner or replay sends no traffic:

- Confirm `--execute` is present for active agent commands.
- Confirm the target host matches `--scope`.
- Check request caps, throttles, stop-on-proof, and approval artifacts.
- Use Repeater single-request replay before launching a matrix, scanner, or exploit validation run.

Reports redact too much or too little:

- Check whether the command is an operational command or a report/submission command.
- Operational commands should preserve executor secrets.
- Report commands should redact submission artifacts while keeping evidence ids, host/path, finding details, and remediation text useful.

Packaged app will not launch:

- Run the relevant `release-smoke` command and inspect the JSON check that failed.
- On Linux deb lanes, confirm Electron runtime dependencies such as `libgbm1` and `libasound2`.
- On headless Linux, use Xvfb-backed smoke rather than manual GUI launch.
- On Windows, separate unpacked GUI smoke, NSIS install smoke, browser-routing smoke, and DPAPI smoke so one blocked host lane does not hide unrelated pass/fail evidence.
- For platform/release status drift, regenerate `proxyforge-platform-release-parity-evidence-package` and compare its requirement booleans before editing the matrix.

Release trust drift:

- Run `npm run release:trust` after rebuilding release candidates to regenerate SBOM, SHA-256 checksums, and provenance manifests under `test-results/release-trust/`.
- Preserve `proxyforge-release-trust-production-evidence-package` artifacts when validating release trust. They prove package-lock-derived SBOM, dependency integrity, license/dependency review policy, source/build/docs/workflow SHA-256 checksums, SLSA-lite provenance, signing/notarization state pins, verification commands, artifact retention, full-fidelity executor material, and report-export-only redaction.
- Treat unsigned local/internal artifacts as pinned, not silently trusted. Public or customer distribution must attach the selected signing/notarization evidence before final handoff.

## Production Signoff

Before calling a build Production Ready, current evidence must show:

- Fast and full/nightly regression metadata are current.
- Fast Regression production evidence is current and matches the latest `npm run test:ci:fast` run.
- Install Docs production evidence is current and matches the packaged install, operator, release, and agent docs.
- Windows Package production evidence is current, and the `windows-trust-runner` trust-store limitation is explicitly pinned as nonblocking.
- Linux Package production evidence is current, and clean-container trusted-CA browser capture is the counted Linux browser trust proof.
- Platform/Release parity evidence is current for the exact build being promoted.
- Release Security production evidence is current and matches the formal zero-warning review, local listener, secret-boundary, exploit-control, agent/AI-control, platform-pin, signed-trust, production-CI, clean-runtime, artifact-hygiene, and package-refresh proof.
- Release Trust production evidence is current and matches the exact SBOM, SHA-256 checksums, provenance, signing/notarization state, verification commands, retained artifacts, and report-export-only redaction boundary for the build being promoted.
- Linux package lane has build, install, runtime, browser-routing, trusted-CA, packaged headless scan/report, packaged agent, packaged runtime proxy/cert/OAST/report, and report export proof.
- Windows package lane has build, install/uninstall, packaged GUI, browser-routing, DPAPI cookie, packaged headless scan/report, packaged agent, packaged runtime proxy/cert/OAST/report, and report export proof, with OS/browser trust-store capture either passed or explicitly pinned as nonblocking by host constraints.
- Operator docs, agent docs, release checklist, release evidence, and install guide match the actual commands and artifact paths.
- Submission reports redact secrets, while operational executor artifacts remain full fidelity until reporting.
