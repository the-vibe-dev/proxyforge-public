# Codex Agent Contract

Codex agents should call ProxyForge through `scripts/proxyforge-agent.mjs` instead of scraping the GUI. Operational commands emit full-fidelity JSON by default, including tokens, keys, cookies, headers, and raw traffic needed for execution. Active workflows require explicit scope plus `--execute` or an approval file, and report/bundle commands redact during submission output.

## Core Flow

```bash
node scripts/proxyforge-agent.mjs status --project ./workspace.proxyforge.json --json
node scripts/proxyforge-agent.mjs mitm-start --project ./workspace.proxyforge.json --session-dir ./agent-session --port 8080 --scope app.example.test --ensure-ca --upstream-tls strict --json
node scripts/proxyforge-agent.mjs search --project ./workspace.proxyforge.json --query authz --json
node scripts/proxyforge-agent.mjs search-index --project ./workspace.proxyforge.json --query authz --out ./artifacts/search-index.json --soak --soak-out ./artifacts/search-soak.json --json
node scripts/proxyforge-agent.mjs search-index --project ./workspace.proxyforge.json --query "authz bypass" --provider-url http://127.0.0.1:9000/rank --provider-token "$SEARCH_PROVIDER_TOKEN" --scope 127.0.0.1 --execute --provider-out ./artifacts/search-provider.json --json
node scripts/proxyforge-agent.mjs sequencer-analyze --sample-file ./tokens.txt --soak --min-samples 5000 --min-reliability reliable --json
node scripts/proxyforge-agent.mjs decoder-chain --project ./workspace.proxyforge.json --request-id hx-1 --source response --transforms base64-decode,json-pretty --json
node scripts/proxyforge-agent.mjs proxy-import --file ./agent-session/exchanges.jsonl --json
node scripts/proxyforge-agent.mjs proxy-import --file ./legacy-proxy-history.xml --json
node scripts/proxyforge-agent.mjs project-store-status --store ./workspace.proxyforge --json
node scripts/proxyforge-agent.mjs project-store-recover --store ./workspace.proxyforge --out ./artifacts/project-store-recovery.json --json
node scripts/proxyforge-agent.mjs project-store-backup --store ./workspace.proxyforge --out ./.gitignored/proxyforge-backups --execute --json
node scripts/proxyforge-agent.mjs content-discovery-plan --project ./workspace.proxyforge.json --scope app.example.test --json
node scripts/proxyforge-agent.mjs content-discovery-run --project ./workspace.proxyforge.json --scope app.example.test --limit 40 --concurrency 4 --soak --execute --json
node scripts/proxyforge-agent.mjs live-target-profile --manifest ./live-targets.json --scope app.example.test --execute --json
node scripts/proxyforge-agent.mjs target-access-review --project ./workspace.proxyforge.json --roles customer,support_admin --json
node scripts/proxyforge-agent.mjs target-map-compare --project ./workspace.proxyforge.json --baseline hx-1 --candidate hx-1,hx-2 --json
node scripts/proxyforge-agent.mjs automation-list --project ./workspace.proxyforge.json --json
node scripts/proxyforge-agent.mjs automation-run --project ./workspace.proxyforge.json --workflow wf-nightly --scope app.example.test --execute --json
node scripts/proxyforge-agent.mjs automation-scheduler-tick --project ./workspace.proxyforge.json --scope app.example.test --execute --json
node scripts/proxyforge-agent.mjs automation-parity-export --project ./workspace.proxyforge.json --out ./artifacts/automation-parity.json --json
node scripts/proxyforge-agent.mjs automation-service-plan --project ./workspace.proxyforge.json --workflow wf-nightly --out ./artifacts/automation-service-lifecycle.json --json
node scripts/proxyforge-agent.mjs automation-service-smoke --project ./workspace.proxyforge.json --workflow wf-nightly --service-dir ./.gitignored/automation-service-smoke --execute --json
node scripts/proxyforge-agent.mjs crawl-run --target https://app.example.test --scope app.example.test --execute --json
node scripts/proxyforge-agent.mjs replay-run --project ./workspace.proxyforge.json --request-id hx-1 --scope app.example.test --redirect follow --connection keep-alive --timeout 10000 --execute --json
node scripts/proxyforge-agent.mjs bulk-replay --project ./workspace.proxyforge.json --scope app.example.test --limit 50 --concurrency 5 --soak --execute --json
node scripts/proxyforge-agent.mjs intruder-run --project ./workspace.proxyforge.json --request-id hx-1 --scope app.example.test --payloads admin,user --concurrency 3 --soak --execute --json
node scripts/proxyforge-agent.mjs repeater-desync-probe --project ./workspace.proxyforge.json --request-id hx-1 --scope app.example.test --execute --json
node scripts/proxyforge-agent.mjs repeater-race-run --project ./workspace.proxyforge.json --request-id hx-1 --scope app.example.test --count 12 --sync single-packet --soak --min-requests 12 --max-release-skew-ms 100 --execute --json
node scripts/proxyforge-agent.mjs insertion-points --project ./workspace.proxyforge.json --request-id hx-1 --out ./artifacts/insertion-points.json --json
node scripts/proxyforge-agent.mjs websocket-list --project ./workspace.proxyforge.json --connection-id ws-conn-1 --json
node scripts/proxyforge-agent.mjs websocket-replay --project ./workspace.proxyforge.json --frame-id ws-1 --scope app.example.test --execute --json
node scripts/proxyforge-agent.mjs websocket-fuzz --project ./workspace.proxyforge.json --frame-id ws-1 --scope app.example.test --max-probes 6 --execute --json
node scripts/proxyforge-agent.mjs websocket-transcript-export --project ./workspace.proxyforge.json --connection-id ws-conn-1 --format markdown --out ./artifacts/websocket-transcript.md --json
node scripts/proxyforge-agent.mjs scanner-plan --project ./workspace.proxyforge.json --request-id hx-1 --check-pack full-active --json
node scripts/proxyforge-agent.mjs scanner-run --project ./workspace.proxyforge.json --request-id hx-1 --scope app.example.test --check-pack full-active --max-requests 13 --execute --soak --min-requests 13 --min-findings 1 --json
node scripts/proxyforge-agent.mjs scanner-retest --project ./workspace.proxyforge.json --issue issue-1 --request-id hx-1 --retest-id hx-2 --json
node scripts/proxyforge-agent.mjs scanner-evidence-export --project ./workspace.proxyforge.json --issue issue-1 --request-id hx-1 --out ./artifacts/scanner-evidence.json --json
node scripts/proxyforge-agent.mjs scanner-oast-promote --project ./workspace.proxyforge.json --workspace ./callbacks.json --request-id hx-1 --payload-id cb-1 --interaction-id int-1 --out ./artifacts/scanner-oast-issue.json --json
node scripts/proxyforge-agent.mjs anvil-plan --project ./workspace.proxyforge.json --request-id hx-1 --json
node scripts/proxyforge-agent.mjs anvil-run --project ./workspace.proxyforge.json --request-id hx-1 --execute --json
node scripts/proxyforge-agent.mjs anvil-package-export --project ./workspace.proxyforge.json --request-id hx-1 --out ./artifacts/anvil-package.json --json
node scripts/proxyforge-agent.mjs extension-fixtures --project ./workspace.proxyforge.json --manifest ./extension.json --request-id hx-1 --json
node scripts/proxyforge-agent.mjs callback-relay-plan --workspace ./callbacks.json --public-base callbacks.app.example.test --json
node scripts/proxyforge-agent.mjs callback-provider-probe --providers ./oast-providers.json --scope callbacks.app.example.test --execute --json
node scripts/proxyforge-agent.mjs callback-relay-soak --workspace ./callbacks.json --public-base callbacks.app.example.test --json
node scripts/proxyforge-agent.mjs callback-retention-prune --workspace ./callbacks.json --retention-hours 72 --json
node scripts/proxyforge-agent.mjs report-export --project ./workspace.proxyforge.json --format markdown --out ./reports --json
```

## Rules

- Treat `status: blocked` as a hard stop unless the operator expands scope or supplies approval.
- Use `mitm-start` as a foreground persistent session when Codex needs ongoing proxy capture. Use `--ensure-ca` when HTTPS capture is expected, choose `--upstream-tls strict|relaxed` deliberately, and keep the returned `proxyUrl`, `statusPath`, `logPath`, and `httpsInspection.certificate` details.
- Treat operational output and session directories as sensitive executor material. Use `report-export` or `bundle-sign` when a redacted submission artifact is needed.
- Use `search-index --provider-url --execute` only for authorized semantic/rerank providers. Preserve `proxyforge-agent-search-live-provider-invocation-package`, provider raw requests/responses, provider credentials, full corpus documents, and provider-ranked handoffs until report export.
- Use `chromium-capture` for managed browser launch plans before live browser capture.
- Use `sequencer-analyze --soak` for captured token corpora. Preserve `data.samples`, `data.result.reliability`, statistical tests, bit/position stats, and `data.soakPackage` until a report command redacts submission material.
- Use `decoder-chain` for repeatable selected-message or inline transforms. Preserve `data.run.steps`, `data.finalOutput`, `data.package.content`, compact JWT/JWE values, decoded bodies, and operational tokens/keys/cookies until a report command redacts submission material.
- Use `proxy-import` to ingest MITM JSONL, HAR, legacy proxy XML history, raw HTTP text archives, or ProxyForge project history, then `content-discovery-plan`, `content-discovery-run --execute --soak`, and `crawl-run --execute` for scoped route gathering. Imported headers, cookies, tokens, API keys, and raw request/response bodies remain full fidelity until report export.
- Use `project-store-status`, `project-store-recover`, and `project-store-backup --execute` when Codex needs durable Project Store v2 recovery or restore points. Preserve recovery journals, sample raw exchanges, restore-point manifests, bearer tokens, cookies, API keys, and callback tokens until report export.
- When crawl-derived Scanner audit evidence is available, preserve `proxyforge-crawl-audit-insertion-evidence-package` fields: query/form/path coverage, duplicate merges, out-of-scope skips, active Scanner handoff, raw probe samples, operational secret signals, and `reportRedactionBoundary`.
- Use `target-access-review` before claiming an authorization issue; preserve role lanes, route decisions, overexposed/underexposed counts, and linked raw exchanges, then verify suspicious routes with `replay-matrix` or `scanner-run --checks authz-diff`.
- Use `live-target-profile` when Codex needs broader authorized live-target proof before Scanner/Intruder hardening. Preserve `proxyforge-agent-live-target-profile-package`, status-class diversity, Scanner candidates, Intruder marked raw requests, bearer tokens, cookies, API keys, and raw responses until report export.
- Use `target-map-compare` before treating new routes as parity coverage; preserve status/MIME/method/host/parameter/authz deltas, affected parameters, raw exchanges, and digest evidence.
- Use `automation-list`, `automation-run --execute`, `automation-scheduler-tick --execute`, `automation-ci-export`, `automation-parity-export`, `automation-service-plan`, and `automation-service-smoke --execute` when Codex needs to drive macros, scheduled workflows, CI/headless presets, durable scheduler leases, Automation parity packages, OS service install/start/status/stop/uninstall plans, or installed-host scheduler start/status/stop smoke proof. Preserve approval-block receipts, scheduler queue receipts, service manifests, status files, JSONL logs, and full-fidelity operational raw material until report export.
- Use `replay-run` transport flags when status depends on redirect, timeout, or connection behavior; preserve `data.transportSettings`, `data.response.redirectHistory`, `data.response.finalUrl`, and timeout errors.
- Use `bulk-replay --soak` for high-volume Repeater batches that need concurrency, request-rate telemetry, retained response windows, and full-fidelity replay evidence.
- Use `intruder-run` for payload-position fuzzing, authorization probes, and high-volume streamed result windows. Start planned and inspect `data.plan.attackModeMatrix` plus `payloadTransformations` for Sniper/Battering Ram/Pitchfork/Cluster Bomb expansion counts, recursive rule expansion, processor output, and sample raw requests, then add `--execute --soak` with explicit `--scope`, caps, and `--concurrency` when sending traffic.
- Use `repeater-desync-plan` before live request-smuggling work and preserve `data.plan.parserDifferential` with parser profiles, queued-followup signals, and leftover previews. Use `repeater-desync-probe --execute` for single-connection evidence and `repeater-race-run --execute --soak` for last-byte or single-packet race proofing with request-count and release-skew budgets.
- Use `insertion-points` before Scanner/Intruder planning when history is raw or imported. Preserve query, path, header, cookie, form, JSON, XML, multipart, and GraphQL candidates plus raw executor tokens/keys/cookies until report export.
- Use `websocket-list`, `websocket-replay --execute`, `websocket-fuzz --execute`, and `websocket-transcript-export` for WebSocket work. Preserve selected frame ids, live handshake proof, response frames, fuzz probe outcomes, JSON/Markdown transcripts, and full text/binary payload tokens/keys/cookies until report export.
- For Scanner check-pack parity, preserve `proxyforge-active-scan-check-pack-evidence-package` output when available: supported/unsupported checks, all built-in check coverage, scope/rate/cap gates, authz two-leg comparison, raw probe samples, operational secret signals, and report-export-only redaction.
- Read `status.data.scannerCatalog` before choosing active checks. Prefer `--check-pack baseline` for low-noise triage, `--check-pack input-attacks` for reflected XSS/SQL/path/open-redirect/command-injection probes, and `--check-pack full-active --max-requests 13` when the operator has approved the full built-in pack.
- Use `scanner-run --soak` for live scanner calibration evidence. Preserve `data.calibrationPackage`, false-positive controls, suppressed findings, dedupe keys, and full seed exchange material until report export.
- Use `scanner-retest` and `scanner-evidence-export` when validating remediation. Preserve `proxyforge-scanner-retest-evidence-delta-package` fields for baseline proof, retest proof, request edits, outcome coverage, raw exchange samples, operational secret signals, and report-export-only redaction.
- Use `scanner-oast-promote` after `scanner-run --checks oast-ssrf` and `callback-poll` when a callback is observed. Preserve `proxyforge-scanner-oast-issue-promotion-package` source/scanner exchanges, callback payload, callback interaction, issue draft, raw material, retest commands, and report-export-only redaction.
- When active Scanner evidence is exported, preserve the `proxyforge-scanner-active-scan-evidence-package` fields: plan id, insertion-point review id, authenticated-state matrix id, replay check package id, CI command, report attachments, active/suppressed finding status, raw exchange samples, and `secretHandling`.
- Use `anvil-plan`, `anvil-run --execute`, and `anvil-package-export` for Anvil custom scan-check parity. Preserve the `.anvil` source, reusable rule library, positive/negative fixtures, fixture validation, custom-only headless run, signed package review, Scanner handoff, Reports attachments, raw exchange samples, operational secret signals, and report-export-only redaction.
- Use `extension-fixtures` before relying on migrated legacy proxy-compatible extensions; preserve request listener, scanner check, editor tab, helper transform, multi-message context menu, session token refresh, insertion-point, package-refresh, and policy-denied evidence as operational output until report export.
- Use `callback-relay-plan` before public OAST relay deployment, `callback-provider-probe` for scoped external OAST provider host proof, `callback-relay-soak` to package public relay/report-import evidence, and `callback-retention-prune` before archiving expired callback interactions. These are operational commands and must preserve provider bearer tokens, raw provider poll requests/responses, and callback tokens until report export.
- Use `exploit-preview` first; use `exploit-run` only with an approval JSON file or dry-run mode.
- Keep the returned `audit` array with any report or Vantix handoff.
