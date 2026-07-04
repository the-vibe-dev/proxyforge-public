# Claude Agent Contract

Claude agents should use the same command surface as Codex and keep outputs structured. The command wrapper is designed for sectioned reasoning: inspect status, gather evidence, plan active work, then run only approved commands.

## Suggested Sequence

```bash
node scripts/proxyforge-agent.mjs inventory --project ./workspace.proxyforge.json --json
node scripts/proxyforge-agent.mjs mitm-status --session-dir ./agent-session --json
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
node scripts/proxyforge-agent.mjs target-access-review --project ./workspace.proxyforge.json --roles customer,support_admin --json
node scripts/proxyforge-agent.mjs target-map-compare --project ./workspace.proxyforge.json --baseline hx-1 --candidate hx-1,hx-2 --json
node scripts/proxyforge-agent.mjs automation-run --project ./workspace.proxyforge.json --workflow wf-nightly --scope app.example.test --execute --json
node scripts/proxyforge-agent.mjs automation-scheduler-tick --project ./workspace.proxyforge.json --scope app.example.test --execute --json
node scripts/proxyforge-agent.mjs automation-ci-export --project ./workspace.proxyforge.json --workflow wf-nightly --provider github-actions,gitlab-ci,azure-pipelines,jenkins --json
node scripts/proxyforge-agent.mjs automation-service-plan --project ./workspace.proxyforge.json --workflow wf-nightly --out ./artifacts/automation-service-lifecycle.json --json
node scripts/proxyforge-agent.mjs automation-service-smoke --project ./workspace.proxyforge.json --workflow wf-nightly --service-dir ./.gitignored/automation-service-smoke --execute --json
node scripts/proxyforge-agent.mjs crawl-run --target https://app.example.test --scope app.example.test --execute --json
node scripts/proxyforge-agent.mjs view --project ./workspace.proxyforge.json --request-id hx-1 --mode raw --json
node scripts/proxyforge-agent.mjs replay-run --project ./workspace.proxyforge.json --request-id hx-1 --redirect follow --connection keep-alive --timeout 10000 --execute --json
node scripts/proxyforge-agent.mjs replay-matrix --project ./workspace.proxyforge.json --request-id hx-1 --roles customer,support_admin --redirect manual --json
node scripts/proxyforge-agent.mjs bulk-replay --project ./workspace.proxyforge.json --scope app.example.test --limit 50 --concurrency 5 --soak --execute --json
node scripts/proxyforge-agent.mjs live-target-profile --manifest ./live-targets.json --scope app.example.test --execute --json
node scripts/proxyforge-agent.mjs intruder-run --project ./workspace.proxyforge.json --request-id hx-1 --scope app.example.test --payloads customer,support_admin --concurrency 3 --soak --execute --json
node scripts/proxyforge-agent.mjs repeater-desync-plan --project ./workspace.proxyforge.json --request-id hx-1 --scope app.example.test --json
node scripts/proxyforge-agent.mjs repeater-desync-probe --project ./workspace.proxyforge.json --request-id hx-1 --scope app.example.test --execute --json
node scripts/proxyforge-agent.mjs repeater-race-run --project ./workspace.proxyforge.json --request-id hx-1 --scope app.example.test --count 12 --sync single-packet --soak --min-requests 12 --max-release-skew-ms 100 --execute --json
node scripts/proxyforge-agent.mjs insertion-points --project ./workspace.proxyforge.json --request-id hx-1 --out ./artifacts/insertion-points.json --json
node scripts/proxyforge-agent.mjs websocket-list --project ./workspace.proxyforge.json --connection-id ws-conn-1 --json
node scripts/proxyforge-agent.mjs websocket-replay --project ./workspace.proxyforge.json --frame-id ws-1 --scope app.example.test --execute --json
node scripts/proxyforge-agent.mjs websocket-fuzz --project ./workspace.proxyforge.json --frame-id ws-1 --scope app.example.test --max-probes 6 --execute --json
node scripts/proxyforge-agent.mjs websocket-transcript-export --project ./workspace.proxyforge.json --connection-id ws-conn-1 --format markdown --out ./artifacts/websocket-transcript.md --json
node scripts/proxyforge-agent.mjs scanner-run --project ./workspace.proxyforge.json --request-id hx-1 --scope app.example.test --check-pack full-active --max-requests 13 --execute --soak --min-requests 13 --json
node scripts/proxyforge-agent.mjs scanner-retest --project ./workspace.proxyforge.json --issue issue-1 --request-id hx-1 --retest-id hx-2 --json
node scripts/proxyforge-agent.mjs scanner-evidence-export --project ./workspace.proxyforge.json --issue issue-1 --request-id hx-1 --out ./artifacts/scanner-evidence.json --json
node scripts/proxyforge-agent.mjs scanner-oast-promote --project ./workspace.proxyforge.json --workspace ./callbacks.json --request-id hx-1 --payload-id cb-1 --interaction-id int-1 --out ./artifacts/scanner-oast-issue.json --json
node scripts/proxyforge-agent.mjs anvil-plan --project ./workspace.proxyforge.json --request-id hx-1 --json
node scripts/proxyforge-agent.mjs anvil-run --project ./workspace.proxyforge.json --request-id hx-1 --execute --json
node scripts/proxyforge-agent.mjs anvil-package-export --project ./workspace.proxyforge.json --request-id hx-1 --out ./artifacts/anvil-package.json --json
node scripts/proxyforge-agent.mjs callback-poll --workspace ./callbacks.json --json
node scripts/proxyforge-agent.mjs callback-provider-probe --providers ./oast-providers.json --scope callbacks.app.example.test --execute --json
node scripts/proxyforge-agent.mjs callback-relay-plan --workspace ./callbacks.json --public-base callbacks.app.example.test --json
node scripts/proxyforge-agent.mjs callback-relay-soak --workspace ./callbacks.json --public-base callbacks.app.example.test --json
node scripts/proxyforge-agent.mjs callback-retention-prune --workspace ./callbacks.json --retention-hours 72 --json
node scripts/proxyforge-agent.mjs extension-fixtures --project ./workspace.proxyforge.json --manifest ./extension.json --request-id hx-1 --json
node scripts/proxyforge-agent.mjs exploit-preview --project ./workspace.proxyforge.json --request-id hx-1 --template manual-validation --json
```

## Output Handling

- Prefer `data`, `artifacts`, and `audit` fields over raw transcript text.
- For persistent MITM work, use `mitm-start --ensure-ca --upstream-tls strict|relaxed` in a managed terminal and poll `mitm-status`/`mitm-export` instead of rereading raw proxy logs. Preserve the returned project-CA fingerprint, root certificate path, upstream TLS mode, and full-fidelity JSONL path.
- For large projects, use `search-index --soak` to persist a full-fidelity semantic index, capture scale evidence, and reuse artifact paths across agent turns.
- For authorized semantic providers, use `search-index --provider-url --execute` and preserve `proxyforge-agent-search-live-provider-invocation-package`, raw provider traffic, provider credentials, and full corpus documents until report export.
- For token review, use `sequencer-analyze --soak` and keep full samples, reliability level, statistical test details, and soak budgets in the handoff.
- For selected-message decoding, use `decoder-chain` and keep each transform step, final output, package digest, and full operational token/key/cookie material intact until reporting.
- For gathering, import existing proxy JSONL, HAR, legacy proxy XML history, raw HTTP text archives, or ProxyForge project logs with `proxy-import`, build candidates with `content-discovery-plan`, execute bounded path probes with `content-discovery-run --execute --soak`, and execute bounded crawls through `crawl-run --execute`. Preserve imported headers, cookies, tokens, API keys, and raw request/response bodies as executor material until report export.
- For Project Store v2 durability, run `project-store-status` to inspect recovery state, `project-store-recover` to replay pending capture journals, and `project-store-backup --execute` to create restore points. Keep sample raw exchanges, recovery reports, and restore manifests full fidelity until report export.
- For crawl-derived Scanner audit work, preserve `proxyforge-crawl-audit-insertion-evidence-package` fields for query/form/path coverage, duplicate merges, out-of-scope skips, active Scanner handoff, raw probe samples, operational secret signals, and report-export-only redaction.
- For authorization triage, use `target-access-review` to get role lanes and route decisions from scoped history before deciding which Repeater matrix or Scanner authz-diff commands need execution.
- For target drift, use `target-map-compare` to package baseline/candidate route additions, removals, status/MIME/method/host changes, parameter changes, and authz-sensitive deltas before promoting Target parity evidence.
- For automations, use `automation-list` to inspect workflow ids, `automation-run --execute` for scoped macro or on-tag runs, `automation-scheduler-tick --execute` for scheduler service work, `automation-parity-export` for proof packages, `automation-service-plan` for Linux systemd user plus Windows Task Scheduler lifecycle plans, and `automation-service-smoke --execute` for installed-host start/status/stop scheduler smoke. Keep approval-block receipts, leases, CI configs, service manifests, status files, JSONL logs, and operational raw material intact until report export.
- Treat operational outputs as sensitive because they preserve execution tokens, cookies, keys, headers, callbacks, and raw traffic until report export.
- Never infer execution from a planned result. Planned commands are dry and send no traffic.
- For transport-sensitive replay, keep redirect mode, max redirects, connection mode, timeout, final URL, redirect history, and timeout errors in the handoff.
- For bulk replay work, preserve `data.summary`, `data.soakPackage`, retained results, and the `maxInFlight`/request-rate evidence before summarizing parity status.
- For live target profiling, preserve `proxyforge-agent-live-target-profile-package`, scoped raw requests/responses, status-class diversity, Scanner candidates, Intruder marked raw requests, bearer tokens, cookies, and API keys until report export.
- For Intruder work, preserve `data.plan.attackModeMatrix`, `payloadTransformations`, `data.summary.streaming`, `data.soakPackage`, retained raw results, grep/extract matches, and the exact command flags used for attack mode, processors, rules, payload counts, caps, and concurrency.
- For desync/race work, preserve `data.plan.parserDifferential` from the dry plan, then preserve `data.result.rawTranscript`, `responseOrder`, `releaseSkewMs`, `jitterMs`, `data.soakPackage`, and `safety.gates` in notes back to the operator.
- For Scanner/Intruder prep from raw history, run `insertion-points` and keep the extracted query, path, header, cookie, form, JSON, XML, multipart, and GraphQL candidates with full operational tokens/keys/cookies intact until reporting.
- For WebSocket work, use `websocket-list` first, then `websocket-replay --execute` or `websocket-fuzz --execute` only with scope. Keep selected frame ids, handshake proof, received frames, fuzz outcomes, transcript exports, and full text/binary payload material intact until reporting.
- For Scanner check-pack work, preserve supported/unsupported check accounting, all built-in check coverage, scope/rate/cap gates, authz comparison legs, raw probe samples, operational secret signals, and report-export-only redaction from `proxyforge-active-scan-check-pack-evidence-package` when present.
- Use `status.data.scannerCatalog` to choose a check pack. `--check-pack input-attacks` covers reflected XSS, SQL injection, path traversal, open redirect, and command injection; `--check-pack full-active --max-requests 13` covers every built-in active Scanner family.
- For scanner work, preserve `data.calibrationPackage`, scanner tuning controls, suppressed findings, confidence reasons, and the full seed exchange before summarizing issue confidence.
- For Scanner retests, preserve `proxyforge-scanner-retest-evidence-delta-package` fields from `scanner-retest` or `scanner-evidence-export`: issue link, baseline proof, retest proof, request edits, fixed/regressed/still-vulnerable/inconclusive coverage, raw samples, and operational secret signals until report export.
- For active Scanner evidence packages, preserve the plan/review/matrix/replay ids, CI command, report attachment manifest, active/suppressed finding status, raw exchange samples, and `secretHandling`; redaction happens only when a report command exports submission material.
- For Scanner OAST callbacks, use `scanner-oast-promote` to bind the source exchange, scanner probe, callback payload, observed interaction, issue draft, and retest commands. Keep the raw token/cookie/callback material intact until report export.
- For Anvil custom scan checks, use `anvil-plan`, then `anvil-run --execute`, then `anvil-package-export` when an artifact is needed. Preserve `.anvil` source, reusable library content, positive/negative fixtures, validation, custom-only headless evidence, signed package review, Scanner/Reports handoff, raw samples, and operational secret signals until report export.
- For extension work, use `extension-fixtures` to capture legacy proxy-compatible `IHttpListener`, `IScannerCheck`, `IMessageEditorTab`, helper transforms, multi-message context menus, session token refresh, insertion points, package-refresh metadata, and policy-denied callback evidence before assuming migrated extension parity.
- For OAST work, preserve `callback-provider-probe` provider host proof fields, signed poll raw requests/responses, provider bearer tokens, `callback-relay-plan` DNS/routes/secret-storage fields, `callback-relay-soak` raw relay/report-import evidence, and `callback-retention-prune` expired ids plus raw pruned interactions until a report command redacts submission output.
- When reporting uncertainty, include the ProxyForge command and `schemaVersion` used.
- For exploit work, distinguish preview, dry-run, queued approved execution, and completed backend evidence.
