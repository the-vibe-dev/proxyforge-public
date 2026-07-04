# Vantix Integration Contract

Vantix agents in `~/vantix/` can consume ProxyForge state through full-fidelity operational JSON handoffs. The default handoff directory is `~/vantix/proxyforge`, but callers can pass `--out`. Commands can be run from `~/vantix/` with an absolute path to `proxyforge-agent.mjs`; the CLI resolves ProxyForge runtime modules from its own app root rather than from the agent runner's current directory.

## Commands

```bash
node scripts/proxyforge-agent.mjs vantix-sync --project ./workspace.proxyforge.json --out ~/vantix/proxyforge --json
node scripts/proxyforge-agent.mjs mitm-export --session-dir ~/vantix/proxyforge/agent-session --json
node scripts/proxyforge-agent.mjs vantix-intel-export --project ./workspace.proxyforge.json --query authz --out ~/vantix/proxyforge --json
node scripts/proxyforge-agent.mjs search-index --project ./workspace.proxyforge.json --query authz --out ~/vantix/proxyforge/search-index.json --soak --soak-out ~/vantix/proxyforge/search-soak.json --json
node scripts/proxyforge-agent.mjs search-index --project ./workspace.proxyforge.json --query "authz bypass" --provider-url http://127.0.0.1:9000/rank --provider-token "$SEARCH_PROVIDER_TOKEN" --scope 127.0.0.1 --execute --provider-out ~/vantix/proxyforge/search-provider.json --json
node scripts/proxyforge-agent.mjs sequencer-analyze --sample-file ~/vantix/proxyforge/tokens.txt --soak --min-samples 5000 --min-reliability reliable --json
node scripts/proxyforge-agent.mjs decoder-chain --project ./workspace.proxyforge.json --request-id hx-1 --source response --transforms base64-decode,json-pretty --out ~/vantix/proxyforge/decoder-chain.json --json
node scripts/proxyforge-agent.mjs proxy-import --file ~/vantix/proxyforge/agent-session/exchanges.jsonl --json
node scripts/proxyforge-agent.mjs proxy-import --file ~/vantix/proxyforge/legacy-proxy-history.xml --json
node scripts/proxyforge-agent.mjs project-store-status --store ./workspace.proxyforge --json
node scripts/proxyforge-agent.mjs project-store-recover --store ./workspace.proxyforge --out ~/vantix/proxyforge/project-store-recovery.json --json
node scripts/proxyforge-agent.mjs project-store-backup --store ./workspace.proxyforge --out ~/vantix/proxyforge/project-store-backups --execute --json
node scripts/proxyforge-agent.mjs content-discovery-plan --project ./workspace.proxyforge.json --scope app.example.test --json
node scripts/proxyforge-agent.mjs content-discovery-run --project ./workspace.proxyforge.json --scope app.example.test --limit 40 --concurrency 4 --soak --execute --json
node scripts/proxyforge-agent.mjs target-access-review --project ./workspace.proxyforge.json --roles customer,support_admin --json
node scripts/proxyforge-agent.mjs target-map-compare --project ./workspace.proxyforge.json --baseline hx-1 --candidate hx-1,hx-2 --json
node scripts/proxyforge-agent.mjs automation-run --project ./workspace.proxyforge.json --workflow wf-nightly --scope app.example.test --execute --json
node scripts/proxyforge-agent.mjs automation-scheduler-tick --project ./workspace.proxyforge.json --scope app.example.test --execute --json
node scripts/proxyforge-agent.mjs automation-parity-export --project ./workspace.proxyforge.json --out ~/vantix/proxyforge/automation-parity.json --json
node scripts/proxyforge-agent.mjs automation-service-plan --project ./workspace.proxyforge.json --workflow wf-nightly --out ~/vantix/proxyforge/automation-service-lifecycle.json --json
node scripts/proxyforge-agent.mjs automation-service-smoke --project ./workspace.proxyforge.json --workflow wf-nightly --service-dir ~/vantix/proxyforge/automation-service-smoke --execute --json
node scripts/proxyforge-agent.mjs crawl-run --target https://app.example.test --scope app.example.test --execute --json
node scripts/proxyforge-agent.mjs replay-run --project ./workspace.proxyforge.json --request-id hx-1 --scope app.example.test --redirect follow --connection keep-alive --timeout 10000 --execute --json
node scripts/proxyforge-agent.mjs bulk-replay --project ./workspace.proxyforge.json --scope app.example.test --limit 50 --concurrency 5 --soak --execute --json
node scripts/proxyforge-agent.mjs live-target-profile --manifest ./live-targets.json --scope app.example.test --execute --json
node scripts/proxyforge-agent.mjs intruder-run --project ./workspace.proxyforge.json --request-id hx-1 --scope app.example.test --payloads admin,user --concurrency 3 --soak --execute --json
node scripts/proxyforge-agent.mjs repeater-desync-probe --project ./workspace.proxyforge.json --request-id hx-1 --scope app.example.test --execute --json
node scripts/proxyforge-agent.mjs repeater-race-run --project ./workspace.proxyforge.json --request-id hx-1 --scope app.example.test --count 12 --sync single-packet --soak --min-requests 12 --max-release-skew-ms 100 --execute --json
node scripts/proxyforge-agent.mjs insertion-points --project ./workspace.proxyforge.json --request-id hx-1 --out ~/vantix/proxyforge/insertion-points.json --json
node scripts/proxyforge-agent.mjs websocket-list --project ./workspace.proxyforge.json --connection-id ws-conn-1 --json
node scripts/proxyforge-agent.mjs websocket-replay --project ./workspace.proxyforge.json --frame-id ws-1 --scope app.example.test --execute --json
node scripts/proxyforge-agent.mjs websocket-fuzz --project ./workspace.proxyforge.json --frame-id ws-1 --scope app.example.test --max-probes 6 --execute --json
node scripts/proxyforge-agent.mjs websocket-transcript-export --project ./workspace.proxyforge.json --connection-id ws-conn-1 --format markdown --out ~/vantix/proxyforge/websocket-transcript.md --json
node scripts/proxyforge-agent.mjs scanner-run --project ./workspace.proxyforge.json --request-id hx-1 --scope app.example.test --check-pack full-active --max-requests 13 --execute --soak --min-requests 13 --json
node scripts/proxyforge-agent.mjs scanner-retest --project ./workspace.proxyforge.json --issue issue-1 --request-id hx-1 --retest-id hx-2 --json
node scripts/proxyforge-agent.mjs scanner-evidence-export --project ./workspace.proxyforge.json --issue issue-1 --request-id hx-1 --out ~/vantix/proxyforge/scanner-evidence.json --json
node scripts/proxyforge-agent.mjs scanner-oast-promote --project ./workspace.proxyforge.json --workspace ./callbacks.json --request-id hx-1 --payload-id cb-1 --interaction-id int-1 --out ~/vantix/proxyforge/scanner-oast-issue.json --json
node scripts/proxyforge-agent.mjs anvil-plan --project ./workspace.proxyforge.json --request-id hx-1 --json
node scripts/proxyforge-agent.mjs anvil-run --project ./workspace.proxyforge.json --request-id hx-1 --execute --json
node scripts/proxyforge-agent.mjs anvil-package-export --project ./workspace.proxyforge.json --request-id hx-1 --out ~/vantix/proxyforge/anvil-package.json --json
node scripts/proxyforge-agent.mjs extension-fixtures --project ./workspace.proxyforge.json --manifest ./extension.json --request-id hx-1 --json
node scripts/proxyforge-agent.mjs callback-relay-plan --workspace ./callbacks.json --public-base callbacks.app.example.test --json
node scripts/proxyforge-agent.mjs callback-provider-probe --providers ./oast-providers.json --scope callbacks.app.example.test --execute --json
node scripts/proxyforge-agent.mjs callback-relay-soak --workspace ./callbacks.json --public-base callbacks.app.example.test --json
node scripts/proxyforge-agent.mjs callback-retention-prune --workspace ./callbacks.json --retention-hours 72 --json
node scripts/proxyforge-agent.mjs report-export --project ./workspace.proxyforge.json --format json --out ~/vantix/proxyforge/reports --json
```

External runner form:

```bash
cd ~/vantix
node ~/proxyforge/scripts/proxyforge-agent.mjs status --project ~/proxyforge/workspace.proxyforge.json --json
node ~/proxyforge/scripts/proxyforge-agent.mjs chromium-capture --project ~/proxyforge/workspace.proxyforge.json --target https://app.example.test --scope app.example.test --json
```

## Handoff Contents

- Project summary and scope.
- Persistent MITM session paths, project-CA fingerprint/root path, upstream TLS mode, and full exchange data when Vantix asks for live gathering state.
- Top findings and evidence ids.
- `agentRuntime.scriptPath`, `agentRuntime.appRoot`, and `agentRuntime.commandPrefix` so Vantix can rerun ProxyForge from its own working directory without guessing paths.
- Persistent semantic search index and `search-index --soak` artifacts for long-running intel gathering, scale checks, and cross-turn reuse.
- Live semantic provider invocation packages from `search-index --provider-url --execute`, including scoped provider raw requests/responses, provider credentials, full corpus documents, ranked matches, and full operational request/response material for Vantix-side intel workflows.
- Sequencer token analysis and large-sample soak packages, including full token samples, reliability level, bit/position statistics, and statistical tests for executor workflows.
- Decoder transform-chain packages from `decoder-chain`, including selected request/response input, every transform step, final decoded/encoded output, digest preview, and full operational token/key/cookie material for executor workflows.
- Proxy/history import packages from ProxyForge JSONL, HAR, legacy proxy XML history, raw HTTP text archives, or project exports, plus content-discovery candidate plans, content-discovery execution/soak packages, and scoped crawl results for Vantix-side intel gathering. Imported headers, cookies, tokens, API keys, and raw request/response bodies stay full fidelity until report export.
- Project Store v2 status, recovery, and restore-point backup packages from `project-store-status`, `project-store-recover`, and `project-store-backup`, including replayed recovery journals, sample raw exchanges, backup manifests, and full operational tokens/cookies/keys/callbacks for executor workflows.
- Target access-control review packages with role lanes, route decisions, overexposed/underexposed counts, raw exchange ids, and recommended Repeater/Scanner verification commands.
- Automation service lifecycle packages from `automation-service-plan`, including Linux systemd user and Windows Task Scheduler manifests, install/start/status/stop/uninstall commands, scheduler tick commands, durable state/log paths, and full operational token/cookie/key samples until report export.
- Installed-host Automation service smoke packages from `automation-service-smoke --execute`, including detached Node runner start/status/stop proof, durable status and scheduler state files, JSONL logs, scheduler tick results, PID lifecycle evidence, and full operational token/cookie/key samples until report export.
- Target map comparison packages with baseline/candidate route deltas, affected parameters, authz-sensitive drift evidence, digest previews, and recommended follow-up commands.
- Automation inventories, scoped run receipts, scheduler tick results, CI/headless provider presets, and Automation parity packages for Vantix-side orchestration. These preserve macro steps, queue leases, approval-block receipts, source raw exchanges, and operational tokens until report export.
- Recommended follow-up commands for Chromium capture, replay, scanner planning, and reporting.
- Replay transport evidence, including redirect history, final URL, timeout errors, and connection mode for Vantix-side differential analysis.
- Bulk replay summaries and high-volume soak packages, including retained full-fidelity responses, request-rate telemetry, max in-flight concurrency, and dropped-window counts for executor workflows.
- Live target profile packages from `live-target-profile`, including scoped raw requests/responses, host/route/status diversity, Scanner candidates, Intruder marked raw requests, replay handoff commands, bearer tokens, cookies, and API keys for executor workflows.
- Intruder attack-mode and payload-transformation matrices, execution summaries, and high-volume soak packages, including Sniper/Battering Ram/Pitchfork/Cluster Bomb expansion counts, recursive payload rule expansion, processor output samples, payload-position metadata, retained raw results, request-rate telemetry, max in-flight concurrency, and grep/extract evidence for executor workflows.
- Repeater desync/race command outputs, including parser-differential dry-plan evidence, single-connection proof transcripts, race soak packages, release timing, response order, and raw request/response evidence for executor workflows.
- Insertion point inventory packages from `insertion-points`, including query, path, header, cookie, form, JSON, XML, multipart, and GraphQL candidates plus full raw request/response material for Vantix-side Scanner, Intruder, and Target planning.
- WebSocket inventory, replay, fuzz, and transcript packages from `websocket-list`, `websocket-replay`, `websocket-fuzz`, and `websocket-transcript-export`, including selected frame ids, live handshake proof, received frames, fuzz probe outcomes, JSON/Markdown transcript content, and full text/binary payload material for executor workflows.
- Active Scanner check-pack evidence packages, including supported/unsupported check accounting, built-in check coverage, scope/rate/cap gates, authz comparison legs, raw probe samples, and operational secret signals for executor workflows.
- Scanner catalog metadata from `status.data.scannerCatalog`, including `baseline`, `input-attacks`, `api-graphql`, `auth-state`, and `full-active` packs. Vantix can use `--check-pack input-attacks` for reflected XSS, SQL injection, path traversal, open redirect, and command injection, or `--check-pack full-active --max-requests 13` for every built-in active check.
- Crawl audit insertion evidence packages, including query/form/path coverage, duplicate merges, out-of-scope skips, active Scanner handoff, raw probe samples, and operational secret signals for executor workflows.
- Scanner live calibration packages, including false-positive controls, suppressed finding records, confidence reasons, dedupe keys, and the seed exchange for executor workflows.
- Scanner active-scan evidence packages, including plan/review/matrix/replay linkages, CI command metadata, report attachment manifests, active/suppressed finding status, raw exchange samples, and operational secret signals for executor workflows.
- Scanner OAST issue promotion packages from `scanner-oast-promote`, including source/scanner exchanges, callback payloads, callback interactions, issue drafts, retest commands, and full callback tokens/cookies/raw material for executor workflows.
- Scanner retest evidence delta packages, including baseline proof, retest proof, request-edit context, fixed/regressed/still-vulnerable/inconclusive outcome coverage, raw samples, and operational secret signals for executor workflows.
- Anvil custom scan-check packages, including `.anvil` source, reusable rule libraries, positive/negative fixtures, validation runs, custom-only headless runs, signed package reviews, Scanner finding handoffs, Reports attachments, raw samples, and operational secret signals for executor workflows.
- Extension fixture packages for legacy proxy-compatible request listeners, scanner checks, message editor tabs, and policy-denied callbacks, including selected raw exchange evidence for executor workflows.
- OAST provider host proof, relay plans, public relay soak/report-import packages, and retention prune manifests, including provider bearer tokens, signed poll raw requests/responses, DNS/routes, secret-storage references, expired payload/interaction ids, and full raw callback records for executor workflows.
- Raw request/response data for executor workflows. Use ProxyForge report exports when Vantix needs redacted submission artifacts.
- Audit metadata that Vantix can attach to its own run log.

## Safety

Vantix should pass explicit `--scope` values for live targets and should avoid `--execute` until the operator has confirmed the target and rate limits. Approved exploit commands must use a dedicated approval JSON artifact.
