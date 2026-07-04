---
name: Safe Scanner
description: Scope-safe, rate-limited vulnerability scanner orchestration with payload budgets, denylists, and replayable evidence capture.
---
# Safe Scanner

Active scanning without guardrails destroys reputations and burns program relationships. This pack operationalizes the safe-scanning constraint model: every payload is pre-flight-checked against scope, every request is rate-limited per program's safety profile, and every finding is deduplicated across scans to prevent alert fatigue.

Composes with `shared/scope_guard.md`, `shared/evidence_rules.md`, `shared/execution_policy.md`, `packs/web_hunter/SKILL.md` (passive discovery feeds candidate endpoints).

## When to Use

- Operator has scope approval for active testing (explicit program policy, not inferred).
- Target scope is narrow and well-defined; you need targeted vulnerability scanning on a specific endpoint class (parameter, file upload, API endpoint).
- Passive discovery alone (content, JS, HTTP headers) has not yielded exploitable findings.
- Rate-limit budgets are known and enforceable (program's documented RPS, daily request cap, per-endpoint throttle).

## Operating Rules

- **Scope check**: every endpoint MUST be scope-matched before any payload fires. Scope include-list is source-of-truth. Glob patterns like `*.api.example.com` expand at plan time, not runtime.
- **Rate budgets**: payload rate is NOT constant. Burst initial probes (5 RPS) then taper per program's safety profile (burst vs. sustained, quiet-hours, per-endpoint backoff).
- **Passive-first**: run passive discovery (HTTP headers, JS bundles, sitemaps, directives) before active scanning. Reuse those targets. Active scans should confirm, not explore.
- **Payload denylist**: XSS payloads that inject script tags are FORBIDDEN on financial-transaction endpoints. SQLi time-delay payloads are FORBIDDEN if they trigger IDS alerts. Maintain a per-program denylist.
- **Evidence replay**: every request MUST be logged as a HAR entry. If a payload generates a 200 response that looks exploitable, replay it from the HAR under proxy to confirm it's not a WAF artifact.

## Phase 0: Pre-Scan Readiness

Before firing any payload:

### Scope Inventory

```
1. Fetch scope from `shared/scope_guard.md` anchor.
2. Expand globs: *.api.example.com → api1.example.com, api2.example.com, ... (via DNS or program policy).
3. Fetch in-scope path patterns: /api/*, /admin, !/admin/internal (exclude).
4. Confirm: at least 3 targets, at most 1000 endpoints per program.
```

### Rate-Limit Profile

```
query {
  program(id: "target-program") {
    active_scan_policy {
      burst_rps: 5       # Initial probes
      sustained_rps: 1   # Long-running scan
      daily_cap: 50000   # Total requests/day
      quiet_hours: "21:00-08:00"
      per_endpoint_backoff_ms: 500  # After 429
    }
  }
}
```

### Payload Denylist

```yaml
program: "payment-processor"
denylist:
  - class: "xss_script_tag"
    reason: "Customer transaction page; alert triggers vendor audit"
  - class: "sqli_time_delay"
    reason: "IDS sensor on database layer; 10-sec delay → auto-block"
endpoints_exempt:
  - "/public/test"  # Explicitly allowlisted for testing
```

## Phase 1: Endpoint Targeting

Leverage passive discovery as input:

```
1. Fetch candidate endpoints from web_hunter scan (HTTP fingerprint, JS routes, sitemaps).
2. Filter: in-scope paths only.
3. Tally parameter types: query, form-body, path segment, header, cookie.
4. Rank by injection potential: (1) user-input query params, (2) form fields, (3) headers/cookies.
```

Example: POST `/api/search?q=` has a query-param injection point in `q`. Payload class: SQLi, XSS, command-injection. Start with SQLi string-concat probes.

## Phase 2: Payload Generation & Rate-Limited Dispatch

### Payload Strategy

```python
# Pseudocode
for endpoint in targets:
    for param in endpoint.params:
        # Tier 1: Passive probes (no special chars, 200-300 byte limit)
        for payload in ["test", "123", "' OR '1'='1"]:
            response = send_with_limit(endpoint, param, payload, rps=5)
            if response.status != 200:
                log_baseline(endpoint, param, payload, response)
                continue
            
            # Tier 2: Active probes (if baseline passes)
            if matches_denylist(payload, program):
                log_blocked(endpoint, param, payload, reason="denylist")
                continue
            
            # Fire payload with rate-limit backoff
            response = send_with_limit(endpoint, param, payload, rps=1)
            deduplicate_and_log(endpoint, param, payload, response)
```

### Rate-Limit Backoff

```
1. Start burst_rps = 5 (initial reconnaissance).
2. On 429 Retry-After: wait specified duration, then drop to sustained_rps = 1.
3. On 403 / 401: endpoint requires auth we don't have; skip.
4. On 5xx: endpoint is unstable; skip, alert operator.
5. Track cumulative daily requests; halt if approaching cap.
```

## Phase 3: Evidence Deduplication & Confirmation

A single 200 response is not proof of vulnerability. Duplicate the finding:

```
1. Baseline: endpoint without payload (or with benign payload).
2. Confirmation: replay the suspicious payload from the HAR.
3. Side-channel: check response time, response size, error message for change.
4. Deduplicate: if 3+ scans in the last 7 days found the same (endpoint, param, class), suppress the alert.
```

Example:

```
Endpoint: POST /api/users/search?q=
Baseline (q=test): 200 OK, 512 bytes, 45ms
Payload (q=' OR '1'='1): 200 OK, 512 bytes, 45ms  <- No change; likely filtered
Payload (q={{7*7}}): 200 OK, 512 bytes, 45ms     <- No change; likely no SSTI
Payload (q=<img src=x>): 200 OK, 512 bytes, 45ms <- No change; likely no XSS
Conclusion: endpoint is not exploitable via q parameter.
```

## Phase 4: Response-Size Cap & Data-Leak Containment

Large responses may indicate database dumps:

```
1. Cap: if response > 10 MB, stop immediately. Log as potential data leak.
2. Verify scope: is this endpoint serving customer data? Log program-sensitive.
3. Downgrade risk: if the data is already public (via /api/users with pagination), note in report.
```

## Theories This Pack Owns

1. **Rate-limit evasion**: Operator discovers an endpoint that lacks rate-limit enforcement, or rate-limit can be bypassed via header manipulation (X-Forwarded-For, X-Real-IP). Safe scanner enforces per-program limits regardless.
2. **Payload-level filtering**: XSS payloads using angle brackets are filtered, but Unicode escapes bypass the filter. Safe scanner tests both variants but respects denylist overrides.
3. **Error-message leakage**: SQLi payloads trigger verbose database errors (e.g., "Syntax error in SQL statement"). Safe scanner captures error-message changes in the response delta.
4. **WAF bypass via polyglot**: A single payload (e.g., `1' AND SLEEP(5) #`) satisfies both SQLi and timing-side-channel signatures. Denylist can block this specific polyglot while allowing safer variants.
5. **Evidence replay under proxy**: A finding captured during active scan must be manually replayed under the operator's proxy to confirm the WAF is not generating false-positives.
6. **Scope creep via redirect**: An in-scope endpoint redirects to an out-of-scope domain. Safe scanner halts at the redirect boundary; does not follow.

## Tooling

- **Custom orchestrator**: rate-limit driver (Python `tenacity` or `ratelimit`), HAR logger, denylist matcher.
- **Intercepting web proxy**: manual payload crafting, batch fuzzing, request/response rewriting, evidence capture.

## Submission Gates

Run `packs/triage_validation/SKILL.md` 7-Question gate. Then for this class:

- [ ] Scope approval documented (program policy, explicit endpoint list).
- [ ] Rate-limit profile applied and logged (RPS, daily cap, backoff).
- [ ] Payload denylist reviewed and applied (no forbidden classes on this program).
- [ ] Evidence deduplicated across prior scans (no duplicate alert).
- [ ] Baseline vs. payload response captured in HAR (reproducible delta).
- [ ] All responses under 10 MB; data-leak risk assessed.

## See Also

- `agent_skills/packs/web_hunter/SKILL.md` — passive endpoint discovery
- `agent_skills/packs/api_security/SKILL.md` — API parameter model
- `agent_skills/shared/scope_guard.md` — scope matching anchor
- `agent_skills/shared/evidence_rules.md` — HAR evidence structure

## Exclusions

- No destructive payloads (DROP TABLE, system commands, file delete).
- No DoS payloads (billion laughs, slowloris, algorithmic complexity).
- No payload classes on denylist for this program.
- No scanning out-of-scope domains or subdomains.
- No persistence (shell uploads, cron jobs, persistence mechanisms).
