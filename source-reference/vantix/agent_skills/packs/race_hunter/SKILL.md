---
name: race_hunter
description: Race condition and TOCTOU hunting. HTTP/2 single-packet attacks, last-byte-sync for HTTP/1.1, payment/voucher/balance/OTP/registration double-action probes with strict baseline-vs-divergence evidence.
---
# Race Hunter

Race conditions remain underexplored on most programs and pay disproportionately. The single-packet attack technique made this class reliable: coalesce 20–50 requests into a single TCP segment over HTTP/2, and the origin's request-dispatch window narrows from "milliseconds of network jitter" to "the deterministic order of the multiplexed frames." Findings here are routinely $5k–$50k on programs with payment, credit, voucher, or quota endpoints.

This pack composes with `shared/scope_guard.md`, `packs/web_hunter/SKILL.md` (where the candidate endpoints come from), `packs/bug_bounty/SKILL.md`, `packs/triage_validation/SKILL.md` (race findings require baseline-vs-divergence evidence, not single-anomaly).

## When to Use

- Target accepts an action with a uniqueness constraint: voucher, OTP, password-reset token, email-confirmation token, single-use coupon.
- Target operates on a counter: balance, credit, quota, vote count, follow cap, friend-request cap.
- Target performs a state-machine transition: order → paid, registration → user-row, refund → credit.
- A GraphQL mutation exists with similar uniqueness or counter semantics — see `packs/graphql_hunter/SKILL.md`.

## Operating Rules

- Scope: ensure the program permits race testing. Some programs scope it out explicitly ("no DoS, no race attacks on production payment").
- Evidence: one anomaly is not proof. Run baseline (N=1) → race-batch (N=10) → repeat 3+ times. The finding is "consistent divergence from baseline at N>1 in this specific window," not "I sent 20 requests and one looked weird."
- Stop at proof: do not actually double-spend funds, do not consume real voucher inventory, do not exhaust quotas. The proof is one extra successful action beyond the limit; one is enough.
- Cleanup: if the race created persistent state (extra user rows, duplicated orders), document the cleanup steps and request the program team to clean up after triage.

## Phase 0: Readiness Probe

The technique varies based on what protocol the origin speaks.

### Is the origin HTTP/2?

```bash
nghttp -v -n https://target.com/api/endpoint
# Look for "h2" ALPN negotiation
```

- **Yes**: single-packet attack applies. This is the strongest attack — frames arrive within microseconds.
- **No, HTTP/1.1 only**: last-byte-sync technique applies. Looser timing, but still effective for windows >50ms.
- **HTTP/1.1 with keep-alive only**: pipelining attacks possible but with worse timing precision than last-byte-sync.

### Is the endpoint reachable without HTTP-2-incompatible features?

- Some endpoints require WebSocket upgrade (race won't apply directly).
- Some endpoints behind WAF buffer requests differently — test with a benign request first to confirm.

## Phase 1: Target Taxonomy

Pick the candidate based on the endpoint shape.

### A. Payment double-charge

```
POST /api/checkout/complete
Body: { "orderId": "<id>", "paymentMethodId": "<id>" }
```

Race: 20 parallel `POST /complete` for the same orderId. Server's "is this order already paid" check happens before "mark paid"; race them.

Evidence: baseline (1 request) charges once; race-batch produces 2+ charges or 2+ "paid" state transitions.

### B. Voucher / coupon double-redeem

```
POST /api/voucher/redeem
Body: { "code": "<one-time-code>" }
```

Race: N parallel redeems for the same code. Should reject N-1 of them; bug is when 2+ succeed.

### C. Balance underflow on concurrent withdraw

```
POST /api/wallet/withdraw
Body: { "amount": 100 }   # account has $150
```

Race: 2 parallel withdraws of $100 each from an account with $150. Should reject one; bug is when both succeed and balance goes negative (or to $50 if signed, $-50 if unsigned underflow wraps).

### D. OTP-window brute

```
POST /api/auth/verify-otp
Body: { "userId": "<id>", "otp": "000000" }
```

Race: 10000 parallel guesses of the OTP within a single dispatch window. Rate-limiter is per-OTP-attempt rather than per-account/per-time-window → all 10000 land before the rate limiter cycles.

### E. Password-reset / email-confirm token reuse

```
POST /api/auth/reset-password
Body: { "token": "<one-time-token>", "newPassword": "x" }
```

Race: 2 parallel resets with the same token → bug is when both succeed and the password is set to whichever finishes last (or both passwords land, depending on the bug).

### F. Vote / poll double-cast

```
POST /api/poll/vote
Body: { "pollId": "<id>", "optionId": "<id>" }
```

Race: 20 parallel votes for the same poll by the same user → should be 1 vote; bug is more.

### G. Quota / cap bypass

- Friend-request cap (max 100 pending) — race 200 send-friend-request actions.
- Follow cap (max 7500 follows/day) — race up to limit + N.
- Comment cap (max 5/min) — race 50 within the second window.

### H. Registration collision

```
POST /api/auth/register
Body: { "email": "victim@example.com", "password": "x" }
```

Race: 2 parallel registers with the same email. Unique-constraint check happens before insert; race for the gap. Result: 2 user rows with the same email, or the email-confirmation flow goes to attacker.

### I. TOCTOU on filesystem / cache

Less common in pure-web targets but appears in deploy/build endpoints, file-upload pipelines, and cache-warming endpoints.

## Phase 2: Single-Packet Attack (HTTP/2)

The technique:

1. Open one HTTP/2 connection.
2. Send the headers for N requests.
3. Hold the body of the last request to ensure all earlier bodies finish first.
4. Send the final body byte; all N requests dispatch to the application worker pool in the same window.

Tooling:

- **Turbo Intruder-style web-proxy extension**: the canonical implementation. `engine.queue(req)` × N, `engine.openGate("racepool")`.
- **`oxdf-race` (community Python)**: standalone, no web-proxy dependency. Slower than the extension but works fine.
- **Custom `nghttp2-client`**: for maximum control over frame ordering.

If an intercepting web proxy is available, the Turbo Intruder-style extension is fastest to write. Otherwise:

```python
# Pseudocode — actual implementation in the wrapper
import asyncio, httpx
async def race(url, headers, body, n=20):
    client = httpx.AsyncClient(http2=True)
    reqs = [client.post(url, headers=headers, content=body) for _ in range(n)]
    return await asyncio.gather(*reqs)
```

## Phase 3: Last-Byte-Sync (HTTP/1.1)

When HTTP/2 isn't available:

1. Open N TCP connections to the origin.
2. On each, send the full request minus the final byte of the body. Wait for the connections to settle (the origin has buffered all but the last byte).
3. Send the final byte on every connection simultaneously.

The N requests now dispatch to the application within a tighter window than independent send-receive would yield.

Tooling: `turbo-intruder` (also supports last-byte-sync), `vegeta` for high-rate fallback, custom raw-socket scripts for full control.

## Phase 4: Evidence Discipline

A race finding is only credible with:

1. **Baseline**: N=1 succeeds once, with the expected state transition.
2. **Race-batch**: N=10 (or appropriate scale) — N successful state transitions when only 1 should have succeeded.
3. **Repeat**: the race-batch produces divergent state across 3+ independent attempts. A one-time anomaly is noise.
4. **State capture**: after the race, fetch the state (balance, voucher status, order list) and show the divergence.
5. **Negative evidence at N=2**: the same race at N=2 may NOT trigger (because the window is wider than 2 requests). Document at what N the divergence appears reliably.

## Submission Gates

Run `packs/triage_validation/SKILL.md` 7-Question gate. Then for this class:

- [ ] Baseline shows the expected behavior (1 action = 1 effect).
- [ ] Race-batch shows divergence reproducibly across multiple attempts.
- [ ] State fetch post-race shows the persistent divergence (balance, voucher status, etc.).
- [ ] The PoC includes the exact N (parallelism) and any timing parameters required.
- [ ] The exploit is contained — one extra action beyond the limit, not full-blown drain.
- [ ] Cleanup steps are documented or already executed (where the race created persistent state).

## Evidence

Store under the run artifact root, named `race_<endpoint>_<timestamp>/`:

- `01_readiness.txt` — `nghttp -v` output showing h2 (or h1.1 + last-byte applicability).
- `02_baseline_n1.har` — single request, single effect.
- `03_race_n10_attempt1.har` — race batch, attempt 1.
- `04_race_n10_attempt2.har`, `05_race_n10_attempt3.har` — reproducibility.
- `06_state_post_race.txt` — balance/quota/voucher state showing the divergence.
- `07_cleanup.md` — what we restored or notified the program to restore.
- `README.md` — verified-vs-not table per `shared/evidence_rules.md`.

## Exclusions

- No actual fund drain — proof is N=2 successful where N=1 should be, not N=999.
- No exhausting real-world inventory (voucher pool, OTP budget).
- No DoS-grade race against rate-limit-only endpoints; that's a different class with different program scope.
- No race attacks on shared infrastructure (cache, third-party services) that would affect other users.

## See Also

- `agent_skills/packs/web_hunter/SKILL.md` — discovery of race-eligible endpoints
- `agent_skills/packs/api_security/SKILL.md` — API authn/authz model that race attacks bypass
- `agent_skills/packs/graphql_hunter/SKILL.md` — alias-batching is a GraphQL-specific race shape
- `agent_skills/packs/triage_validation/SKILL.md` — submission gates
- External tools: Turbo Intruder-style web-proxy extension; community race-condition example repos.
