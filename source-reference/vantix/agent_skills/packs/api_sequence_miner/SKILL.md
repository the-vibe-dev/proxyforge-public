---
name: api_sequence_miner
description: Business-logic bugs emerge from API sequencing errors. Extract all valid API sequences from application workflows (payment flow, account setup, content publishing). Identify preconditions and state invariants at each step. Reorder steps and test which fail correctly and which permit bypass. Feed valid-but-reordered sequences to the business-logic verifier to find state-check gaps.
---
# API Sequence Miner

Business-logic bugs arise when APIs fail to enforce workflow preconditions. A checkout flow should be: add-to-cart → set-delivery-address → apply-discount → enter-payment → confirm. If the API permits confirm without prior steps, the app accepts a payment from an invalid state.

This pack extracts valid API sequences from the running application, infers the state machine, and tests permutations to find missing guards.

Composes with `packs/web_hunter/SKILL.md` (endpoint discovery), `packs/triage_validation/SKILL.md` (evidence of state bypass).

## When to Use

- Application has multi-step workflows: payment, registration, content publishing, form submission.
- API endpoints correspond to workflow steps.
- Browser traffic shows a repeating sequence of API calls.
- OpenAPI or GraphQL schema is available.
- Mobile app is decompilable for API discovery.

## Operating Rules

- Extract sequences from clean runs first (happy path).
- Infer state from request/response patterns (usually evident from HTTP status or response content).
- Test reorderings minimally: skip a step, skip two steps, replay a step, reorder later steps.
- Document which reorderings are correctly rejected (proof of state guards).
- Avoid DoS or data mutation; use read-only or easily reversible test actions.

## Phase 0: Sequence Extraction

Capture API call sequences from four sources:

### Source A: Browser Traffic (HAR / Proxy)

Run a complete workflow in the browser with an intercepting proxy recording.

```
Happy-path workflow: e-commerce checkout
1. POST /api/cart/add-item {itemId, qty}
2. POST /api/cart/set-delivery-address {address, method}
3. POST /api/cart/apply-discount-code {code}
4. POST /api/payment/initiate {total}
5. POST /api/payment/confirm {paymentMethodId, nonce}
6. GET /api/order/latest
```

Extract from HAR: request method, path, body (params), response status, response body (state indicators).

### Source B: OpenAPI Specification

If available, parse openapi.json or swagger.yaml:

```yaml
paths:
  /cart/add-item:
    post:
      operationId: addToCart
      tags: [checkout]
  /cart/set-delivery:
    post:
      operationId: setDelivery
      tags: [checkout]
  /payment/confirm:
    post:
      operationId: confirmPayment
      tags: [checkout]
```

Extract operation IDs, tags, request/response schema; infer sequence from tags.

### Source C: JS Bundle Analysis

Search JS for API endpoint strings and call patterns:

```javascript
// In bundle, search for /api/ endpoints
fetch('/api/cart/add-item', {method: 'POST', body: JSON.stringify({itemId, qty})})
  .then(r => r.json())
  .then(cartState => {
    // Next step inferred from callers
    fetch('/api/cart/set-delivery', ...)
  })
```

Extract call graph and infer sequence from .then chains, async/await.

### Source D: Mobile App Decompile

Decompile APK/IPA and search for API endpoint strings:

```
strings app.apk | grep -E '^/api/' | sort | uniq
→ /api/cart/add
  /api/delivery/set
  /api/discount/apply
  /api/payment/start
  /api/payment/confirm
```

Cross-reference with method calls to infer sequence.

## Phase 1: State Machine Inference

For each endpoint in the sequence, infer preconditions and post-conditions:

```
Endpoint: POST /api/payment/confirm
Precondition:
  - User is authenticated
  - Cart is non-empty (inferred from cart/{itemId} present)
  - Delivery method is set (inferred from set-delivery call in prior sequence)
  - Discount applied? (optional, inferred from optional apply-discount call)

Post-condition:
  - Order is created with status=pending_payment
  - Payment processing begins
  - Cart is cleared

State indicators (from response):
  - "orderId": indicates order creation
  - "status": "pending_payment" indicates successful creation
  - "paymentUrl": indicates payment processor redirect

Precondition guards observed?
  - GET /api/payment/confirm without prior cart/delivery → expected: 400, actual?
  - GET /api/payment/confirm with empty cart → expected: 400, actual?
```

## Phase 2: Sequence Reordering Tests

Test each reordering and document the result:

### Test A: Skip a Single Step

```
Original sequence:
1. POST /cart/add-item {itemId}
2. POST /cart/set-delivery {address}
3. POST /payment/confirm {paymentMethodId}

Test: skip step 2
1. POST /cart/add-item {itemId}
3. POST /payment/confirm {paymentMethodId}

Expected: 400 delivery not set, actual: 200 order created?
  → FAIL: missing state guard on delivery
```

### Test B: Reorder Later Steps

```
Original:
1. add-item
2. set-delivery
3. apply-discount
4. confirm-payment

Test: apply-discount before set-delivery
1. add-item
3. apply-discount
2. set-delivery
4. confirm-payment

Expected: discount not applied (order state unclear), actual: discount applied then delivery changed?
```

### Test C: Replay a Step

```
Original:
1. add-item {item_a}
2. add-item {item_b}
3. confirm-payment

Test: replay step 2
1. add-item {item_a}
2. add-item {item_b}
2. add-item {item_b}  (repeat)
3. confirm-payment

Expected: item_b in cart once, actual: item_b qty=2?
```

## Phase 3: API Precondition Completeness Check

For each endpoint, verify the server checks all required preconditions:

```
Checklist for POST /api/payment/confirm:
- [ ] User authenticated? Test: /confirm as unauthenticated → 401 expected
- [ ] Cart non-empty? Test: /confirm with empty cart → 400 expected
- [ ] Delivery set? Test: /confirm without set-delivery step → 400 expected
- [ ] Valid payment method? Test: /confirm with nonexistent methodId → 400 expected
- [ ] Total amount matches cart? Test: /confirm with manipulated total param → 400 expected

Unchecked preconditions are potential bypasses.
```

## Phase 4: Output Format

Produce under the run artifact root, named `api_sequences_<target>_<timestamp>/`:

- `01_extracted_sequences.txt` — happy-path and variant workflows, all endpoints listed.
- `02_state_machine_inferred.txt` — preconditions and post-conditions per endpoint, state indicators.
- `03_reordering_tests.txt` — each reordering, expected result, actual result, pass/fail.
- `04_precondition_coverage.txt` — which preconditions are guarded, which are missing.
- `05_bypass_candidates.txt` — endpoints with unchecked preconditions, permutations to test.
- `README.md` — summary, most likely business-logic bug, exploit chain.

## Submission Gates

- [ ] Sequences are extracted from actual application workflow (not speculative).
- [ ] State machine is inferred with evidence (response status, response body fields).
- [ ] Reordering tests show both success (correct guard) and failure (missing guard).
- [ ] Precondition coverage maps each guard tested, not just asserted.
- [ ] Bypass is demonstrated if found (not hypothetical).

## See Also

- `agent_skills/packs/web_hunter/SKILL.md` — endpoint discovery.
- `agent_skills/packs/triage_validation/SKILL.md` — evidence gates.

## Exclusions

- No actually mutating data beyond test workflows (do not drain real carts or confirm real orders).
- No brute-forcing state values; infer from happy-path observations.
