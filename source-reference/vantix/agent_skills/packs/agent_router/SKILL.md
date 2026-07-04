---
name: Agent Router
description: Multi-agent router by surface, bug class, confidence, evidence requirements, model tier, cost, and risk. Maintains audit log of routing decisions.
---
# Agent Router

A finding arrives: XSS on a marketing subdomain with low confidence. Do you route it to `web_hunter` (broad, fast) or `xss_specialist` (deep, slower)? A race-condition proof on payment flows costs $5k to validate but pays $50k if accepted. A third-party JavaScript injection needs both code review and runtime verification. The router decides: which pack, which model (Haiku / Sonnet / Opus), when to escalate, and logs every decision for audit.

Composes with `shared/scope_guard.md`, `shared/execution_policy.md`, `packs/triage_validation/SKILL.md` (confidence thresholds), `packs/bug_bounty/SKILL.md` (program policy).

## When to Use

- Multiple packs are capable of handling a candidate finding; need deterministic routing.
- Model budget is limited (Opus calls cost 3x Haiku); route accordingly.
- Confidence or evidence gaps require human review or escalated model.
- Risk-tier on program forbids certain scan classes (no race attacks on payment systems with strict scoping).
- Audit trail is required for compliance or operator review.

## Operating Rules

- **Surface-to-pack mapping**: web endpoint → web_hunter, API endpoint → api_security, GraphQL mutation → graphql_hunter, smart contract → web3_audit. One primary pack per surface; fallback is listed.
- **Confidence escalation**: confidence < 40% → require human review or escalate to Opus. 40-75% → default model (Haiku). 75%+ → can route to cheaper packs.
- **Cost-class assignment**: cost-per-finding < $100 (opportunistic) → route to fast pack. $100-$1000 (standard) → default. >$1000 (high-value) → deep pack, Opus model, retry on failure.
- **Evidence gates**: XSS requires PoC in target context; SQL injection requires data exfiltration or behavioral proof; race conditions require baseline-vs-race-batch evidence. No route without evidence gate.
- **Risk-tier gating**: program forbids "race attacks on payment" → route race findings to human-review queue, not automated race-hunter pack.
- **Audit log**: record decision (pack, model, reasoning) with timestamp, program, finding-id, confidence, cost estimate. Queryable for operator review.

## Phase 0: Finding Classification

Intake a finding and determine: surface, class, confidence, evidence state.

```
Input:
{
  "title": "Stored XSS in comments section",
  "surface": "web_ui",
  "bug_class": "xss_stored",
  "confidence": 0.65,
  "evidence": ["dom_sink_identified", "user_input_unsanitized"],
  "program": "acme-corp",
  "cost_estimate": 200
}

Classify:
- Surface: web_ui (vs. api, graphql, smart_contract, mobile, os_command, supply_chain)
- Bug class: xss_stored (vs. sqli, ssrf, auth_bypass, race_condition, etc.)
- Confidence: 65% (based on how many evidence gates are met)
- Evidence state: ["dom_sink_identified", "user_input_unsanitized"] (what's proven, what's assumed)
```

## Phase 1: Surface-to-Pack Mapping

Route by primary surface:

```
Surface           → Primary Pack          → Fallback
web_ui            → web_hunter            → triage (human review)
api_rest          → api_security          → web_hunter
graphql           → graphql_hunter        → api_security
smart_contract    → web3_audit            → source_auditor
file_upload       → safe_scanner          → web_hunter
authentication    → oauth_attack          → api_security
cache             → cache_poison          → web_hunter
request_smuggling → smuggle               → web_hunter
payment           → race_hunt             → triage (human review, high-cost)
source_code       → source_auditor        → sast
mobile            → triage                → triage
```

Primary pack is preferred; fallback routes to a lower-specificity pack or human queue if the primary pack is unavailable or explicitly forbidden.

## Phase 2: Bug-Class Confidence Gate

Not all bug classes are equally reliable. Confidence thresholds per class:

```
Bug Class              Min Confidence for Auto-Route
xss_reflected          40%   (easy to detect in response)
xss_stored             50%   (harder: requires state + render)
xss_dom                65%   (requires JS analysis + sink tracing)
sqli_error             45%   (easy: error message is proof)
sqli_blind_timebased   70%   (requires timing measurement)
ssrf                   60%   (requires out-of-band confirmation)
auth_bypass            65%   (requires state verification)
race_condition         80%   (requires baseline-vs-race-batch)
information_disclosure 55%   (depends on sensitivity)
```

If confidence < threshold: escalate to human queue or require evidence gate (PoC, manual verification).

## Phase 3: Evidence-Requirement Gating

Each pack has minimum evidence gates:

```
Pack           Evidence Gate
web_hunter     → screenshot + HAR + PoC description
api_security   → request/response + auth context + impact description
graphql_hunter → query + mutation + schema misuse
web3_audit     → source code + compiler output + runtime proof
race_hunt      → baseline test + race-batch test (3+ attempts) + state delta
source_auditor → taint chain (source → sink) + framework context
safe_scanner   → scope approval + rate-limit profile + payload denylist
```

If evidence is incomplete: route to human queue for collection, or escalate to Opus for deeper analysis.

## Phase 4: Model-Tier Selection

Choose model based on confidence, cost, and complexity:

```
Confidence  Cost       Complexity  → Model
< 40%       any        any         → Opus (deepest analysis)
40-75%      < $100     low         → Haiku (default, cost-efficient)
40-75%      $100-1k    medium      → Sonnet (balanced)
40-75%      > $1k      high        → Opus (justify cost)
75%+        any        any         → Haiku (confident, cheap)
```

Example: Confidence 35%, high-value race-condition finding on payment endpoint.
- Confidence 35% < 40% threshold → Opus required.
- Cost estimate $5k > $1k threshold → Opus justified.
- Route decision: `race_hunt` pack, Opus model.

## Phase 5: Risk-Tier Gating

Program-level risk policy gates certain packs:

```
Program Policy:       "no race attacks on payment endpoints"
Finding Class:        "race_condition"
Surface:              "payment_checkout"
Risk Tier:            "critical_financial"
Routing Decision:     REJECT (route to human queue instead)
Audit Log:            "Blocked by program risk policy"
```

If pack is forbidden: alert operator, route to human queue, do not proceed.

## Phase 6: Cost-Class Assignment

Route to packs based on cost-per-finding estimate:

```
Cost Estimate  Category      Packs (Fast First)
< $100         opportunistic web_hunter, api_security (fast iteration)
$100-500       standard      default pack, normal model tier
$500-1k        premium       web3_audit, variant_hunt (deeper analysis)
> $1k          high-value    deep investigation, Opus, retry on failure
```

If cost estimate exceeds monthly budget: queue for later (or route to cheaper pack if available).

## Phase 7: Audit Log & Decision Record

Record every routing decision:

```json
{
  "id": "route_2026_05_14_001",
  "timestamp": "2026-05-14T09:23:45Z",
  "finding_id": "h1_12345678",
  "program": "acme-corp",
  "surface": "web_ui",
  "bug_class": "xss_stored",
  "confidence": 0.65,
  "decision": {
    "pack": "web_hunter",
    "model": "haiku",
    "reasoning": "confidence 65% >= threshold 50%, cost $200 < $500, standard path"
  },
  "gates_passed": [
    "confidence_gate",
    "surface_mapping_available",
    "evidence_sufficient",
    "program_risk_policy_passed"
  ],
  "gates_failed": [],
  "cost_estimate": 200,
  "escalation_required": false
}
```

Audit log is immutable; operator can replay routing decisions and challenge them before execution.

## Theories This Pack Owns

1. **Surface misclassification**: A finding claimed as "web_ui" is actually an API endpoint. Router detects multiple surfaces and routes to multi-surface pack (e.g., triage for manual disambiguation).
2. **Confidence thresholds as guardrails**: Low-confidence findings routed to Opus catch false-positives faster than routing to fast packs and spending time on false leads.
3. **Cost-aware routing prevents budget exhaustion**: High-value findings are routed to deep packs (and Opus); opportunistic findings to fast packs (Haiku). Monthly spend stays predictable.
4. **Risk-tier gating avoids program-specific blockers**: Some programs explicitly forbid race attacks on payment. Router detects this and redirects to human queue instead of wasting compute on a forbidden pack.
5. **Audit log enables operator replay**: If a routing decision looks wrong, operator can re-run the decision logic with different weights or confidence thresholds without re-analyzing the finding.

## Tooling

- **Routing table**: YAML or database (surface → pack mapping, confidence thresholds per class).
- **Audit log store**: immutable log (file-based, database, or append-only ledger).
- **Decision API**: HTTP endpoint that accepts a finding and returns routing decision.
- **Cost estimator**: function that maps (pack, model, program) to cost in USD or token-count.

## Submission Gates

Run `packs/triage_validation/SKILL.md` 7-Question gate. Then for this class:

- [ ] Routing table is defined and version-controlled (surface, pack, confidence thresholds).
- [ ] Program risk policy is loaded before routing (no forbidden packs).
- [ ] Evidence gates are checked; missing evidence routes to human or escalates to Opus.
- [ ] Cost estimate is within operator budget (or flagged for approval).
- [ ] Audit log entry is recorded with decision timestamp and reasoning.
- [ ] Operator reviews high-risk routing decisions (confidence < 50%, cost > $1k, risk-tier critical).

## See Also

- `agent_skills/packs/triage_validation/SKILL.md` — confidence gates
- `agent_skills/packs/bug_bounty/SKILL.md` — program policy model
- `agent_skills/shared/execution_policy.md` — Tier 1 / Tier 2 model cost
- `agent_skills/packs/web_hunter/SKILL.md` — web surface pack
- `agent_skills/packs/api_security/SKILL.md` — API surface pack

## Exclusions

- Router does not execute packs; it only makes routing decisions.
- Router does not modify findings; it only routes them.
- Router does not override program risk policy; forbidden packs are always forbidden.
- Router assumes finding data is valid; upstream triage is responsible for classification accuracy.
