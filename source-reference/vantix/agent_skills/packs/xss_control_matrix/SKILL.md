# XSS Compensating-Control Matrix and Impact Planner

Backing methodology: `docs/agent-learning/bug-bounty-methodology-playbook.md`
§10–§13 (learning sources `corpus.bb.client_side_injection`,
`corpus.bb.xss_bypass`, `corpus.bb.ato_xss`). Retrieve via
`python3 scripts/learn_engine.py --root . lookup tag:xss-compensating-controls --format prompt`.

This pack runs **after** a client-side injection candidate exists. It does
not hunt reflections — it decides whether an executing payload can reach
real impact, so time is not wasted on self-XSS or alert-only findings.
Pairs with `dom_taint_hunter` (execution) and `exploit_chainer` /
`playbook.ato_through_xss` (weaponization). Inherits
`agent_skills/shared/operating_rules.md`.

## Method

1. **Confirm execution context.** Identify the output context (HTML body,
   attribute, JS string, URL, JSON, CSS) and whether a virtual-DOM
   framework escaped the value. A string appearing in the DOM is not
   execution.
2. **Build the compensating-control matrix** for the impact path:
   - **CSP** — enforced vs report-only; `script-src` inline/eval;
     `connect-src`/`img-src` for exfiltration; `default-src` fallback.
   - **Cookies** — HttpOnly (token readable?), Secure, SameSite, Domain
     scope, lifetime.
   - **CSRF** — token presence, location, server-validated vs match-only,
     JS-readability.
   - **CORS** — allowed origins, credentials, origin reflection, and the
     **preflight reality check** (validate in the browser, not just proxy).
   - **WAF/CDN** — present? only layer or one of many? (do not run bypass
     research without explicit authorization).
   - **Output encoding** — per render location; differs by context.
   - **Cache** — cacheable + reflected = impact multiplier (document only).
3. **Plan impact before payload work** in this order: session hijack →
   forced action / session riding → data exfiltration → privilege
   escalation → business-logic harm.
4. **Plan delivery and reject self-XSS.** Reflected needs a URL-deliverable
   sink; stored needs a render location a real victim class views; DOM
   needs URL/fragment delivery validated in a browser. If only the
   attacker can trigger it on themselves, it is self-XSS — stop.

Relevant theories: `client.xss_compensating_control_gap`,
`ato.via_client_side_injection`, `injection.xss.{reflected,stored,dom}`.

## Evidence

Record the control-posture evidence, the impact-path evidence, and the
not-self-XSS justification. Demonstrate token readability without
transmitting real data off-system unless program rules explicitly allow it.

## Exclusions

- No WAF-bypass research or cache poisoning without explicit authorization.
- No exfiltration of real user data; owned accounts and canaries only.
- No alert-only or self-XSS submissions.

## See Also

- `agent_skills/packs/dom_taint_hunter/SKILL.md` — execution discovery
- `agent_skills/packs/exploit_chainer/SKILL.md` — ATO weaponization
- `playbooks/templates/playbook.ato_through_xss.playbook.yaml`
