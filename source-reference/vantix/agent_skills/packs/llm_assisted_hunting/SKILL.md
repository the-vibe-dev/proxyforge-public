# LLM-Assisted Hunting (Operator-Side)

Backing methodology: `docs/agent-learning/bug-bounty-methodology-playbook.md`
§15 (learning source `corpus.bb.ai_assisted`). Retrieve via
`python3 scripts/learn_engine.py --root . lookup tag:llm-assisted --format prompt`.

This pack uses an LLM as a **hunting aid**, not as an oracle. It is
distinct from `ai_application_security` (which tests a target app's LLM
features) and `llm_redteam` (model-internal red-teaming). Every LLM output
here is an unverified hypothesis that must be checked against live program
scope and browser/proxy evidence. Inherits
`agent_skills/shared/operating_rules.md`.

## Three high-return uses

1. **Program / target selection from structured data.** Build a JSON of
   public programs (scope targets, bounty status, response metrics) via
   platform APIs, then ask the model to shortlist programs matching the
   current style (e.g. XSS hunter → authenticated apps with many subdomains
   and user-generated content; IDOR hunter → SaaS with account creation and
   multiple roles/tenants). **Verify every recommendation against current
   platform scope; never trust LLM ownership/scope claims.** Feeds
   `recon.complexity_target_selection`.
2. **Threat-model brainstorming.** Give the model the target purpose,
   roles, mechanisms, observed endpoints, and controls; request a STRIDE
   model where each threat names the mechanism, object, trust boundary,
   control under test, safe validation step, and likely impact. Mark all
   assumptions. Feeds `playbook.threat_model_to_theory`.
3. **Scan-finding interpretation.** For a scanner result (DOM manipulation,
   reflected input, JSON injection), ask what the class means, the likely
   source→sink, how to safely validate, what controls might block it, and
   whether it is likely a false positive. Confirm with evidence.

## Safeguards

- Store the prompt and output as **advisory, not evidence**.
- Do not paste secrets, tokens, customer data, or proprietary source into
  an external LLM; use a local model for sensitive context.
- Every hypothesis exits this pack with a concrete validation step.

## Exclusions

- No acting on LLM-asserted scope/ownership without platform confirmation.
- No external-LLM submission of sensitive context.

## See Also

- `agent_skills/packs/threat_modeler/SKILL.md`
- `agent_skills/packs/recon_advisor/SKILL.md`
- `playbooks/templates/playbook.threat_model_to_theory.playbook.yaml`
