# Mutation Ladder

Disciplined request mutation instead of one-shot guesses. Every class pack
(web_hunter, api_security, oauth_sso_attacker, graphql_hunter, race_hunter,
access_control_bypass, cache_smuggling, …) should drive variation through this
ladder so results are diff-backed and reproducible.

Dense-first: `vantix lookup tag:mutation-ladder`.

## The ladder (one variable at a time)

1. **Baseline capture.** Record the exact request + full response
   (status, headers, body, timing). This is the comparison anchor.
2. **Hypothesis.** State what a single change should prove and the expected
   observable delta. No hypothesis → no mutation.
3. **Single-variable mutation.** Change exactly one dimension (see categories).
   Never co-vary; a co-varied result is inconclusive.
4. **Response diff.** Compare against baseline on status / body shape /
   length / headers / timing / error text. Record the delta.
5. **State validation.** Confirm any side effect is real (re-read the object,
   re-auth, re-fetch) — not a cached or cosmetic difference.
6. **Artifact save.** Persist request, response, and diff as evidence
   (hash-addressed); thin/ambiguous evidence is not proof.
7. **Retry budget.** Bounded retries per hypothesis (default 3). Exhausted →
   record negative evidence; do not loop.
8. **Escalate.** On a meaningful delta, hand to the matching class pack /
   `exploit_precision`; on repeated dead ends, switch skill or mark refuted.
9. **Human-review threshold.** Any mutation that is destructive-capable,
   state-changing beyond owned objects, or crosses scope → stop and request
   approval (`scope_guard` / `authorization_anchor`).

## Mutation categories

URL path · query parameter · body parameter · header · cookie · HTTP method ·
content-type · encoding (url/double/unicode/base64/case) · JSON shape
(type juggling, extra/missing keys, arrays-for-scalars) · XML entity ·
GraphQL query (alias/batch/depth/fragment) · JWT claims (alg/kid/exp/sub/scope)
· OAuth parameters (redirect_uri/state/scope/response_type) · redirect URI ·
Host header · CL/TE & duplicate/whitespace headers · cache headers/keys ·
file-upload metadata (name/type/magic) · race timing (single-packet /
last-byte) · object IDs · tenant IDs · role IDs.

## Stop conditions

Out of scope · destructive/irreversible required · real-user blast radius ·
retry budget exhausted with no delta · co-variation that cannot be isolated.

## See also
- `agent_skills/packs/exploit_precision/SKILL.md`
- `agent_skills/shared/precision_exploitation.md`
- `agent_skills/shared/false_positive_exclusions.md`
