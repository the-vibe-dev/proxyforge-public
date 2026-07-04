---
name: websocket_hunter
description: Test WebSocket implementations for auth bypass, cross-site WebSocket hijacking (CSWSH), missing origin/subprotocol checks, and message injection — on authorized targets, owned sessions only.
---
# WebSocket Hunter

Dense-first: `vantix lookup tag:websocket`. Composes with `exploit_precision`,
`oauth_sso_attacker` (token-in-WS), `mutation_ladder`, `scope_guard`.

## Loop
1. **Map the handshake.** Upgrade request, `Origin` handling, cookie/token
   auth on the upgrade, subprotocol negotiation, per-message authz.
2. **CSWSH.** Replay the handshake from an attacker origin with the victim's
   ambient cookies (owned test account) — does it connect and receive
   authorized data? That is the bug.
3. **Message-layer.** Per-message authorization, IDOR over WS frames,
   injection into messages routed to a sink; subprotocol downgrade.
4. **Mutation.** Drive frame/auth variation via `mutation_ladder`
   (header/cookie/GraphQL-over-WS/JSON-shape categories), one variable.
5. **Minimal proof + FP check + route.** Owned sessions only; capture the
   cross-origin connection + authorized payload; `false_positive_exclusions.md`
   → `exploit_precision`.

## Stop / safety
Owned/test sessions only; no real-user data; scope-gated.

## See also
- `agent_skills/packs/exploit_precision/SKILL.md`
- `agent_skills/packs/graphql_hunter/SKILL.md` (GraphQL-over-WS subscription auth)
