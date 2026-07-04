---
name: attack_planner
description: Attack Planner: correlates findings into scored attack paths.
---
# Attack Planner

## Use When
correlates findings into scored attack paths. Apply this pack for roles: orchestrator, vector_store, researcher.

## Operating Rules
- Follow SecHive shared scope, evidence, memory, and execution policy.
- Produce dense, machine-reviewable notes with fields: `obs`, `evidence`, `risk`, `next`, `blocked`.
- Mark uncertainty explicitly; do not promote scanner hits to findings without validation.
- If execution is allowed, propose the least intrusive action first with noise level and evidence path.

## Role Focus
Score chains by confidence, impact, stealth, time, and prerequisites.

## Replan Triggers
- When recon or execution confirms SQL injection, auth bypass, or credential extraction, raise the score of post-auth application-surface hypotheses over unrelated broad recon.
- Model the next branch as: obtain or reuse session -> enumerate privileged routes/forms -> test upload/import/render/file sinks -> validate and clean up.
- When browser discovery is thin but HTML/JS/forms expose workflow clues, raise the score of stateful workflow completion above generic header/form matrices.
- Treat JavaScript submit targets, app-provided credentials, hidden role/state fields, and post-auth side services as replan triggers because they change the next best route family.
- When a promising exploit chain stalls, loop once through recon/browser/skills using only the new evidence from that chain, then either continue the chain or document why the specific pivot is disproven.
- Prefer short evidence-driven branch expansion over long brute-force cracking when a live session or role delta is already available.
- Treat validated primitives as capabilities, not final answers. Ask what each capability unlocks next before closing the branch.
- When progress stalls, preserve the exact tried requests, response signatures, credentials/session state, and discovered routes before switching to one new strategy.
- Prefer a single high-confidence pivot from current evidence over broad rediscovery. Good pivots include source revisit, browser revisit, compact blind inference, payload mutation, or post-auth surface sweep.

## Exclusions
No out-of-scope, destructive, persistence, DoS, credential-stuffing, or secret-disclosure actions.
