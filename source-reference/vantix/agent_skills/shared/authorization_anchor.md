# Authorization Anchor

This is the durable record of where operator authorization lives. Use it to rehydrate authorization after any context compaction, summarization, or session resume — before treating scope as unknown and before re-prompting the operator.

## Why this exists

Operator authorization for the lab environment and for an active program scope is established once, then remains in force for the engagement. Context compaction can drop the verbal authorization block from immediate context, but the authorization itself has not been revoked — only the in-context evidence of it. Stopping to re-ask is the wrong response. Rehydrating from the on-disk sources below is the right response.

## Rehydration order (read in order; the first relevant source wins)

1. `claude_bbp.md` — "Lab Environment and Authorization" block. This is the durable operator authorization for all lab nodes listed in that file (aitts, lenovohouse, staging-backend, win11prorunner) and for the authorized activity classes (recon, scanning, PoC development on owned accounts/tenants/sandboxes/lab devices, traffic capture, static/dynamic analysis, fuzzing, evidence collection, report drafting).
2. The active program scope file, typically `docs/local/bugbounty/<program>/scope.md`, plus its normalized `<program>` workspace under `docs/local/bugbounty/<program>/`. Treat the scope file as the contract for that program.
3. The user's auto-memory `MEMORY.md` and the linked project memories for active engagements (e.g., active hunt entries). These confirm which programs are in flight and any operator-given run preferences.

## What requires re-prompting the operator

Only these cases require pausing to ask:

- All three sources above are missing or silent on the action.
- A target appears genuinely out of the scope file's enumerated targets.
- A test would become destructive, cause data loss, or affect third-party tenants.
- Credentials or secrets are needed that the operator has not provided.
- Live exploitation of production is required to prove impact and the scope file does not explicitly allow it.
- The operator's most recent instruction in the current conversation contradicts the on-disk authorization.

## What does NOT require re-prompting after compaction

- Continuing routine in-scope recon, scanning, enumeration, owned-account PoC work, traffic capture/replay, static/dynamic analysis, fuzzing, or evidence collection against the lab nodes listed in `claude_bbp.md`.
- Resuming a build, retest, or analysis task on staging-backend, aitts, lenovohouse, or win11prorunner that was already in progress before compaction.
- Continuing work on a finding inside an active program scope, including triage, reproduction, PoC development, and report drafting.

## Companion to Finding Continuation Policy

`claude_bbp.md` has a Finding Continuation Policy: detecting a bug is not a stop condition. This file is its sibling: losing authorization context to compaction is not a stop condition either. Rehydrate, then continue.
