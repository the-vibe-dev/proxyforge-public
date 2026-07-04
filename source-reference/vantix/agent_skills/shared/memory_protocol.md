# Memory Protocol

- On session start AND immediately after any context compaction or summarization, rehydrate authorization and run state before evaluating scope. Read in this order: (1) `claude_bbp.md` "Lab Environment and Authorization" block, (2) the active program scope file under `docs/local/bugbounty/<program>/scope.md` if one is in play, (3) the project's MEMORY.md entries for active engagements. This is mandatory, not "when time allows" — compaction is the moment it matters.
- Retrieve memory before external research when time allows.
- Write compact checkpoints at phase boundaries, approval blocks, failures, replans, and close.
- Store reusable facts, validated procedures, failed paths, and next actions.
- Keep memory dense and machine-reviewable; avoid narrative padding.
