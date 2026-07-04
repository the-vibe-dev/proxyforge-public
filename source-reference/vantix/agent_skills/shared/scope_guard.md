# Scope Guard

- Require an active authorized scope before any execution-capable action.
- Authorization is durable. If an operator has already authorized work for the lab nodes listed in `claude_bbp.md` or for the active program scope file under `docs/local/bugbounty/<program>/scope.md`, that authorization survives context compaction, summarization, and session resume. After any compaction or resume, rehydrate authorization from those on-disk sources before treating scope as unknown. See `agent_skills/shared/authorization_anchor.md` for the rehydration order. Only re-prompt the operator if those sources are missing, ambiguous, or contradicted by newer instructions.
- Validate every target, callback, credential, and artifact path against scope.
- Refuse out-of-scope actions and unbounded destructive activity.
- Treat in-scope high-impact labels such as DoS, persistence-adjacent, state mutation, bypass, or local file read as risk metadata, not automatic blockers.
- When run config permits validation, attempt a bounded proof and record `risk_tags`, `impact_bound`, `state_changed`, `cleanup_attempted`, and evidence artifact paths.
- Prefer low-noise collection before active validation.
- Tag proposed actions as `quiet`, `moderate`, or `loud`.
- In target-scoped proof mode, scope remains the hard boundary but high-impact labels are not automatic stop conditions. The expected behavior is bounded proof, artifact capture, cleanup notes, and continued chaining inside the selected target.
