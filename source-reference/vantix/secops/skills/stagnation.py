from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class StagnationResult:
    stalled: bool
    reason: str = ""
    recommended_pivot: str = ""
    summary: str = ""


def detect_stagnation(attempts: list[dict[str, Any]], *, elapsed_seconds: float = 0.0) -> StagnationResult:
    if elapsed_seconds >= 1500:
        return StagnationResult(True, "time-budget-near-exhaustion", "summarize-state-and-switch-strategy", "Long-running attempt without objective completion.")
    if len(attempts) < 3:
        return StagnationResult(False)

    recent = attempts[-5:]
    signatures = [str(item.get("signature") or item.get("payload") or item.get("request") or "") for item in recent]
    outcomes = [str(item.get("outcome") or item.get("status") or "") for item in recent]
    families = [str(item.get("family") or "") for item in recent if item.get("family")]
    new_evidence = [bool(item.get("new_evidence")) for item in recent]

    if len(set(signatures)) == 1 and len(signatures) >= 3:
        return StagnationResult(True, "repeated-identical-attempts", "preserve-state-and-change-payload-family", "Same request or payload repeated without progress.")
    if families and len(set(families)) == 1 and outcomes.count(outcomes[-1]) >= 3 and not any(new_evidence):
        return StagnationResult(True, "payload-family-exhausted", "switch-to-blind-inference-or-chain-pivot", "One payload family produced repeated identical outcomes.")
    if len(recent) >= 4 and not any(new_evidence):
        return StagnationResult(True, "no-new-evidence", "revisit-recon-source-or-skill-triage", "Multiple attempts produced no new evidence.")
    if any(str(item.get("status") or "").lower() in {"cancelled", "timeout", "timed_out"} for item in recent):
        return StagnationResult(True, "cancelled-or-timeout-state", "write-handoff-and-resume-from-discoveries", "Run hit cancellation or timeout signal.")
    return StagnationResult(False)
