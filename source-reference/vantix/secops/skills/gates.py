from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from secops.models import ScopeDecision, WorkspaceRun
from secops.services.scope_decisions import ScopeDecisionRequest, ScopeDecisionService
from secops.services.skills import SkillPack


BLOCKED_BY_DEFAULT = {
    "payload_crafter",
    "social_engineer",
    "wireless_pentester",
}
BUGBOUNTY_EXPLICIT_ENABLE_ONLY = {
    "social_engineer",
    "wireless_pentester",
}
PROOF_PROFILE_ALLOWED_LOCKED = {
    "payload_crafter",
}

# Mode × safety_level policy. Maps mode -> set of allowed safety_level values.
# Packs whose safety_level is not in the allowed set for the mode are blocked
# unless the operator has explicitly enabled the pack via run config.
# safety_level values observed in pack metadata: "passive", "active", "restricted".
MODE_SAFETY_LEVEL_POLICY: dict[str, set[str]] = {
    "private_source_audit": {"passive", "active", "controlled"},
    "bugbounty": {"passive", "active", "controlled", "restricted", "locked"},
    "bug_bounty": {"passive", "active", "controlled", "restricted", "locked"},
    "pentest": {"passive", "active", "controlled", "restricted", "locked"},
    "ctf": {"passive", "active", "controlled", "restricted", "locked"},
    "koth": {"passive", "active", "controlled", "restricted", "locked"},
    "windows-ctf": {"passive", "active", "controlled", "restricted", "locked"},
    "windows-koth": {"passive", "active", "controlled", "restricted", "locked"},
    "native_research": {"passive", "active", "controlled", "restricted", "locked"},
}


def _proof_profile_enabled(run: WorkspaceRun) -> bool:
    validation = dict((run.config_json or {}).get("validation") or {})
    risk_mode = str(validation.get("risk_mode") or "").strip().lower()
    return (
        str(validation.get("profile") or "").strip().lower() == "proof"
        and (bool(validation.get("full_capability_acknowledged")) or risk_mode == "always_attempt")
    )


def _surface_lock_allows_pack(run: WorkspaceRun, pack_id: str) -> bool:
    config = run.config_json or {}
    lock = config.get("surface_lock")
    if not isinstance(lock, dict) or not bool(lock.get("active")):
        return False
    if str(lock.get("status") or "locked") in {"proved", "negative_with_evidence", "environment_blocked", "scope_blocked", "operator_released"}:
        return False
    if run.mode not in {"pentest", "bugbounty", "bug_bounty", "ctf", "koth", "windows-ctf", "windows-koth"}:
        return False
    return pack_id in {str(item) for item in (lock.get("allowed_skills") or []) if str(item).strip()}


def apply_skill_gate(
    db: Session,
    run: WorkspaceRun,
    pack: SkillPack,
    *,
    target_ref: str,
) -> tuple[str, str, str | None]:
    config = run.config_json or {}
    proof_profile = _proof_profile_enabled(run)
    enabled_skills = set(config.get("enabled_skills") or [])
    bugbounty_scope_decision: ScopeDecision | None = None
    bugbounty_scope_allows = False
    if run.mode in {"bugbounty", "bug_bounty"}:
        bugbounty_scope_decision = record_scope_decision(db, run, target_ref=target_ref, skill_id=pack.id)
        if bugbounty_scope_decision.decision != "allowed":
            return ("blocked", bugbounty_scope_decision.reason, bugbounty_scope_decision.id)
        if pack.id in BUGBOUNTY_EXPLICIT_ENABLE_ONLY and pack.id not in enabled_skills:
            return (
                "blocked",
                "Bug Bounty mode requires explicit operator enablement for this skill class",
                bugbounty_scope_decision.id,
            )
        bugbounty_scope_allows = True
    if str(config.get("disabled_skills") or "").find(pack.id) >= 0 or pack.id in set(config.get("disabled_skills") or []):
        return ("disabled", "operator disabled this skill for the run", None)
    surface_lock_allows = _surface_lock_allows_pack(run, pack.id)
    proof_allows_locked = (proof_profile and pack.id in PROOF_PROFILE_ALLOWED_LOCKED) or surface_lock_allows
    if (
        bool(getattr(pack, "metadata", {}).get("disabled_by_default", False))
        and pack.id not in enabled_skills
        and not proof_allows_locked
        and not bugbounty_scope_allows
    ):
        return ("disabled", "skill is locked by default and needs explicit operator enablement", None)
    if pack.id in BLOCKED_BY_DEFAULT and pack.id not in enabled_skills and not proof_allows_locked and not bugbounty_scope_allows:
        return ("blocked", "skill is high-risk/advisory and is not enabled by the run profile", None)

    # Mode × safety_level tier gate: e.g., private_source_audit only allows
    # passive packs; bug-bounty blocks restricted packs unless operator-enabled.
    safety_level = str(getattr(pack, "safety_level", "active") or "active").strip().lower()
    allowed_levels = MODE_SAFETY_LEVEL_POLICY.get(run.mode)
    if allowed_levels is not None and safety_level not in allowed_levels and pack.id not in enabled_skills and not bugbounty_scope_allows:
        return (
            "blocked",
            f"mode '{run.mode}' policy disallows safety_level '{safety_level}' (allowed: {sorted(allowed_levels)})",
            None,
        )

    if run.mode == "private_source_audit" and not bool(config.get("user_declared_authorized", False)):
        return ("blocked", "Own Source Bug Hunt requires user_declared_authorized=true", None)

    if bugbounty_scope_decision is not None:
        return ("applied", "Bug Bounty scope ledger allowed this authorized validation skill", bugbounty_scope_decision.id)

    if proof_allows_locked:
        return ("applied", "target-scoped proof profile enabled this advisory validation skill", None)
    return ("applied", "mode and scope gate allowed this skill", None)


def record_scope_decision(db: Session, run: WorkspaceRun, *, target_ref: str, skill_id: str) -> ScopeDecision:
    return ScopeDecisionService().decide(
        db,
        ScopeDecisionRequest(
            run=run,
            target_ref=target_ref,
            phase="skill-gate",
            agent_role="skill-router",
            action_kind=f"skill:{skill_id}",
        ),
    )
