from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from secops.services.skills import SkillPack
from secops.skills.contracts import ReconFeatureSet
from secops.skills.skilllets import parent_skills_for_skilllets


@dataclass(frozen=True)
class ScoreParts:
    surface_match: float = 0.0
    evidence_strength: float = 0.0
    mode_fit: float = 0.0
    tool_readiness: float = 0.0
    learning_prior: float = 0.0
    operator_intent: float = 0.0
    penalties: float = 0.0

    @property
    def total(self) -> float:
        raw = (
            0.35 * self.surface_match
            + 0.25 * self.evidence_strength
            + 0.15 * self.mode_fit
            + 0.10 * self.tool_readiness
            + 0.10 * self.learning_prior
            + 0.05 * self.operator_intent
            - self.penalties
        )
        return round(max(0.0, min(1.0, raw)), 4)


SKILL_SURFACES: dict[str, tuple[str, ...]] = {
    "web_hunter": (
        "web_endpoints",
        "headers",
        "forms",
        "js_bundles",
        "cms_indicators",
        "plugin_indicators",
        "auth_indicators",
        "xss_indicators",
        "lfi_indicators",
        "ssrf_indicators",
        "ssti_indicators",
        "capabilities",
        "blind_inference_signals",
        "payload_filter_signals",
        "stagnation_signals",
    ),
    "api_security": ("api_schemas", "graphql", "auth_indicators", "object_id_params", "web_endpoints", "capabilities", "blind_inference_signals"),
    "bizlogic_hunter": ("business_logic_terms", "object_id_params", "auth_indicators", "capabilities"),
    "mobile_pentester": ("apk_metadata", "exported_android_components", "mobile_permissions", "mobile_deeplinks"),
    "reverse_engineer": ("apk_metadata", "source_languages", "dependency_manifests"),
    "cicd_redteam": ("cicd_files", "secret_config_candidates", "source_languages"),
    "cloud_security": ("cloud_indicators",),
    "ad_attacker": ("ad_indicators",),
    "credential_tester": ("credential_indicators", "auth_indicators", "capabilities"),
    "vuln_scanner": (
        "cves",
        "detection_engine_matches",
        "versions",
        "services",
        "cms_indicators",
        "plugin_indicators",
        "tls_indicators",
        "scanner_indicators",
        "enterprise_protocol_indicators",
    ),
    "threat_modeler": ("source_languages", "source_frameworks", "risky_source_sinks", "agentic_security_indicators"),
    "poc_validator": (
        "web_endpoints",
        "cms_indicators",
        "plugin_indicators",
        "risky_source_sinks",
        "xss_indicators",
        "lfi_indicators",
        "ssrf_indicators",
        "ssti_indicators",
        "cves",
        "business_logic_terms",
        "api_schemas",
        "graphql",
        "capabilities",
        "blind_inference_signals",
        "payload_filter_signals",
        "tls_indicators",
        "scanner_indicators",
        "enterprise_protocol_indicators",
        "agentic_security_indicators",
    ),
    "attack_planner": ("web_endpoints", "api_schemas", "business_logic_terms", "cves", "capabilities", "stagnation_signals"),
    "exploit_chainer": ("capabilities", "auth_indicators", "lfi_indicators", "ssrf_indicators", "ssti_indicators", "payload_filter_signals"),
    "payload_crafter": ("payload_filter_signals", "blind_inference_signals", "xss_indicators", "lfi_indicators", "ssrf_indicators", "ssti_indicators", "capabilities"),
    "report_generator": ("web_endpoints", "risky_source_sinks", "cves", "business_logic_terms"),
    "bug_bounty": ("web_endpoints", "api_schemas", "business_logic_terms"),
    "recon_advisor": ("services", "ports", "versions"),
    "osint_collector": ("services", "web_endpoints", "headers"),
}


def score_skill(
    pack: SkillPack,
    features: ReconFeatureSet,
    *,
    run_config: dict[str, Any] | None = None,
    learning_boosts: dict[str, float] | None = None,
    operator_intent: dict[str, float] | None = None,
) -> tuple[float, float, str, list[str], ScoreParts]:
    run_config = run_config or {}
    learning_boosts = learning_boosts or {}
    operator_intent = operator_intent or {}
    surface_fields = SKILL_SURFACES.get(pack.id, tuple(pack.tags or []))
    matched_fields = []
    for field in surface_fields:
        if bool(getattr(features, field, None)):
            matched_fields.append(field)
    surface_match = min(1.0, len(matched_fields) / max(1, min(3, len(surface_fields) or 1)))
    evidence_count = sum(len(getattr(features, field, []) or []) for field in matched_fields)
    evidence_strength = min(1.0, evidence_count / 6.0)
    mode_fit = 1.0 if features.mode in pack.modes else 0.45 if "pentest" in pack.modes else 0.2
    if features.mode == "private_source_audit" and pack.id in {"threat_modeler", "cicd_redteam", "api_security", "bizlogic_hunter"}:
        mode_fit = max(mode_fit, 0.95)
    tool_ready = _tool_readiness(pack, run_config)
    learning = max(0.0, min(0.2, float(learning_boosts.get(pack.id, 0.0))))
    operator = max(0.0, min(1.0, float(operator_intent.get(pack.id, 0.0))))
    lock = _active_surface_lock(run_config)
    locked_allowed = _lock_allowed_parent_skills(lock)
    proof_boost_skills = {
        "web_hunter",
        "api_security",
        "vuln_scanner",
        "poc_validator",
        "attack_planner",
        "exploit_chainer",
        "payload_crafter",
        "recon_advisor",
    }
    if locked_allowed and not _surface_lock_focus_only(run_config):
        proof_boost_skills = proof_boost_skills & locked_allowed
    if _proof_profile_enabled(run_config) and pack.id in proof_boost_skills:
        operator = max(operator, 0.85)
        if matched_fields:
            surface_match = min(1.0, surface_match + 0.18)
            evidence_strength = min(1.0, evidence_strength + 0.15)
    penalties = 0.08 * len(features.negative_signals) if matched_fields else 0.0
    penalties += _contextual_penalty(pack.id, features, matched_fields, evidence_count)
    parts = ScoreParts(
        surface_match=surface_match,
        evidence_strength=evidence_strength,
        mode_fit=mode_fit,
        tool_readiness=tool_ready,
        learning_prior=learning,
        operator_intent=operator,
        penalties=min(0.4, penalties),
    )
    reason = _reason(pack.id, matched_fields, evidence_count, parts)
    confidence = round(min(1.0, (parts.total + evidence_strength) / 2 + 0.1), 4)
    return parts.total, confidence, reason, matched_fields, parts


def _tool_readiness(pack: SkillPack, run_config: dict[str, Any]) -> float:
    meta = getattr(pack, "metadata", {}) or {}
    required, optional = _pack_tool_lists(meta)
    available = set(str(item) for item in (run_config.get("available_tools") or []))
    fallback = meta.get("fallback_chain") if isinstance(meta, dict) else None
    if required and not all(item in available for item in required):
        # If a fallback chain covers the missing required verbs, soften the penalty.
        if isinstance(fallback, dict) and any(
            any(tool in available for tool in (options or []))
            for options in fallback.values()
        ):
            return 0.45
        return 0.25
    if optional:
        present = sum(1 for item in optional if item in available)
        return max(0.65, min(1.0, 0.65 + 0.35 * present / len(optional)))
    return 0.85


def _pack_tool_lists(meta: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Read tool requirements from both legacy ``tool_requirements`` and the
    Phase 1/2 flat ``required_tools``/``optional_tools`` keys, deduping."""
    required: list[str] = []
    optional: list[str] = []
    requirements = meta.get("tool_requirements") if isinstance(meta, dict) else None
    if isinstance(requirements, dict):
        required.extend(str(item) for item in (requirements.get("required") or []))
        optional.extend(str(item) for item in (requirements.get("optional") or []))
    for item in (meta.get("required_tools") or []):
        sid = str(item)
        if sid and sid not in required:
            required.append(sid)
    for item in (meta.get("optional_tools") or []):
        sid = str(item)
        if sid and sid not in optional and sid not in required:
            optional.append(sid)
    return required, optional


def _proof_profile_enabled(run_config: dict[str, Any]) -> bool:
    validation = run_config.get("validation")
    if not isinstance(validation, dict):
        validation = {}
    risk_mode = str(validation.get("risk_mode") or "").strip().lower()
    return (
        str(validation.get("profile") or "").strip().lower() == "proof"
        and (bool(validation.get("full_capability_acknowledged")) or risk_mode == "always_attempt")
    )


def _surface_lock_focus_only(run_config: dict[str, Any]) -> bool:
    validation = run_config.get("validation")
    if not isinstance(validation, dict):
        validation = {}
    return (
        str(run_config.get("wizard_risk_profile") or "").strip().lower() == "aggressive"
        or (
            str(validation.get("profile") or "").strip().lower() == "proof"
            and str(validation.get("risk_mode") or "").strip().lower() == "always_attempt"
            and bool(validation.get("full_capability_acknowledged"))
        )
    )


def _active_surface_lock(run_config: dict[str, Any]) -> dict[str, Any]:
    lock = run_config.get("surface_lock")
    if not isinstance(lock, dict) or not bool(lock.get("active")):
        return {}
    if str(lock.get("status") or "locked") in {"proved", "negative_with_evidence", "environment_blocked", "scope_blocked", "operator_released"}:
        return {}
    return lock


def _lock_allowed_parent_skills(lock: dict[str, Any]) -> set[str]:
    if not lock:
        return set()
    explicit = {str(item) for item in (lock.get("allowed_skills") or []) if str(item).strip()}
    from_skilllets = parent_skills_for_skilllets(tuple(str(item) for item in (lock.get("allowed_skilllets") or []) if str(item).strip()))
    return explicit | from_skilllets


def _contextual_penalty(skill_id: str, features: ReconFeatureSet, matched_fields: list[str], evidence_count: int) -> float:
    """Reduce broad specialist noise when stronger web/source evidence exists.

    Lab web targets often expose host-side services and incidental words such as
    "iam", "credential", or "active directory" in logs or source snippets. Those
    should not outrank concrete route/sink evidence from browser/source review.
    """

    if not matched_fields:
        return 0.0
    web_or_source = features.target_kind == "web" or features.has_any("web_endpoints", "forms", "xss_indicators", "lfi_indicators", "ssrf_indicators", "ssti_indicators")
    if web_or_source and skill_id in {"cloud_security", "ad_attacker"} and evidence_count < 3:
        return 0.34
    if features.xss_indicators and skill_id == "credential_tester":
        strong_credential = any(
            any(marker in str(item).lower() for marker in ("default password", "default-login", "hardcoded password", "password=", "username="))
            for item in features.credential_indicators
        )
        if not strong_credential:
            return 0.16
    return 0.0


def _reason(skill_id: str, matched_fields: list[str], evidence_count: int, parts: ScoreParts) -> str:
    if not matched_fields:
        return f"{skill_id} kept as a low-confidence advisory match; no strong surface evidence yet."
    fields = ", ".join(matched_fields[:4])
    return (
        f"{skill_id} matched {fields} from {evidence_count} evidence item(s); "
        f"score={parts.total:.2f}, readiness={parts.tool_readiness:.2f}."
    )
