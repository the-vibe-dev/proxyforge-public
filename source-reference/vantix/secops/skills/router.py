from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from secops.learning.knowledge_graph import KnowledgeGraph
from secops.models import WorkspaceRun
from secops.services.skills import SkillRegistry
from secops.services.surface_locks import ESSENTIAL_SKILLS, SurfaceLockService
from secops.skills.compatibility import check_skill_compatibility
from secops.skills.contracts import ReconFeatureSet, SkillRouteDecision, SkillRouteResult
from secops.skills.gates import apply_skill_gate
from secops.skills.scoring import score_skill


class ReconSkillRouter:
    def __init__(self, registry: SkillRegistry | None = None) -> None:
        self.registry = registry or SkillRegistry()

    def route(self, db: Session, run: WorkspaceRun, features: ReconFeatureSet) -> SkillRouteResult:
        learning_boosts = self._learning_boosts(db, features)
        operator_intent = self._operator_intent(run)
        surface_lock = SurfaceLockService().current(run)
        allowed_locked = SurfaceLockService().allowed_parent_skills(run) if surface_lock else set()
        surface_lock_focus_only = self._surface_lock_focus_only(run)
        decisions: list[SkillRouteDecision] = []
        for pack in self.registry.active():
            compatibility = check_skill_compatibility(
                pack.manifest,
                mode=run.mode,
                available_tools=set(str(item) for item in (run.config_json or {}).get("available_tools", [])),
                scope_valid=True,
                pack_metadata=pack.metadata,
            )
            score, confidence, reason, matched_fields, parts = score_skill(
                pack,
                features,
                run_config=run.config_json or {},
                learning_boosts=learning_boosts,
                operator_intent=operator_intent,
            )
            if score < 0.22 and pack.id not in self._default_skill_ids(run):
                continue
            status, gate_reason, scope_decision_id = apply_skill_gate(db, run, pack, target_ref=run.target or run.repo_path or "")
            if status == "applied" and score < 0.35:
                status = "recommended"
            if gate_reason and status in {"blocked", "disabled"}:
                reason = f"{reason} Gate: {gate_reason}"
            if compatibility.state in {"revoked", "permission_blocked", "scope_blocked", "environment_blocked"}:
                status = "blocked"
                reason = f"{reason} Compatibility: {'; '.join(compatibility.reasons)}"
            suppressed_by_lock = False
            if surface_lock and pack.id not in allowed_locked and pack.id not in ESSENTIAL_SKILLS and status in {"applied", "recommended"}:
                if surface_lock_focus_only:
                    reason = (
                        f"{reason} Surface lock {surface_lock.get('surface_type')} is active, "
                        "but full proof mode keeps it as focus guidance instead of suppressing routed skills."
                    )
                else:
                    status = "suppressed_by_surface_lock"
                    suppressed_by_lock = True
                    reason = (
                        f"{reason} Surface lock {surface_lock.get('surface_type')} is active; "
                        f"load this skill only after lock release or directly related evidence."
                    )
            roles = self._roles_for(pack, run)
            refs = self._refs_for(features, matched_fields)
            decisions.append(
                SkillRouteDecision(
                    skill_id=pack.id,
                    score=score,
                    confidence=confidence,
                    reason=reason,
                    feature_refs=matched_fields,
                    evidence_refs=refs,
                    status=status,
                    agent_roles=roles,
                    scope_decision_id=scope_decision_id,
                    skill_version=str(pack.version),
                    matched_capability_tags=list(pack.manifest.capability_tags),
                    theory_refs=list(pack.manifest.compatibility.compatible_theory_tags),
                    expected_evidence_types=list(pack.manifest.evidence_outputs.allowed_types),
                    required_permissions=list(compatibility.required_permissions),
                    missing_inputs=list(compatibility.missing_inputs),
                    blockers=list(compatibility.reasons),
                    compatibility_state=compatibility.state,
                    metadata={
                        "score_parts": parts.__dict__,
                        "tool_readiness": parts.tool_readiness,
                        "matched_fields": matched_fields,
                        "surface_lock": surface_lock,
                        "suppressed_by_surface_lock": suppressed_by_lock,
                        "surface_lock_focus_only": surface_lock_focus_only,
                        "active_skilllets": list(surface_lock.get("allowed_skilllets") or []) if surface_lock else [],
                        "manifest": {
                            "capability_tags": list(pack.manifest.capability_tags),
                            "evidence_outputs": list(pack.manifest.evidence_outputs.allowed_types),
                            "compatibility": compatibility.public(),
                            "validation_issues": [issue.model_dump(mode="json") for issue in pack.validation_issues],
                        },
                    },
                )
            )
        decisions.sort(key=lambda item: (item.status != "applied", -item.score, item.skill_id))
        return SkillRouteResult(
            run_id=run.id,
            features=features,
            decisions=decisions,
            summary=self._summary(features, decisions, surface_lock=surface_lock),
        )

    def _default_skill_ids(self, run: WorkspaceRun) -> set[str]:
        from secops.services.skills import MODE_DEFAULTS, ROLE_DEFAULTS

        ids: set[str] = set(MODE_DEFAULTS.get(run.mode, []))
        for values in ROLE_DEFAULTS.values():
            ids.update(values)
        return ids

    def _roles_for(self, pack, run: WorkspaceRun) -> list[str]:
        roles = [role for role in pack.roles if role in {"orchestrator", "recon", "researcher", "developer", "executor", "browser", "reporter"}]
        if not roles:
            roles = ["orchestrator"]
        if pack.id in {"web_hunter", "api_security", "bizlogic_hunter"} and "browser" not in roles:
            roles.append("browser")
        if run.mode == "private_source_audit" and "developer" not in roles:
            roles.append("developer")
        return sorted(set(roles))

    def _refs_for(self, features: ReconFeatureSet, matched_fields: list[str]) -> list[str]:
        refs: list[str] = []
        for field in matched_fields:
            for ref in features.feature_refs.get(field, []):
                if ref not in refs:
                    refs.append(ref)
                if len(refs) >= 20:
                    return refs
        return refs

    def _operator_intent(self, run: WorkspaceRun) -> dict[str, float]:
        config = run.config_json or {}
        intent: dict[str, float] = {}
        for skill_id in config.get("preferred_skills") or []:
            intent[str(skill_id)] = 1.0
        profile = str(config.get("scan_profile") or "").lower()
        if "source" in profile:
            intent.update({"threat_modeler": 0.8, "cicd_redteam": 0.6})
        if "deep" in profile:
            intent.update({"attack_planner": 0.6, "poc_validator": 0.7})
        validation = config.get("validation") if isinstance(config.get("validation"), dict) else {}
        if (
            str(config.get("wizard_risk_profile") or "").strip().lower() == "aggressive"
            or str(validation.get("risk_mode") or "").strip().lower() == "always_attempt"
        ):
            intent.update(
                {
                    "attack_planner": 0.9,
                    "exploit_chainer": 0.9,
                    "payload_crafter": 0.9,
                    "poc_validator": 0.9,
                    "vuln_scanner": 0.75,
                    "web_hunter": 0.75,
                    "api_security": 0.75,
                    "recon_advisor": 0.65,
                }
            )
        return intent

    def _surface_lock_focus_only(self, run: WorkspaceRun) -> bool:
        config = run.config_json or {}
        validation = config.get("validation") if isinstance(config.get("validation"), dict) else {}
        return (
            str(config.get("wizard_risk_profile") or "").strip().lower() == "aggressive"
            or (
                str(validation.get("profile") or "").strip().lower() == "proof"
                and str(validation.get("risk_mode") or "").strip().lower() == "always_attempt"
                and bool(validation.get("full_capability_acknowledged"))
            )
        )

    def _learning_boosts(self, db: Session, features: ReconFeatureSet) -> dict[str, float]:
        boosts: dict[str, float] = {}
        graph = KnowledgeGraph().load_db(db)
        for endpoint in features.web_endpoints[:20]:
            for edge in graph.recall(endpoint):
                skill_id = {
                    "idor": "api_security",
                    "authz_bypass": "bizlogic_hunter",
                    "sql_injection": "web_hunter",
                    "xss_reflected": "web_hunter",
                    "auth_weakness": "credential_tester",
                }.get(edge.vuln_class)
                if skill_id:
                    boosts[skill_id] = min(0.2, boosts.get(skill_id, 0.0) + 0.05)
        return boosts

    def _summary(self, features: ReconFeatureSet, decisions: list[SkillRouteDecision], *, surface_lock: dict[str, Any] | None = None) -> dict[str, Any]:
        return {
            "detected_surfaces": {
                "web": bool(features.web_endpoints or features.forms),
                "api": bool(features.api_schemas or features.graphql or features.object_id_params),
                "mobile": bool(features.apk_metadata or features.exported_android_components),
                "source": bool(features.source_languages or features.risky_source_sinks),
                "cloud": bool(features.cloud_indicators),
                "ad": bool(features.ad_indicators),
                "tls": bool(features.tls_indicators),
                "scanner": bool(features.scanner_indicators),
                "enterprise_protocol": bool(features.enterprise_protocol_indicators),
                "agentic_security": bool(features.agentic_security_indicators),
                "capability_chain": bool(features.capabilities),
                "blind_inference": bool(features.blind_inference_signals),
                "payload_filter": bool(features.payload_filter_signals),
                "stagnation": bool(features.stagnation_signals),
            },
            "applied_count": sum(1 for item in decisions if item.status == "applied"),
            "blocked_count": sum(1 for item in decisions if item.status == "blocked"),
            "recommended_count": sum(1 for item in decisions if item.status == "recommended"),
            "suppressed_by_surface_lock_count": sum(1 for item in decisions if item.status == "suppressed_by_surface_lock"),
            "surface_lock": dict(surface_lock or {}),
        }
