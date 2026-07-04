from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from secops.planning.hypothesis import Hypothesis
from secops.skills.contracts import ReconFeatureSet, SkillRouteDecision
from secops.theories.registry import TheoryRegistry
from secops.playbooks.registry import PlaybookRegistry


@dataclass(frozen=True)
class SeededHypothesis:
    hypothesis: Hypothesis
    source_decision: SkillRouteDecision
    theory_ids: list[str] = field(default_factory=list)
    playbook_ids: list[str] = field(default_factory=list)


def seed_from_skill_route(
    decision: SkillRouteDecision,
    features: ReconFeatureSet,
    *,
    run_id: str,
    run_target: str = "",
    branch_id: str = "main",
) -> list[SeededHypothesis]:
    if decision.status not in {"applied", "recommended"}:
        return []
    if decision.score < 0.35 and not decision.evidence_refs:
        return []
    target_ref = _target_for(decision, features, fallback=run_target)
    if not target_ref:
        return []

    theories = _theory_registry().by_skill(decision.skill_id)
    playbooks = _playbooks_for_skill(decision.skill_id)
    theory_ids = [theory.id for theory in theories[:4]] or list(decision.theory_refs or [])
    playbook_ids = [playbook.id for playbook in playbooks[:4]]
    vuln_class = _vuln_class(decision.skill_id, decision.feature_refs)
    selected_theory = theories[0] if theories else None
    if selected_theory is not None:
        vuln_class = selected_theory.vuln_class

    hypothesis_id = _stable_id(run_id, branch_id, decision.skill_id, vuln_class, target_ref)
    severity = str(getattr(selected_theory, "severity_default", "") or "").lower()
    impact = 0.85 if severity in {"high", "critical"} else 0.62 if severity else _default_impact(vuln_class)
    hypothesis = Hypothesis(
        id=hypothesis_id,
        run_id=run_id,
        branch_id=branch_id,
        vuln_class=vuln_class,
        target_ref=target_ref,
        preconditions=list(selected_theory.preconditions.get("required") or []) if selected_theory else _preconditions(decision),
        likelihood=min(max(float(decision.score or 0.0), 0.1), 0.95),
        impact=impact,
        evidence_confidence=min(max(float(decision.confidence or 0.0), 0.1), 0.95),
        source="skill-route",
        evidence_refs=list(dict.fromkeys(decision.evidence_refs or [])),
        theory_id=selected_theory.id if selected_theory else "",
        theory_version=selected_theory.version if selected_theory else "",
        external_mappings=dict(selected_theory.mappings or {}) if selected_theory else {},
        evidence_gate_refs=[decision.evidence_gate_id] if decision.evidence_gate_id else _evidence_gate_refs(selected_theory),
        applicability_confidence=min(max(float(decision.confidence or 0.0), 0.1), 0.95),
        exploitability_score=min(max(float(decision.score or 0.0), 0.1), 0.95),
        impact_score=impact,
        metadata={
            "skill_id": decision.skill_id,
            "skill_version": decision.skill_version,
            "feature_refs": list(decision.feature_refs or []),
            "theory_ids": theory_ids,
            "playbook_ids": playbook_ids,
            "playbook_id": playbook_ids[0] if playbook_ids else decision.playbook_id,
            "playbook_step_id": decision.playbook_step_id,
            "evidence_gate_id": decision.evidence_gate_id,
            "matched_capability_tags": list(decision.matched_capability_tags or []),
            "reason": decision.reason,
        },
    )
    return [SeededHypothesis(hypothesis=hypothesis, source_decision=decision, theory_ids=theory_ids, playbook_ids=playbook_ids)]


def _stable_id(*parts: str) -> str:
    digest = hashlib.sha256("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()[:20]
    return f"hyp_{digest}"


def _target_for(decision: SkillRouteDecision, features: ReconFeatureSet, *, fallback: str = "") -> str:
    for field in decision.feature_refs:
        values = getattr(features, field, []) or []
        if values:
            return str(values[0])[:1024]
    for field in ("web_endpoints", "forms", "api_schemas", "object_id_params", "services", "ports"):
        values = getattr(features, field, []) or []
        if values:
            return str(values[0])[:1024]
    return str(fallback or "")[:1024]


def _vuln_class(skill_id: str, fields: list[str]) -> str:
    field_set = set(fields or [])
    if "object_id_params" in field_set:
        return "idor"
    if "xss_indicators" in field_set:
        return "xss_reflected"
    if "ssrf_indicators" in field_set:
        return "ssrf"
    if "lfi_indicators" in field_set:
        return "file_read"
    if "ssti_indicators" in field_set:
        return "template_injection"
    if skill_id == "api_security":
        return "authz_bypass"
    if skill_id == "credential_tester":
        return "auth_weakness"
    return f"{skill_id}_candidate"


def _default_impact(vuln_class: str) -> float:
    if vuln_class in {"idor", "authz_bypass", "sql_injection", "ssrf", "template_injection", "file_read"}:
        return 0.78
    return 0.58


def _preconditions(decision: SkillRouteDecision) -> list[str]:
    out = [f"skill:{decision.skill_id}"]
    out.extend(f"feature:{item}" for item in decision.feature_refs[:6])
    return out


def _evidence_gate_refs(theory) -> list[str]:
    if theory is None:
        return []
    req = theory.evidence_requirements or {}
    refs: list[str] = []
    for key, value in req.items():
        if isinstance(value, list):
            refs.extend(str(item.get("type") or "") for item in value if isinstance(item, dict))
        else:
            refs.append(str(key))
    return [item for item in dict.fromkeys(refs) if item]


_PLAYBOOK_REGISTRY: PlaybookRegistry | None = None
_THEORY_REGISTRY: TheoryRegistry | None = None


def _registry() -> PlaybookRegistry:
    global _PLAYBOOK_REGISTRY
    if _PLAYBOOK_REGISTRY is None:
        _PLAYBOOK_REGISTRY = PlaybookRegistry()
    return _PLAYBOOK_REGISTRY


def _theory_registry() -> TheoryRegistry:
    global _THEORY_REGISTRY
    if _THEORY_REGISTRY is None:
        _THEORY_REGISTRY = TheoryRegistry()
    return _THEORY_REGISTRY


def _playbooks_for_skill(skill_id: str):
    out = []
    for playbook in _registry().all():
        required = playbook.required_skills or {}
        values: list[str] = []
        for raw in required.values():
            if isinstance(raw, list):
                values.extend(str(item) for item in raw)
            elif isinstance(raw, str):
                values.append(raw)
        if skill_id in set(values):
            out.append(playbook)
    return out


__all__ = ["SeededHypothesis", "seed_from_skill_route"]
