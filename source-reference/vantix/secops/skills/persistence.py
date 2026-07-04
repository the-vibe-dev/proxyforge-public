from __future__ import annotations

import hashlib
from typing import Any

from sqlalchemy.orm import Session

from secops.models import SkillApplication, SkillFeatureSnapshot, SkillRouteEvent, WorkspaceRun, new_id
from secops.planning.graph import HypothesisGraph
from secops.planning.hypothesis import Hypothesis
from secops.skills.contracts import SkillRouteDecision, SkillRouteResult
from secops.skills.hypothesis_seed import seed_from_skill_route
from secops.theories.registry import TheoryRegistry


_TR: TheoryRegistry | None = None


def _theory_registry() -> TheoryRegistry:
    global _TR
    if _TR is None:
        _TR = TheoryRegistry()
    return _TR


class SkillTriageStore:
    def save(self, db: Session, run: WorkspaceRun, result: SkillRouteResult, *, phase: str = "recon-skill-triage") -> None:
        features_payload = result.features.model_dump(mode="json")
        if result.summary.get("surface_lock"):
            features_payload["surface_lock"] = result.summary["surface_lock"]
        db.add(
            SkillFeatureSnapshot(
                run_id=run.id,
                phase=phase,
                features_json=features_payload,
                source_counts_json=result.features.source_counts,
            )
        )
        graph = HypothesisGraph.load(db, run)
        for decision in result.decisions:
            for role in decision.agent_roles or ["orchestrator"]:
                self._upsert_application(db, run, decision, role=role, phase=phase)
            self._event(db, run, decision, phase=phase)
            decision.hypotheses_seeded = self._seed_hypotheses(graph, run, result, decision)
        graph.persist(db, run)
        db.flush()

    def _upsert_application(self, db: Session, run: WorkspaceRun, decision: SkillRouteDecision, *, role: str, phase: str) -> None:
        row = (
            db.query(SkillApplication)
            .filter(
                SkillApplication.run_id == run.id,
                SkillApplication.agent_role == role,
                SkillApplication.skill_id == decision.skill_id,
                SkillApplication.phase == phase,
            )
            .one_or_none()
        )
        payload = {
            "status": decision.status,
            "score": decision.score,
            "confidence": decision.confidence,
            "reason": decision.reason,
            "feature_refs_json": list(decision.feature_refs),
            "evidence_refs_json": list(decision.evidence_refs),
            "scope_decision_id": decision.scope_decision_id,
            "mode": run.mode,
            "metadata_json": dict(decision.metadata),
        }
        if row is None:
            row = SkillApplication(
                id=new_id(),
                run_id=run.id,
                agent_role=role,
                skill_id=decision.skill_id,
                phase=phase,
                **payload,
            )
            db.add(row)
            return
        for key, value in payload.items():
            setattr(row, key, value)

    def _event(self, db: Session, run: WorkspaceRun, decision: SkillRouteDecision, *, phase: str) -> None:
        db.add(
            SkillRouteEvent(
                run_id=run.id,
                event_type=decision.status,
                skill_id=decision.skill_id,
                message=decision.reason,
                payload_json={
                    "phase": phase,
                    "score": decision.score,
                    "confidence": decision.confidence,
                    "feature_refs": decision.feature_refs,
                    "evidence_refs": decision.evidence_refs,
                    "suppressed_by_surface_lock": bool((decision.metadata or {}).get("suppressed_by_surface_lock")),
                    "surface_lock": dict((decision.metadata or {}).get("surface_lock") or {}),
                    "active_skilllets": list((decision.metadata or {}).get("active_skilllets") or []),
                },
            )
        )

    def _seed_hypotheses(self, graph: HypothesisGraph, run: WorkspaceRun, result: SkillRouteResult, decision: SkillRouteDecision) -> list[str]:
        if decision.status not in {"applied", "recommended"}:
            return []
        seeded_from_route = seed_from_skill_route(
            decision,
            result.features,
            run_id=run.id,
            run_target=run.target or run.repo_path or "",
        )
        if seeded_from_route:
            seeded: list[str] = []
            for item in seeded_from_route:
                graph.add(item.hypothesis)
                seeded.append(item.hypothesis.id)
            return seeded
        theories = _theory_registry().by_skill(decision.skill_id)
        if theories:
            return self._seed_theories(graph, run, decision, theories)
        templates = _HYPOTHESIS_BY_SKILL.get(decision.skill_id, [])
        seeded: list[str] = []
        for vuln_class, label in templates:
            raw = f"{run.id}:{decision.skill_id}:{vuln_class}:{','.join(decision.evidence_refs[:3])}"
            hyp_id = "skill-" + hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]
            graph.add(
                Hypothesis(
                    id=hyp_id,
                    run_id=run.id,
                    vuln_class=vuln_class,
                    target_ref=run.target or run.repo_path or label,
                    preconditions=[label],
                    likelihood=max(0.35, decision.score),
                    impact=0.7,
                    evidence_confidence=max(0.35, decision.confidence),
                    source="skill-triage",
                    evidence_refs=list(decision.evidence_refs),
                    metadata={"skill_id": decision.skill_id, "reason": decision.reason},
                )
            )
            seeded.append(hyp_id)
        return seeded

    def _seed_theories(self, graph: HypothesisGraph, run: WorkspaceRun, decision: SkillRouteDecision, theories) -> list[str]:
        seeded: list[str] = []
        for theory in theories:
            raw = f"{run.id}:{decision.skill_id}:{theory.id}:{','.join(decision.evidence_refs[:3])}"
            hyp_id = "theory-" + hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]
            graph.add(
                Hypothesis(
                    id=hyp_id,
                    run_id=run.id,
                    vuln_class=theory.vuln_class,
                    target_ref=run.target or run.repo_path or theory.title,
                    preconditions=list(theory.preconditions.get("required") or []),
                    likelihood=max(0.35, decision.score),
                    impact=0.75 if theory.severity_default in {"high", "critical"} else 0.55,
                    evidence_confidence=max(0.35, decision.confidence),
                    source="skill-triage",
                    evidence_refs=list(decision.evidence_refs),
                    theory_id=theory.id,
                    theory_version=theory.version,
                    external_mappings=dict(theory.mappings or {}),
                    evidence_gate_refs=list((theory.evidence_requirements or {}).keys()),
                    applicability_confidence=max(0.35, decision.confidence),
                    exploitability_score=max(0.35, decision.score),
                    impact_score=0.85 if theory.severity_default in {"high", "critical"} else 0.65,
                    metadata={"skill_id": decision.skill_id, "reason": decision.reason, "theory_title": theory.title},
                )
            )
            seeded.append(hyp_id)
        return seeded


_HYPOTHESIS_BY_SKILL: dict[str, list[tuple[str, str]]] = {
    "web_hunter": [("xss_reflected", "Probe reflected/filtered web inputs"), ("sql_injection", "Probe string parser boundaries")],
    "api_security": [("idor", "Check object identifier authorization"), ("authz_bypass", "Check API auth boundary")],
    "bizlogic_hunter": [("authz_bypass", "Validate business workflow boundary")],
    "credential_tester": [("auth_weakness", "Validate credential/default-login signal")],
    "cloud_security": [("ssrf", "Check metadata/cloud boundary only if in scope")],
    "mobile_pentester": [("authz_bypass", "Validate mobile exposed component/deeplink boundary")],
    "reverse_engineer": [("auth_weakness", "Review static trust boundary and secrets safely")],
    "cicd_redteam": [("privesc_chain", "Review CI/CD trust boundary")],
}
