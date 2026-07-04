from __future__ import annotations

from typing import Any

from secops.external_knowledge.models import ExternalKnowledgeObject


def build_safe_probe_plan(payload_family: ExternalKnowledgeObject, target_context: dict[str, Any]) -> dict[str, Any]:
    if payload_family.object_type != "payload_family":
        raise ValueError("safe probe planning requires a payload_family object")
    if not target_context.get("scope_authorized"):
        return {
            "status": "blocked",
            "reason": "missing_scope_authorization",
            "payload_templates": [],
            "expected_signals": [],
            "stop_conditions": ["target_out_of_scope"],
            "evidence_requirements": ["scope_record"],
        }
    if payload_family.risk.destructive_potential == "high":
        return {
            "status": "requires_manual_approval",
            "reason": "destructive_risk_high",
            "payload_templates": [],
            "expected_signals": payload_family.evidence_model.expected_positive_signals,
            "stop_conditions": ["destructive_payload_required"],
            "evidence_requirements": ["manual_approval", "scope_record", "validation_oracle"],
        }
    payload_refs = list(payload_family.payload.get("payload_template_refs") or [])[:3]
    return {
        "status": "planned",
        "payload_templates": payload_refs,
        "expected_signals": payload_family.evidence_model.expected_positive_signals,
        "rate_limit": {"max_variants": 3, "max_bypass_attempts": 2, "backoff": "exponential"},
        "stop_conditions": ["authz_boundary_reached", "rate_limit_detected", "target_out_of_scope", "missing_validation_oracle"],
        "evidence_requirements": ["paired_control", "request_response_diff", "negative_control"],
    }
