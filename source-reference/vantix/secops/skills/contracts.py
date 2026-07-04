from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


SkillStatus = Literal[
    "recommended",
    "applied",
    "blocked",
    "disabled",
    "missing_inputs",
    "permission_blocked",
    "environment_blocked",
    "revoked",
    "suppressed_by_surface_lock",
]


class ReconFeatureSet(BaseModel):
    run_id: str = ""
    mode: str = "pentest"
    target_kind: str = "unknown"
    services: list[str] = Field(default_factory=list)
    ports: list[str] = Field(default_factory=list)
    versions: list[str] = Field(default_factory=list)
    web_endpoints: list[str] = Field(default_factory=list)
    headers: list[str] = Field(default_factory=list)
    forms: list[str] = Field(default_factory=list)
    js_bundles: list[str] = Field(default_factory=list)
    cms_indicators: list[str] = Field(default_factory=list)
    plugin_indicators: list[str] = Field(default_factory=list)
    api_schemas: list[str] = Field(default_factory=list)
    graphql: list[str] = Field(default_factory=list)
    auth_indicators: list[str] = Field(default_factory=list)
    xss_indicators: list[str] = Field(default_factory=list)
    lfi_indicators: list[str] = Field(default_factory=list)
    ssrf_indicators: list[str] = Field(default_factory=list)
    ssti_indicators: list[str] = Field(default_factory=list)
    object_id_params: list[str] = Field(default_factory=list)
    source_languages: list[str] = Field(default_factory=list)
    source_frameworks: list[str] = Field(default_factory=list)
    risky_source_sinks: list[str] = Field(default_factory=list)
    dependency_manifests: list[str] = Field(default_factory=list)
    cicd_files: list[str] = Field(default_factory=list)
    secret_config_candidates: list[str] = Field(default_factory=list)
    apk_metadata: list[str] = Field(default_factory=list)
    exported_android_components: list[str] = Field(default_factory=list)
    mobile_permissions: list[str] = Field(default_factory=list)
    mobile_deeplinks: list[str] = Field(default_factory=list)
    cloud_indicators: list[str] = Field(default_factory=list)
    ad_indicators: list[str] = Field(default_factory=list)
    tls_indicators: list[str] = Field(default_factory=list)
    scanner_indicators: list[str] = Field(default_factory=list)
    enterprise_protocol_indicators: list[str] = Field(default_factory=list)
    agentic_security_indicators: list[str] = Field(default_factory=list)
    credential_indicators: list[str] = Field(default_factory=list)
    cves: list[str] = Field(default_factory=list)
    detection_engine_matches: list[str] = Field(default_factory=list)
    business_logic_terms: list[str] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)
    blind_inference_signals: list[str] = Field(default_factory=list)
    payload_filter_signals: list[str] = Field(default_factory=list)
    stagnation_signals: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    feature_refs: dict[str, list[str]] = Field(default_factory=dict)
    negative_signals: list[str] = Field(default_factory=list)
    source_counts: dict[str, int] = Field(default_factory=dict)

    def has_any(self, *names: str) -> bool:
        return any(bool(getattr(self, name, None)) for name in names)


class SkillRouteDecision(BaseModel):
    skill_id: str
    score: float
    confidence: float
    reason: str
    feature_refs: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    status: SkillStatus = "recommended"
    agent_roles: list[str] = Field(default_factory=list)
    hypotheses_seeded: list[str] = Field(default_factory=list)
    scope_decision_id: str | None = None
    skill_version: str = ""
    matched_capability_tags: list[str] = Field(default_factory=list)
    theory_refs: list[str] = Field(default_factory=list)
    playbook_id: str = ""
    playbook_step_id: str = ""
    evidence_gate_id: str = ""
    expected_evidence_types: list[str] = Field(default_factory=list)
    required_permissions: list[str] = Field(default_factory=list)
    missing_inputs: list[str] = Field(default_factory=list)
    blockers: list[str] = Field(default_factory=list)
    alternatives: list[dict[str, Any]] = Field(default_factory=list)
    compatibility_state: str = "compatible"
    metadata: dict[str, Any] = Field(default_factory=dict)


class SkillRouteResult(BaseModel):
    run_id: str
    features: ReconFeatureSet
    decisions: list[SkillRouteDecision]
    summary: dict[str, Any] = Field(default_factory=dict)
