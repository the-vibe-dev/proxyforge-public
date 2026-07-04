from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


SkillLifecycleStatus = Literal["draft", "active", "deprecated", "revoked"]
TrustTier = Literal["trusted", "reviewed", "sandbox_only", "blocked"]
CompatibilityState = Literal[
    "compatible",
    "compatible_with_warnings",
    "missing_inputs",
    "missing_tools",
    "permission_blocked",
    "scope_blocked",
    "environment_blocked",
    "revoked",
]


class ValidationIssue(BaseModel):
    file_path: str = ""
    field_path: str = ""
    severity: Literal["info", "warning", "error", "blocked"] = "warning"
    message: str
    remediation: str = ""


class Owner(BaseModel):
    model_config = ConfigDict(extra="allow")

    team: str = "sechive-core"
    maintainer: str = "security-platform"
    review_status: Literal["unreviewed", "approved", "restricted", "revoked"] = "approved"


class Provenance(BaseModel):
    model_config = ConfigDict(extra="allow")

    source_type: Literal["bundled", "local", "marketplace", "git", "generated"] = "bundled"
    source_ref: str = ""
    source_uri: str = "internal"
    content_hash: str = ""
    signature: str = ""
    trust_tier: TrustTier = "trusted"
    update_policy: Literal["pinned", "manual_review", "auto_minor", "blocked"] = "pinned"


class Modes(BaseModel):
    model_config = ConfigDict(extra="allow")

    allowed: list[str] = Field(default_factory=lambda: ["pentest"])
    denied: list[str] = Field(default_factory=list)
    requires_scope: bool = True
    approval_required_for: list[str] = Field(default_factory=list)


class Inputs(BaseModel):
    model_config = ConfigDict(extra="allow")

    required: list[dict[str, Any]] = Field(default_factory=list)
    optional: list[dict[str, Any]] = Field(default_factory=list)
    constraints: dict[str, Any] = Field(default_factory=dict)


class Outputs(BaseModel):
    model_config = ConfigDict(extra="allow")

    produces: list[dict[str, Any]] = Field(default_factory=list)
    output_contract: dict[str, Any] = Field(default_factory=dict)


class EvidenceOutputs(BaseModel):
    model_config = ConfigDict(extra="allow")

    allowed_types: list[str] = Field(default_factory=list)
    redaction_policy: str = "standard-sensitive"
    retention_policy: str = "proof-pack-default"
    replayable: bool = False
    evidence_quality_floor: float = 0.5
    negative_evidence_supported: bool = True


class ValidationHooks(BaseModel):
    model_config = ConfigDict(extra="allow")

    preflight: list[str] = Field(default_factory=list)
    postconditions: list[str] = Field(default_factory=list)
    evidence_quality: list[str] = Field(default_factory=list)
    compatibility: list[str] = Field(default_factory=list)
    learning: list[str] = Field(default_factory=list)


class Environment(BaseModel):
    model_config = ConfigDict(extra="allow")

    runtime: dict[str, Any] = Field(default_factory=dict)
    tools: dict[str, Any] = Field(default_factory=dict)
    isolation: dict[str, Any] = Field(default_factory=dict)
    resource_limits: dict[str, Any] = Field(default_factory=dict)


class Permissions(BaseModel):
    model_config = ConfigDict(extra="allow")

    requested: list[str] = Field(default_factory=list)
    denied: list[str] = Field(default_factory=list)
    escalation_requires_approval: list[str] = Field(default_factory=list)


class Compatibility(BaseModel):
    model_config = ConfigDict(extra="allow")

    state: CompatibilityState = "compatible"
    vantix_min_version: str = "1.0.0"
    schema_min_version: str = "skill.system"
    compatible_theory_tags: list[str] = Field(default_factory=list)
    compatible_playbook_tags: list[str] = Field(default_factory=list)
    incompatible_with: list[str] = Field(default_factory=list)
    platform_notes: list[str] = Field(default_factory=list)


class ContractLineage(BaseModel):
    model_config = ConfigDict(extra="allow")

    system: str = "skill.system"
    posture: str = "unified"
    preserves: list[str] = Field(
        default_factory=lambda: [
            "strict_manifest",
            "capability_ontology",
            "provenance_governance",
            "permissions_environment",
            "evidence_outputs",
            "compatibility_checks",
            "prompt_contract",
        ]
    )
    adds: list[str] = Field(
        default_factory=lambda: [
            "proof_continuation",
            "candidate_closure",
            "theory_refs",
            "playbook_refs",
            "coverage_refs",
        ]
    )


class RiskControls(BaseModel):
    model_config = ConfigDict(extra="allow")

    safety_level: str = "active"
    execution_level: str = "gated"
    policy_tags: list[str] = Field(default_factory=lambda: ["requires_scope", "proof_first"])
    blocked_actions: list[str] = Field(default_factory=list)


class ProofContinuation(BaseModel):
    model_config = ConfigDict(extra="allow")

    enabled_by_default: bool = False
    unresolved_candidate_policy: str = "close_or_continue"
    closure_statuses: list[str] = Field(default_factory=lambda: ["validated", "negative_evidence", "blocked", "capped"])
    route_thin_fallback_required: bool = False
    max_replans: int = 3
    revisit_phases: list[str] = Field(default_factory=list)


class PromptContract(BaseModel):
    model_config = ConfigDict(extra="allow")

    system_instructions_ref: str = ""
    allowed_instruction_sources: list[str] = Field(default_factory=lambda: ["bundled"])
    prompt_injection_resistance: dict[str, Any] = Field(default_factory=dict)


class SkillManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["skill.system"] = "skill.system"
    id: str
    name: str
    version: str
    status: SkillLifecycleStatus = "active"
    summary: str = ""
    description: str = ""
    owner: Owner = Field(default_factory=Owner)
    provenance: Provenance = Field(default_factory=Provenance)
    lifecycle: dict[str, Any] = Field(default_factory=dict)
    roles: list[str] = Field(default_factory=list)
    modes: Modes = Field(default_factory=Modes)
    capability_tags: list[str] = Field(default_factory=list)
    framework_mappings: dict[str, Any] = Field(default_factory=dict)
    inputs: Inputs = Field(default_factory=Inputs)
    outputs: Outputs = Field(default_factory=Outputs)
    evidence_outputs: EvidenceOutputs = Field(default_factory=EvidenceOutputs)
    validation_hooks: ValidationHooks = Field(default_factory=ValidationHooks)
    environment: Environment = Field(default_factory=Environment)
    permissions: Permissions = Field(default_factory=Permissions)
    compatibility: Compatibility = Field(default_factory=Compatibility)
    contract_lineage: ContractLineage = Field(default_factory=ContractLineage)
    selection_hints: dict[str, Any] = Field(default_factory=dict)
    risk_controls: RiskControls = Field(default_factory=RiskControls)
    proof_continuation: ProofContinuation = Field(default_factory=ProofContinuation)
    prompt_contract: PromptContract = Field(default_factory=PromptContract)
    extensions: dict[str, Any] = Field(default_factory=dict)

    @field_validator("id")
    @classmethod
    def _id_is_stable(cls, value: str) -> str:
        if not value or not all(ch.isalnum() or ch in "_.-" for ch in value):
            raise ValueError("skill id must contain only letters, numbers, dot, dash, or underscore")
        return value

    @model_validator(mode="after")
    def _required_capabilities(self) -> "SkillManifest":
        namespaces = {tag.split(".", 1)[0] for tag in self.capability_tags if "." in tag}
        missing = {"surface", "execution", "evidence"} - namespaces
        if missing:
            raise ValueError(f"capability_tags missing required namespaces: {', '.join(sorted(missing))}")
        return self

    def public(self) -> dict[str, Any]:
        data = self.model_dump(mode="json")
        data["schema_version"] = "skill.system"
        return data


def load_manifest(path: Path) -> SkillManifest:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return SkillManifest.model_validate(data)


SkillManifestV3 = SkillManifest
