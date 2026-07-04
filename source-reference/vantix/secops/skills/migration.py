from __future__ import annotations

from typing import Any

from secops.skills.manifest import SkillManifest, ValidationIssue


TAG_ALIASES: dict[str, str] = {
    "web": "surface.web.http",
    "api": "surface.api.rest",
    "graphql": "surface.api.graphql",
    "mobile": "surface.mobile.android",
    "apk": "surface.mobile.android",
    "source": "surface.source",
    "cve": "vuln.supply_chain.software",
    "cve-intel": "vuln.supply_chain.software",
    "authz": "vuln.authz.object_access",
    "idor": "vuln.authz.object_access",
    "xss": "vuln.injection.xss",
    "sqli": "vuln.injection.sql",
    "ssrf": "vuln.ssrf.server_side_fetch",
    "proof": "execution.evidence_validation",
    "report": "execution.reporting",
    "browser": "tool.browser",
}

SKILL_DEFAULT_VULNS: dict[str, list[str]] = {
    "web_hunter": ["vuln.injection.xss", "vuln.injection.sql", "vuln.ssrf.server_side_fetch", "vuln.exception.fail_open"],
    "api_security": ["vuln.authz.object_access", "vuln.authz.function_level", "vuln.authn.credential_boundary"],
    "bizlogic_hunter": ["vuln.authz.function_level", "vuln.integrity.data_update"],
    "mobile_pentester": ["vuln.mobile.storage", "vuln.authz.object_access"],
    "vuln_scanner": ["vuln.supply_chain.software"],
    "credential_tester": ["vuln.authn.credential_boundary"],
    "cicd_redteam": ["vuln.supply_chain.software", "vuln.integrity.data_update"],
    "poc_validator": ["vuln.injection.xss", "vuln.injection.sql", "vuln.authz.object_access"],
    "report_generator": ["vuln.logging.alerting_failure"],
    "threat_modeler": ["vuln.exception.fail_open", "vuln.integrity.data_update"],
}


def migrate_v1_metadata(meta: dict[str, Any], *, skill_path: str = "") -> tuple[SkillManifest, list[ValidationIssue]]:
    skill_id = str(meta.get("id") or "unknown_skill")
    warnings: list[ValidationIssue] = []
    capability_tags = _capability_tags(skill_id, meta)
    evidence_types = _evidence_types(skill_id, meta)
    if not meta.get("output_contract"):
        warnings.append(_warning(skill_path, "output_contract", "Legacy skill metadata has no explicit output contract", "Add unified manifest outputs.output_contract."))
    if not meta.get("tool_requirements"):
        warnings.append(_warning(skill_path, "tool_requirements", "Legacy skill metadata has no declared tool requirements", "Add unified manifest environment.tools."))
    if not any(tag.startswith("evidence.") for tag in capability_tags):
        warnings.append(_warning(skill_path, "tags", "v1 tags did not map to evidence capability tags", "Declare evidence outputs."))
    manifest = SkillManifest(
        id=skill_id,
        name=str(meta.get("name") or skill_id.replace("_", " ").title()),
        version=str(meta.get("version") or "1.0.0"),
        status="active",
        summary=str(meta.get("summary") or ""),
        owner={"team": "sechive-core", "maintainer": "security-platform", "review_status": "approved"},
        provenance={"source_type": "bundled", "source_uri": "agent_skills", "source_ref": skill_path, "trust_tier": "trusted", "update_policy": "pinned"},
        lifecycle={"introduced_in": "unified-system", "migrated_from": "registry.v1"},
        roles=list(meta.get("roles") or ["orchestrator"]),
        modes={"allowed": _modes_for(skill_id, meta), "requires_scope": bool(meta.get("requires_scope", True))},
        capability_tags=capability_tags,
        inputs={
            "required": [{"name": "target_profile", "type": "TargetProfile"}, {"name": "scope", "type": "ScopeEnvelope"}],
            "optional": [{"name": "recon_features", "type": "ReconFeatureSet"}, {"name": "hypothesis", "type": "Hypothesis"}],
        },
        outputs={
            "produces": [
                {"name": "observations", "type": "ObservationBundle", "required": True},
                {"name": "evidence", "type": "EvidenceRef[]", "required": False},
                {"name": "hypothesis_updates", "type": "HypothesisUpdate[]", "required": False},
                {"name": "suggested_next_actions", "type": "ActionProposal[]", "required": False},
            ],
            "output_contract": {
                "must_include": ["skill_id", "run_id", "target_ref", "evidence_refs", "confidence", "limitations"],
                **dict(meta.get("output_contract") or {}),
            },
        },
        evidence_outputs={
            "allowed_types": evidence_types,
            "redaction_policy": "standard-sensitive",
            "retention_policy": "proof-pack-default",
            "replayable": skill_id in {"web_hunter", "api_security", "poc_validator", "exploit_chainer"},
            "negative_evidence_supported": True,
        },
        validation_hooks={
            "preflight": ["scope_present", "required_inputs_present", "permission_grant_present"],
            "postconditions": ["outputs_match_contract", "evidence_refs_resolve", "redaction_applied"],
            "evidence_quality": ["proof_signal_count", "false_positive_filter_applied"],
            "learning": ["record_capability_outcome"],
        },
        environment={"tools": dict(meta.get("tool_requirements") or {}), "isolation": {"filesystem": "workspace_only", "network": "scoped_targets_only"}},
        permissions={
            "requested": _permissions_for(skill_id, meta),
            "denied": ["network.unscoped", "exfiltrate.secret"],
            "escalation_requires_approval": ["active_payload_probe", "credentialed_session_use", "high_volume_scan"],
        },
        compatibility={
            "compatible_theory_tags": [tag for tag in capability_tags if tag.startswith("vuln.")],
            "compatible_playbook_tags": ["playbook.web.*", "playbook.api.*", "playbook.mobile.*", "playbook.proof.*"],
        },
        selection_hints={"triggers": dict(meta.get("triggers") or {}), "legacy_tags": list(meta.get("tags") or [])},
        risk_controls={
            "safety_level": str(meta.get("safety_level") or "active"),
            "execution_level": str(meta.get("execution_level") or "advisory"),
            "policy_tags": ["requires_scope", "proof_first"] if bool(meta.get("requires_scope", True)) else ["proof_first"],
            "blocked_actions": list(meta.get("forbidden") or []),
        },
        prompt_contract={
            "system_instructions_ref": skill_path,
            "allowed_instruction_sources": ["bundled"],
            "prompt_injection_resistance": {
                "ignore_target_supplied_instructions": True,
                "quote_untrusted_content": True,
                "require_tool_output_boundaries": True,
            },
        },
        extensions={"v1_metadata": dict(meta)},
    )
    return manifest, warnings


def _warning(file_path: str, field_path: str, message: str, remediation: str) -> ValidationIssue:
    return ValidationIssue(file_path=file_path, field_path=field_path, severity="warning", message=message, remediation=remediation)


def _capability_tags(skill_id: str, meta: dict[str, Any]) -> list[str]:
    tags: list[str] = []
    for raw in list(meta.get("tags") or []):
        mapped = TAG_ALIASES.get(str(raw), str(raw))
        if "." in mapped:
            tags.append(mapped)
    if not any(tag.startswith("surface.") for tag in tags):
        tags.append(_default_surface(skill_id))
    if not any(tag.startswith("execution.") for tag in tags):
        level = str(meta.get("execution_level") or "advisory")
        tags.append("execution.active.gated" if level in {"gated", "active"} else "execution.passive")
    if not any(tag.startswith("evidence.") for tag in tags):
        tags.extend(f"evidence.{item}" for item in _evidence_types(skill_id, meta)[:2])
    tags.extend(SKILL_DEFAULT_VULNS.get(skill_id, []))
    return sorted(set(tags))


def _default_surface(skill_id: str) -> str:
    if "mobile" in skill_id:
        return "surface.mobile.android"
    if skill_id in {"api_security"}:
        return "surface.api.rest"
    if skill_id in {"cicd_redteam"}:
        return "surface.cicd"
    if skill_id in {"threat_modeler"}:
        return "surface.threat_model"
    if skill_id in {"reverse_engineer"}:
        return "surface.source"
    return "surface.web.http"


def _evidence_types(skill_id: str, meta: dict[str, Any]) -> list[str]:
    declared = list((meta.get("output_contract") or {}).get("evidence_types") or [])
    if declared:
        return [str(item) for item in declared]
    if skill_id == "mobile_pentester":
        return ["mobile_static_artifact", "mobile_dynamic_trace", "negative_evidence"]
    if skill_id == "threat_modeler":
        return ["threat_model_node", "coverage_matrix", "negative_evidence"]
    if skill_id == "report_generator":
        return ["coverage_matrix", "log_excerpt", "negative_evidence"]
    if skill_id in {"poc_validator", "web_hunter", "api_security", "bizlogic_hunter"}:
        return ["http_exchange", "browser_screenshot", "replay_spec", "negative_evidence"]
    return ["log_excerpt", "negative_evidence"]


def _permissions_for(skill_id: str, meta: dict[str, Any]) -> list[str]:
    requested = ["read.scope", "read.recon", "emit.evidence", "emit.hypothesis"]
    if skill_id in {"web_hunter", "api_security", "bizlogic_hunter", "poc_validator"}:
        requested.extend(["use.http_client", "use.browser"])
    if skill_id in {"mobile_pentester", "reverse_engineer"}:
        requested.extend(["read.mobile_artifact", "use.static_analyzer"])
    if skill_id in {"cicd_redteam", "threat_modeler"}:
        requested.append("read.source")
    return sorted(set(requested))


def _modes_for(skill_id: str, meta: dict[str, Any]) -> list[str]:
    modes = {str(item) for item in (meta.get("modes") or ["pentest"]) if str(item)}
    if skill_id in {"cicd_redteam", "threat_modeler", "reverse_engineer", "api_security", "bizlogic_hunter", "poc_validator", "report_generator"}:
        modes.add("private_source_audit")
        modes.add("own-source")
    return sorted(modes)
