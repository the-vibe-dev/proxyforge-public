from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from secops.skills.compatibility import check_skill_compatibility
from secops.skills.manifest import SkillManifest, ValidationIssue
from secops.skills.scanner import scan_metadata, scan_skill_text


VALID_PREFIXES = {"surface", "vuln", "evidence", "execution", "agent", "tool", "framework"}


def load_ontology(path: Path | None = None) -> dict[str, Any]:
    ontology_path = path or Path("agent_skills/capability_ontology.yaml")
    if not ontology_path.exists():
        return {"namespaces": {}, "aliases": {}}
    return yaml.safe_load(ontology_path.read_text(encoding="utf-8")) or {}


def validate_skill_manifest(manifest: SkillManifest, *, file_path: str = "", body: str = "", metadata: dict[str, Any] | None = None) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    issues.extend(_validate_tags(manifest, file_path=file_path))
    issues.extend(_validate_provenance(manifest, file_path=file_path))
    issues.extend(_validate_permissions(manifest, file_path=file_path))
    issues.extend(_scanner_issues(file_path, body, metadata or {}))
    compatibility = check_skill_compatibility(manifest, mode=(manifest.modes.allowed[0] if manifest.modes.allowed else "pentest"))
    if compatibility.state in {"revoked", "permission_blocked", "scope_blocked", "environment_blocked"}:
        issues.append(
            ValidationIssue(
                file_path=file_path,
                field_path="compatibility",
                severity="blocked",
                message=f"Skill compatibility state is {compatibility.state}",
                remediation="Resolve compatibility blockers before routing this skill.",
            )
        )
    return issues


def blocking_issues(issues: list[ValidationIssue]) -> list[ValidationIssue]:
    return [issue for issue in issues if issue.severity in {"error", "blocked"}]


def _validate_tags(manifest: SkillManifest, *, file_path: str) -> list[ValidationIssue]:
    out: list[ValidationIssue] = []
    namespaces = {tag.split(".", 1)[0] for tag in manifest.capability_tags if "." in tag}
    for required in ("surface", "execution", "evidence"):
        if required not in namespaces:
            out.append(ValidationIssue(file_path=file_path, field_path="capability_tags", severity="error", message=f"Missing {required}.* capability tag."))
    for tag in manifest.capability_tags:
        prefix = tag.split(".", 1)[0]
        if prefix not in VALID_PREFIXES:
            out.append(
                ValidationIssue(
                    file_path=file_path,
                    field_path="capability_tags",
                    severity="warning",
                    message=f"Capability tag {tag!r} is outside the first-party ontology.",
                    remediation="Map freeform tags under extensions or add a first-party ontology tag.",
                )
            )
    return out


def _validate_provenance(manifest: SkillManifest, *, file_path: str) -> list[ValidationIssue]:
    out: list[ValidationIssue] = []
    if manifest.status == "revoked":
        out.append(ValidationIssue(file_path=file_path, field_path="status", severity="blocked", message="Revoked skills cannot be selected."))
    if manifest.provenance.trust_tier == "blocked" or manifest.provenance.update_policy == "blocked":
        out.append(ValidationIssue(file_path=file_path, field_path="provenance", severity="blocked", message="Skill provenance blocks runtime use."))
    if manifest.provenance.source_type != "bundled" and not manifest.provenance.content_hash:
        out.append(
            ValidationIssue(
                file_path=file_path,
                field_path="provenance.content_hash",
                severity="warning",
                message="Non-bundled skill lacks immutable content hash.",
                remediation="Pin non-bundled skills to sha256 content hashes.",
            )
        )
    return out


def _validate_permissions(manifest: SkillManifest, *, file_path: str) -> list[ValidationIssue]:
    out: list[ValidationIssue] = []
    requested = set(manifest.permissions.requested)
    if "network.unscoped" in requested or "exfiltrate.secret" in requested:
        out.append(
            ValidationIssue(
                file_path=file_path,
                field_path="permissions.requested",
                severity="blocked",
                message="Skill requests a permission that violates SecHive safety policy.",
                remediation="Use scoped network and explicit secret grants only.",
            )
        )
    if "emit.evidence" not in requested:
        out.append(ValidationIssue(file_path=file_path, field_path="permissions.requested", severity="warning", message="Skill does not declare emit.evidence."))
    return out


def _scanner_issues(file_path: str, body: str, metadata: dict[str, Any]) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    for finding in [*scan_skill_text(body), *scan_metadata(metadata)]:
        severity = "blocked" if finding.severity in {"critical", "high"} else "warning"
        issues.append(
            ValidationIssue(
                file_path=file_path,
                field_path=finding.field_path,
                severity=severity,
                message=finding.message,
                remediation=finding.recommended_action,
            )
        )
    return issues
