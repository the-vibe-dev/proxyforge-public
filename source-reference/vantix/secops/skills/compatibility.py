from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from secops.skills.manifest import SkillManifest


@dataclass(frozen=True)
class SkillCompatibilityResult:
    state: str
    reasons: list[str] = field(default_factory=list)
    missing_inputs: list[str] = field(default_factory=list)
    missing_tools: list[str] = field(default_factory=list)
    required_permissions: list[str] = field(default_factory=list)

    def public(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "reasons": list(self.reasons),
            "missing_inputs": list(self.missing_inputs),
            "missing_tools": list(self.missing_tools),
            "required_permissions": list(self.required_permissions),
        }


def check_skill_compatibility(
    manifest: SkillManifest,
    *,
    mode: str = "pentest",
    available_tools: set[str] | None = None,
    granted_permissions: set[str] | None = None,
    scope_valid: bool = True,
    pack_metadata: dict[str, Any] | None = None,
) -> SkillCompatibilityResult:
    if manifest.status == "revoked" or manifest.provenance.trust_tier == "blocked":
        return SkillCompatibilityResult("revoked", ["Skill is revoked or blocked by provenance."])
    if mode in manifest.modes.denied or (manifest.modes.allowed and mode not in manifest.modes.allowed):
        return SkillCompatibilityResult("environment_blocked", [f"Mode {mode} is not allowed for this skill."])
    if manifest.modes.requires_scope and not scope_valid:
        return SkillCompatibilityResult("scope_blocked", ["Scope is missing or invalid."])
    available_tools = available_tools or set()
    missing_tools = _missing_tools(manifest, available_tools, pack_metadata or {})
    requested = set(manifest.permissions.requested)
    granted_permissions = granted_permissions if granted_permissions is not None else requested
    missing_permissions = sorted(requested - granted_permissions)
    if missing_permissions:
        return SkillCompatibilityResult("permission_blocked", [f"Missing permissions: {', '.join(missing_permissions)}"], required_permissions=sorted(requested))
    if missing_tools:
        return SkillCompatibilityResult("missing_tools", ["Required tool capabilities are unavailable."], missing_tools=missing_tools, required_permissions=sorted(requested))
    return SkillCompatibilityResult("compatible", required_permissions=sorted(requested))


def _missing_tools(manifest: SkillManifest, available_tools: set[str], pack_metadata: dict[str, Any]) -> list[str]:
    missing: list[str] = []
    required = manifest.environment.tools.get("required", [])
    for item in required or []:
        if isinstance(item, dict):
            name = str(item.get("name") or item.get("capability") or "")
        else:
            name = str(item)
        if name and name not in available_tools and name not in missing:
            missing.append(name)
    # Also honor the Phase 1/2 flat metadata convention.
    for item in (pack_metadata.get("required_tools") or []):
        name = str(item)
        if name and name not in available_tools and name not in missing:
            missing.append(name)
    # If a fallback_chain covers a missing required tool, drop it from the
    # missing list — the operator has at least one viable alternative.
    fallback = pack_metadata.get("fallback_chain") or {}
    if isinstance(fallback, dict):
        covered: set[str] = set()
        for verb_options in fallback.values():
            if any(tool in available_tools for tool in (verb_options or [])):
                # All tools listed under this verb are interchangeable for the
                # verb's purpose — treat each as covered.
                covered.update(str(t) for t in (verb_options or []))
        missing = [m for m in missing if m not in covered]
    return missing
