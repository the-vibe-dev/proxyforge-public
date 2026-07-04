from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class BundleValidationResult:
    bundle_id: str
    kind: str
    status: str
    content_hash: str
    trust_tier: str = "local"
    signature_status: str = "unsigned"
    reasons: list[str] = field(default_factory=list)
    path: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "bundle_id": self.bundle_id,
            "kind": self.kind,
            "status": self.status,
            "content_hash": self.content_hash,
            "trust_tier": self.trust_tier,
            "signature_status": self.signature_status,
            "reasons": list(self.reasons),
            "path": self.path,
        }


def validate_bundle_file(path: str | Path, *, expected_hash: str = "", revoked_ids: set[str] | None = None) -> BundleValidationResult:
    target = Path(path)
    data = target.read_bytes()
    content_hash = hashlib.sha256(data).hexdigest()
    payload = _load_payload(target, data)
    bundle_id = str(payload.get("id") or payload.get("name") or target.stem)
    kind = _kind_for_path(target)
    reasons: list[str] = []
    signature_status = "unsigned"
    provenance = payload.get("provenance") if isinstance(payload.get("provenance"), dict) else {}
    trust_tier = str(payload.get("trust_tier") or provenance.get("trust_tier") or "local")
    if expected_hash and expected_hash != content_hash:
        reasons.append("content hash changed")
    if bundle_id in (revoked_ids or set()) or str(payload.get("status") or "").lower() == "revoked":
        reasons.append("bundle revoked")
    sig_path = target.with_suffix(target.suffix + ".sig")
    if sig_path.is_file():
        signature_status = "verified" if sig_path.read_text(encoding="utf-8", errors="ignore").strip() == content_hash else "signature_failed"
        if signature_status == "signature_failed":
            reasons.append("signature sidecar mismatch")
    status = "passed" if not reasons else "failed"
    return BundleValidationResult(
        bundle_id=bundle_id,
        kind=kind,
        status=status,
        content_hash=content_hash,
        trust_tier=trust_tier,
        signature_status=signature_status,
        reasons=reasons,
        path=str(target),
    )


def validate_bundle_tree(root: str | Path, *, revoked_ids: set[str] | None = None) -> list[BundleValidationResult]:
    base = Path(root)
    files: list[Path] = []
    files.extend(sorted((base / "agent_skills" / "packs").glob("*/metadata.yaml")))
    files.extend(sorted((base / "theories" / "templates").glob("*.theory.yaml")))
    files.extend(sorted((base / "playbooks" / "templates").glob("*.playbook.yaml")))
    return [validate_bundle_file(path, revoked_ids=revoked_ids) for path in files if path.is_file()]


def _kind_for_path(path: Path) -> str:
    text = str(path).replace("\\", "/")
    if "/agent_skills/" in text:
        return "skill"
    if "/theories/" in text:
        return "theory"
    if "/playbooks/" in text:
        return "playbook"
    return "bundle"


def _load_payload(path: Path, data: bytes) -> dict[str, Any]:
    try:
        if path.suffix == ".json":
            loaded = json.loads(data.decode("utf-8", errors="ignore"))
        else:
            import yaml

            loaded = yaml.safe_load(data.decode("utf-8", errors="ignore"))
        return loaded if isinstance(loaded, dict) else {}
    except Exception:
        return {}


__all__ = ["BundleValidationResult", "validate_bundle_file", "validate_bundle_tree"]
