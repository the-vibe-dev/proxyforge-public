from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from typing import Literal


ScannerSeverity = Literal["info", "warning", "high", "critical"]


@dataclass(frozen=True)
class SkillScannerFinding:
    severity: ScannerSeverity
    field_path: str
    message: str
    evidence_hash: str
    recommended_action: str

    def public(self) -> dict[str, str]:
        return {
            "severity": self.severity,
            "field_path": self.field_path,
            "message": self.message,
            "evidence_hash": self.evidence_hash,
            "recommended_action": self.recommended_action,
        }


ZERO_WIDTH = {"\u200b", "\u200c", "\u200d", "\ufeff"}
SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{16,}"),
    re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----"),
]
OVERBROAD_PATTERNS = [
    re.compile(r"(?i)\b(network\s*:\s*true|shell\s*:\s*true|write\s*:\s*\*\*/\*)"),
    re.compile(r"(?i)(read\s+all\s+files|access\s+all\s+credentials|disable\s+safety)"),
]
TARGET_INSTRUCTION_PATTERNS = [
    re.compile(r"(?i)(follow|obey|execute).{0,40}(target|page|website|server).{0,40}(instruction|prompt)"),
    re.compile(r"(?i)ignore.{0,20}(system|developer|policy).{0,20}instruction"),
]


def scan_skill_text(text: str, *, field_path: str = "body") -> list[SkillScannerFinding]:
    findings: list[SkillScannerFinding] = []
    if any(ch in text for ch in ZERO_WIDTH):
        findings.append(_finding("high", field_path, "Hidden zero-width text detected", text, "Remove hidden Unicode before skill loading."))
    for pattern in SECRET_PATTERNS:
        match = pattern.search(text)
        if match:
            findings.append(_finding("critical", field_path, "Credential-like material detected", match.group(0), "Remove secrets and rotate exposed credentials."))
    for pattern in OVERBROAD_PATTERNS:
        match = pattern.search(text)
        if match:
            findings.append(_finding("high", field_path, "Overbroad permission or unsafe instruction detected", match.group(0), "Minimize permissions and require approval gates."))
    for pattern in TARGET_INSTRUCTION_PATTERNS:
        match = pattern.search(text)
        if match:
            findings.append(_finding("high", field_path, "Target-supplied instruction confusion risk detected", match.group(0), "Require target content boundaries and quote untrusted text."))
    for blob in re.findall(r"\b[A-Za-z0-9+/]{80,}={0,2}\b", text):
        if _looks_like_encoded_instruction(blob):
            findings.append(_finding("high", field_path, "Encoded instruction-like blob detected", blob, "Decode and review or remove encoded content."))
    return findings


def scan_metadata(metadata: dict[str, object]) -> list[SkillScannerFinding]:
    return scan_skill_text(str(metadata), field_path="metadata")


def _looks_like_encoded_instruction(blob: str) -> bool:
    try:
        decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
    except Exception:
        return False
    lowered = decoded[:512].decode("utf-8", errors="ignore").lower()
    return any(marker in lowered for marker in ("ignore", "instruction", "system", "curl", "token", "secret"))


def _finding(severity: ScannerSeverity, field_path: str, message: str, evidence: str, recommended_action: str) -> SkillScannerFinding:
    digest = hashlib.sha256(evidence.encode("utf-8", errors="ignore")).hexdigest()
    return SkillScannerFinding(severity=severity, field_path=field_path, message=message, evidence_hash=f"sha256:{digest}", recommended_action=recommended_action)
