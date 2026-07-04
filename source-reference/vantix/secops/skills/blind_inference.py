from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from typing import Mapping


@dataclass(frozen=True)
class HttpObservation:
    status: int = 0
    body: str = ""
    headers: Mapping[str, str] = field(default_factory=dict)
    elapsed_ms: float = 0.0

    @property
    def body_len(self) -> int:
        return len(self.body or "")

    @property
    def body_hash(self) -> str:
        return hashlib.sha256((self.body or "").encode("utf-8", errors="ignore")).hexdigest()[:16]


@dataclass(frozen=True)
class BlindInferenceDelta:
    status_changed: bool
    body_length_delta: int
    body_changed: bool
    header_changed: bool
    elapsed_delta_ms: float
    confidence: float
    reasons: list[str]


def compare_observations(
    baseline: HttpObservation,
    probe: HttpObservation,
    *,
    length_threshold: int = 24,
    timing_threshold_ms: float = 750.0,
) -> BlindInferenceDelta:
    """Score a compact blind-inference probe against a baseline response.

    The scoring is deliberately small and explainable. It is meant to help an
    agent decide whether to continue one bounded inference family, not to prove
    a vulnerability by itself.
    """

    reasons: list[str] = []
    status_changed = baseline.status != probe.status
    if status_changed:
        reasons.append(f"status changed {baseline.status}->{probe.status}")
    body_delta = probe.body_len - baseline.body_len
    if abs(body_delta) >= length_threshold:
        reasons.append(f"body length delta {body_delta}")
    body_changed = baseline.body_hash != probe.body_hash
    if body_changed and abs(body_delta) < length_threshold:
        reasons.append("body hash changed without large length shift")
    baseline_headers = {str(k).lower(): str(v) for k, v in baseline.headers.items()}
    probe_headers = {str(k).lower(): str(v) for k, v in probe.headers.items()}
    header_changed = baseline_headers != probe_headers
    if header_changed:
        reasons.append("headers changed")
    elapsed_delta = float(probe.elapsed_ms or 0.0) - float(baseline.elapsed_ms or 0.0)
    if elapsed_delta >= timing_threshold_ms:
        reasons.append(f"timing delta {elapsed_delta:.0f}ms")

    confidence = 0.0
    if status_changed:
        confidence += 0.3
    if abs(body_delta) >= length_threshold:
        confidence += 0.25
    if body_changed:
        confidence += 0.15
    if header_changed:
        confidence += 0.1
    if elapsed_delta >= timing_threshold_ms:
        confidence += 0.25
    confidence = round(max(0.0, min(1.0, confidence)), 4)
    return BlindInferenceDelta(
        status_changed=status_changed,
        body_length_delta=body_delta,
        body_changed=body_changed,
        header_changed=header_changed,
        elapsed_delta_ms=round(elapsed_delta, 3),
        confidence=confidence,
        reasons=reasons,
    )


def proof_bundle_guidance(delta: BlindInferenceDelta) -> dict[str, object]:
    """Return the minimum evidence an agent should preserve for blind proof."""

    return {
        "requires_baseline": True,
        "requires_probe": True,
        "requires_repeated_probe": delta.confidence < 0.65,
        "confidence": delta.confidence,
        "reasons": delta.reasons,
        "bundle_fields": [
            "baseline_request",
            "baseline_status_headers_body_hash_length_time",
            "probe_request",
            "probe_status_headers_body_hash_length_time",
            "delta_summary",
            "noise_notes",
        ],
    }
