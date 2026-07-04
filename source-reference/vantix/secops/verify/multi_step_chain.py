"""V3-11 — MultiStepChainVerifier.

Composes an ordered list of ``[type, payload]`` verifier dispatches
into a single chain. Each step's ``signal`` is threaded into the next
step's payload under ``__prev`` so verifiers can refer to upstream
results — e.g. an api_sequence step that asserts the body sha matches
the previous step's signal.

Schema:

    steps:
        - {type: "http",        payload: {...}, expect_validated: true}
        - {type: "state_diff",  payload: {...}}
        - {type: "authz_matrix", payload: {...}}
    require_all: bool   (default true; false = pass if last step passes)
    bind_signal_to: list[str]  (keys to expose downstream under __prev)

The chain is the killer feature for the Phase 4 severity gate: a
finding that ships a ``multi_step_chain`` verifier proves
"reachable end-to-end" — not just "an HTTP call returned 200".
"""
from __future__ import annotations

from typing import Any

from secops.verify.base import ReplaySpec, ReplayVerifier, VerifyContext, VerifyOutcome
from secops.verify.registry import VerifierRegistry


class MultiStepChainVerifier(ReplayVerifier):
    type = "multi_step_chain"

    def __init__(self, registry: VerifierRegistry) -> None:
        self._registry = registry

    def verify(self, spec: ReplaySpec, ctx: VerifyContext) -> VerifyOutcome:
        payload = spec.payload
        steps = list(payload.get("steps") or [])
        if not steps:
            return VerifyOutcome(validated=False, reason="multi_step_chain.steps is empty")
        require_all = bool(payload.get("require_all", True))

        executed: list[dict[str, Any]] = []
        prev_signal: dict[str, Any] = {}
        last_validated = False
        last_outcome: VerifyOutcome | None = None
        for index, step in enumerate(steps):
            kind = str(step.get("type") or "").strip().lower()
            if not kind:
                return VerifyOutcome(
                    validated=False, reason=f"step {index} missing type",
                    signal={"steps": executed},
                )
            if kind == self.type:
                # Disallow infinite recursion.
                return VerifyOutcome(
                    validated=False, reason=f"step {index} cannot be a chain itself",
                    signal={"steps": executed},
                )
            inner_payload = dict(step.get("payload") or {})
            inner_payload["__prev"] = dict(prev_signal)
            inner = ReplaySpec(type=kind, payload=inner_payload)
            outcome = self._registry.dispatch(inner, ctx)
            executed.append({
                "index": index,
                "type": kind,
                "validated": outcome.validated,
                "reason": outcome.reason,
                "signal_keys": sorted(outcome.signal.keys()) if outcome.signal else [],
            })
            last_outcome = outcome
            last_validated = outcome.validated
            prev_signal = dict(outcome.signal) if outcome.signal else {}
            if require_all and not outcome.validated:
                return VerifyOutcome(
                    validated=False,
                    reason=f"step {index} ({kind}): {outcome.reason}",
                    signal={"steps": executed, "last_signal": prev_signal},
                )

        signal = {"steps": executed, "last_signal": prev_signal}
        if require_all:
            return VerifyOutcome(validated=True, signal=signal)
        if last_validated:
            return VerifyOutcome(validated=True, signal=signal)
        last_reason = last_outcome.reason if last_outcome else "no last step"
        return VerifyOutcome(validated=False, reason=f"final step failed: {last_reason}", signal=signal)


__all__ = ["MultiStepChainVerifier"]
