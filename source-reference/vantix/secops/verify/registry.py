from __future__ import annotations

from secops.verify.base import ReplaySpec, ReplayVerifier, VerifyContext, VerifyOutcome


class VerifierRegistry:
    """Static registry mapping replay.type → verifier instance."""

    def __init__(self) -> None:
        self._verifiers: dict[str, ReplayVerifier] = {}

    def register(self, verifier: ReplayVerifier) -> None:
        kind = (verifier.type or "").strip().lower()
        if not kind:
            raise ValueError("verifier.type must be a non-empty string")
        self._verifiers[kind] = verifier

    def get(self, kind: str) -> ReplayVerifier | None:
        return self._verifiers.get((kind or "").strip().lower())

    def types(self) -> list[str]:
        return sorted(self._verifiers.keys())

    def dispatch(self, spec: ReplaySpec, ctx: VerifyContext) -> VerifyOutcome:
        verifier = self.get(spec.type)
        if verifier is None:
            return VerifyOutcome(
                validated=False,
                reason=f"no verifier registered for replay.type={spec.type!r}",
            )
        return verifier.verify(spec, ctx)


def _build_default_registry() -> VerifierRegistry:
    from secops.verify.api_sequence import ApiSequenceVerifier
    from secops.verify.artifact import ArtifactVerifier
    from secops.verify.authz_matrix import AuthzMatrixVerifier
    from secops.verify.browser import BrowserVerifier
    from secops.verify.browser_actions import BrowserActionVerifier
    from secops.verify.http import HttpVerifier
    from secops.verify.multi_step_chain import MultiStepChainVerifier
    from secops.verify.script import ScriptVerifier
    from secops.verify.side_effect_guard import SideEffectGuardVerifier
    from secops.verify.state_diff import StateDiffVerifier

    registry = VerifierRegistry()
    registry.register(HttpVerifier())
    registry.register(ArtifactVerifier())
    registry.register(ScriptVerifier())
    registry.register(BrowserVerifier())
    registry.register(BrowserActionVerifier())
    # V3-09 / V3-10 / V3-11
    registry.register(StateDiffVerifier())
    registry.register(ApiSequenceVerifier())
    registry.register(AuthzMatrixVerifier())
    registry.register(SideEffectGuardVerifier())
    registry.register(MultiStepChainVerifier(registry))
    # Extended verifier fabric (2026-05-15 audit): 13 new types.
    from secops.verify.extended_verifiers import ALL_EXTENDED_VERIFIERS

    for verifier_cls in ALL_EXTENDED_VERIFIERS:
        registry.register(verifier_cls())
    return registry


default_registry = _build_default_registry()
