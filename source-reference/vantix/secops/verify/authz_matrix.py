"""V3-10 — AuthzMatrixVerifier.

Replays a single probe across N principals and asserts the resulting
allow/deny matrix matches the expected one. Single biggest unblock for
IDOR / privilege-escalation findings: instead of running the same
verifier 5x by hand, encode the expected allow/deny set and prove the
target enforces it.

Two modes:

* ``mode="fixture"``: ``responses_by_principal`` is a dict keyed on
  principal name with ``{status, body_contains, length}`` per entry.
* ``mode="live"``: ``probe`` is the request template; ``principals`` is
  a list of ``{name, headers}`` overlays applied on top.

Classification: by default any 2xx is ``allow``, any 4xx is ``deny``,
anything else is ``error``. Override via ``classify``:

    classify:
        allow_status: [200, 302]
        deny_status:  [401, 403]

Expectation under ``matrix`` is ``{principal_name: "allow"|"deny"}``.
Mismatches fail with an explicit per-principal diff in the signal.
"""
from __future__ import annotations

from typing import Any

from secops.verify.base import ReplaySpec, ReplayVerifier, VerifyContext, VerifyOutcome
from secops.verify.http import HttpVerifier


_DEFAULT_ALLOW = (200, 201, 202, 204, 301, 302, 303)
_DEFAULT_DENY = (401, 403)


class AuthzMatrixVerifier(ReplayVerifier):
    type = "authz_matrix"

    def __init__(self, http: HttpVerifier | None = None) -> None:
        self._http = http or HttpVerifier()

    def verify(self, spec: ReplaySpec, ctx: VerifyContext) -> VerifyOutcome:
        payload = spec.payload
        mode = str(payload.get("mode") or "fixture").lower()
        matrix = dict(payload.get("matrix") or {})
        if not matrix:
            return VerifyOutcome(validated=False, reason="authz_matrix.matrix is empty")

        classify = payload.get("classify") or {}
        allow = tuple(int(x) for x in (classify.get("allow_status") or _DEFAULT_ALLOW))
        deny = tuple(int(x) for x in (classify.get("deny_status") or _DEFAULT_DENY))

        observed: dict[str, dict[str, Any]] = {}
        if mode == "fixture":
            responses = dict(payload.get("responses_by_principal") or {})
            for name in matrix:
                resp = dict(responses.get(name) or {})
                observed[name] = {
                    "status": int(resp.get("status") or 0),
                    "body": str(resp.get("body") or ""),
                    "length": int(resp.get("length") or 0),
                }
        elif mode == "live":
            probe = dict(payload.get("probe") or {})
            principals = list(payload.get("principals") or [])
            if not probe or not principals:
                return VerifyOutcome(validated=False, reason="authz_matrix.live requires probe + principals")
            principal_map = {str(p.get("name")): p for p in principals if p.get("name")}
            for name in matrix:
                principal = principal_map.get(name)
                if principal is None:
                    observed[name] = {"status": 0, "body": "", "length": 0, "error": "principal_not_found"}
                    continue
                req = dict(probe)
                req["headers"] = {**(probe.get("headers") or {}), **(principal.get("headers") or {})}
                outcome = self._http.verify(ReplaySpec(type="http", payload=req), ctx)
                observed[name] = {
                    "status": int(outcome.signal.get("status") or 0),
                    "body": "",
                    "length": int(outcome.signal.get("length") or 0),
                }
        else:
            return VerifyOutcome(validated=False, reason=f"unknown authz_matrix.mode={mode!r}")

        diff: dict[str, dict[str, Any]] = {}
        failed: list[str] = []
        for name, expected in matrix.items():
            obs = observed.get(name) or {}
            classification = _classify(obs.get("status"), allow, deny)
            entry = {
                "expected": str(expected).lower(),
                "observed": classification,
                "status": obs.get("status"),
            }
            diff[name] = entry
            if str(expected).lower() != classification:
                failed.append(f"{name}: expected={expected} observed={classification} (status={obs.get('status')})")

        signal = {"matrix": diff, "allow_status": list(allow), "deny_status": list(deny)}
        if failed:
            return VerifyOutcome(validated=False, reason="; ".join(failed), signal=signal)
        return VerifyOutcome(validated=True, signal=signal)


def _classify(status: int | None, allow: tuple[int, ...], deny: tuple[int, ...]) -> str:
    s = int(status or 0)
    if s in allow:
        return "allow"
    if s in deny:
        return "deny"
    return "error"


__all__ = ["AuthzMatrixVerifier"]
