"""V3-09 — ApiSequenceVerifier.

Replays an ordered list of HTTP requests; asserts cumulative final
state. Two modes:

* ``mode="fixture"``: each step carries a ``response`` dict — the
  verifier just checks per-step ``expect`` against the supplied
  responses. No network.
* ``mode="live"``: each step carries a ``request`` dict; the verifier
  dispatches ``HttpVerifier`` per step and threads the previous step's
  ``signal`` into ``ctx.extras["prev_signal"]``.

Schema:

    mode: "fixture" | "live"
    steps:
        - request: {url, method, headers, body}        # live
          response: {status, body_sha256, length, headers}  # fixture
          expect: {status, body_contains, header_contains}
    final_expect: {status, body_contains}             # checked against last step's signal

Returns ``validated=False`` on the first failure (fail-fast: an API
sequence is only meaningful end-to-end).
"""
from __future__ import annotations

import hashlib
from typing import Any

from secops.verify.base import ReplaySpec, ReplayVerifier, VerifyContext, VerifyOutcome
from secops.verify.http import HttpVerifier


class ApiSequenceVerifier(ReplayVerifier):
    type = "api_sequence"

    def __init__(self, http: HttpVerifier | None = None) -> None:
        self._http = http or HttpVerifier()

    def verify(self, spec: ReplaySpec, ctx: VerifyContext) -> VerifyOutcome:
        payload = spec.payload
        mode = str(payload.get("mode") or "fixture").lower()
        steps = list(payload.get("steps") or [])
        if not steps:
            return VerifyOutcome(validated=False, reason="api_sequence.steps is empty")

        executed: list[dict[str, Any]] = []
        last_signal: dict[str, Any] = {}
        for index, step in enumerate(steps):
            expect = dict(step.get("expect") or {})
            if mode == "fixture":
                response = dict(step.get("response") or {})
                signal = {
                    "status": response.get("status"),
                    "length": int(response.get("length") or 0),
                    "body_sha256": response.get("body_sha256")
                        or hashlib.sha256(str(response.get("body") or "").encode("utf-8")).hexdigest(),
                    "headers": dict(response.get("headers") or {}),
                }
                failed = _check_step_expect(signal, expect, body=response.get("body") or "")
            elif mode == "live":
                request = dict(step.get("request") or {})
                if not request:
                    return VerifyOutcome(validated=False, reason=f"step {index} missing request")
                outcome = self._http.verify(ReplaySpec(type="http", payload={**request, "expect": expect}), ctx)
                signal = dict(outcome.signal)
                failed = [] if outcome.validated else [outcome.reason]
            else:
                return VerifyOutcome(validated=False, reason=f"unknown api_sequence.mode={mode!r}")

            executed.append({"index": index, "signal": signal, "failed": failed})
            if failed:
                return VerifyOutcome(
                    validated=False,
                    reason=f"step {index}: {'; '.join(failed)}",
                    signal={"steps": executed},
                )
            last_signal = signal

        final_expect = dict(payload.get("final_expect") or {})
        if final_expect:
            failed = _check_step_expect(last_signal, final_expect, body="")
            if failed:
                return VerifyOutcome(
                    validated=False, reason=f"final: {'; '.join(failed)}",
                    signal={"steps": executed},
                )
        return VerifyOutcome(validated=True, signal={"steps": executed, "final": last_signal})


def _check_step_expect(signal: dict[str, Any], expect: dict[str, Any], *, body: str) -> list[str]:
    failed: list[str] = []
    if "status" in expect and int(expect["status"]) != int(signal.get("status") or 0):
        failed.append(f"status {signal.get('status')} != {expect['status']}")
    body_contains = expect.get("body_contains")
    if body_contains and str(body_contains) not in str(body or ""):
        failed.append("body_contains not matched")
    for h_name, h_sub in (expect.get("header_contains") or {}).items():
        if str(h_sub) not in (signal.get("headers") or {}).get(str(h_name), ""):
            failed.append(f"header {h_name} missing expected substring")
    return failed


__all__ = ["ApiSequenceVerifier"]
