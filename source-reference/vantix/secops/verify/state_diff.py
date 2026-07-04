"""V3-09 — StateDiffVerifier.

Captures pre/post state snapshots and asserts the diff matches an
expected shape. Two modes:

* ``mode="fixture"`` (default): payload carries ``pre_signal`` and
  ``post_signal`` dicts. Used in tests and when the executor already
  produced both observations.
* ``mode="live"``: payload carries ``probe`` (an HTTP request spec) and
  optionally an ``action`` (HTTP request fired between pre and post).
  The verifier dispatches the probe twice and compares.

Expected shape under ``expect``:

    sha_changed:        bool
    length_increased:   bool
    length_decreased:   bool
    same:               bool
    status_changed:     bool
    keys_changed:       list[str]   (compares ``signal.keys`` lists)

Empty ``expect`` means "any diff is acceptable; just record both
signals" — useful for first-write evidence capture.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from secops.verify.base import ReplaySpec, ReplayVerifier, VerifyContext, VerifyOutcome
from secops.verify.http import HttpVerifier


def _sig_from_dict(d: dict[str, Any]) -> dict[str, Any]:
    raw = json.dumps(d.get("body") or {}, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "sha256": d.get("sha256") or hashlib.sha256(raw).hexdigest(),
        "length": int(d.get("length") if d.get("length") is not None else len(raw)),
        "status": d.get("status"),
        "keys": sorted(d.get("keys") or list((d.get("body") or {}).keys())),
    }


class StateDiffVerifier(ReplayVerifier):
    type = "state_diff"

    def __init__(self, http: HttpVerifier | None = None) -> None:
        self._http = http or HttpVerifier()

    def verify(self, spec: ReplaySpec, ctx: VerifyContext) -> VerifyOutcome:
        payload = spec.payload
        mode = str(payload.get("mode") or "fixture").lower()
        expect = payload.get("expect") or {}

        if mode == "fixture":
            pre = _sig_from_dict(dict(payload.get("pre_signal") or {}))
            post = _sig_from_dict(dict(payload.get("post_signal") or {}))
        elif mode == "live":
            probe = payload.get("probe") or {}
            if not probe:
                return VerifyOutcome(validated=False, reason="state_diff.live requires payload.probe")
            pre_outcome = self._http.verify(ReplaySpec(type="http", payload=dict(probe)), ctx)
            if not pre_outcome.validated and not pre_outcome.signal:
                return VerifyOutcome(validated=False, reason=f"pre-probe failed: {pre_outcome.reason}")
            action = payload.get("action")
            if action:
                self._http.verify(ReplaySpec(type="http", payload=dict(action)), ctx)
            post_outcome = self._http.verify(ReplaySpec(type="http", payload=dict(probe)), ctx)
            pre = _sig_from_dict({**pre_outcome.signal, "body": {}})
            post = _sig_from_dict({**post_outcome.signal, "body": {}})
        else:
            return VerifyOutcome(validated=False, reason=f"unknown state_diff.mode={mode!r}")

        diff = _diff(pre, post)
        signal = {"pre": pre, "post": post, "diff": diff}
        failed = _check_expectations(diff, pre, post, expect)
        if failed:
            return VerifyOutcome(validated=False, reason="; ".join(failed), signal=signal)
        return VerifyOutcome(validated=True, signal=signal)


def _diff(pre: dict[str, Any], post: dict[str, Any]) -> dict[str, Any]:
    return {
        "sha_changed": pre.get("sha256") != post.get("sha256"),
        "length_delta": int(post.get("length") or 0) - int(pre.get("length") or 0),
        "status_changed": pre.get("status") != post.get("status"),
        "keys_added": sorted(set(post.get("keys") or []) - set(pre.get("keys") or [])),
        "keys_removed": sorted(set(pre.get("keys") or []) - set(post.get("keys") or [])),
    }


def _check_expectations(
    diff: dict[str, Any], pre: dict[str, Any], post: dict[str, Any], expect: dict[str, Any],
) -> list[str]:
    failed: list[str] = []
    if "sha_changed" in expect and bool(expect["sha_changed"]) != bool(diff["sha_changed"]):
        failed.append(f"sha_changed expected={expect['sha_changed']} actual={diff['sha_changed']}")
    if expect.get("same") and (diff["sha_changed"] or diff["length_delta"] != 0):
        failed.append("expected same, observed diff")
    if expect.get("length_increased") and diff["length_delta"] <= 0:
        failed.append(f"length_delta {diff['length_delta']} not positive")
    if expect.get("length_decreased") and diff["length_delta"] >= 0:
        failed.append(f"length_delta {diff['length_delta']} not negative")
    if "status_changed" in expect and bool(expect["status_changed"]) != bool(diff["status_changed"]):
        failed.append(f"status_changed expected={expect['status_changed']} actual={diff['status_changed']}")
    expected_keys = expect.get("keys_changed")
    if expected_keys is not None:
        observed = sorted(set(diff["keys_added"]) | set(diff["keys_removed"]))
        if observed != sorted(list(expected_keys)):
            failed.append(f"keys_changed expected={list(expected_keys)} actual={observed}")
    return failed


__all__ = ["StateDiffVerifier"]
