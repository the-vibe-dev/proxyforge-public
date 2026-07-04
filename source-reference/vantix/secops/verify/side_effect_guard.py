"""V3-10 — SideEffectGuardVerifier.

Asserts an action produced no out-of-scope side effects. Given a
captured ``pre_state`` and ``post_state`` (each a dict of arbitrary
``key -> value`` pairs representing the observed environment), the
verifier:

1. Computes the diff between pre and post.
2. Fails if any change appears outside the ``allowed_changes`` set.
3. Fails if a key under ``required_unchanged`` differs.

Schema:

    pre_state:           dict[str, Any]
    post_state:          dict[str, Any]
    allowed_changes:     list[str]   (keys we expect to mutate)
    required_unchanged:  list[str]   (keys that must NOT mutate)

Both lists are optional; an empty ``allowed_changes`` means "no change
of any kind is acceptable" — useful for read-only audits.
"""
from __future__ import annotations

from typing import Any

from secops.verify.base import ReplaySpec, ReplayVerifier, VerifyContext, VerifyOutcome


class SideEffectGuardVerifier(ReplayVerifier):
    type = "side_effect_guard"

    def verify(self, spec: ReplaySpec, ctx: VerifyContext) -> VerifyOutcome:
        payload = spec.payload
        pre = dict(payload.get("pre_state") or {})
        post = dict(payload.get("post_state") or {})
        allowed = set(str(k) for k in (payload.get("allowed_changes") or []))
        required_unchanged = set(str(k) for k in (payload.get("required_unchanged") or []))

        added = sorted(set(post) - set(pre))
        removed = sorted(set(pre) - set(post))
        changed = sorted(k for k in (set(pre) & set(post)) if pre[k] != post[k])

        all_diff = set(added) | set(removed) | set(changed)
        unauthorized = sorted(all_diff - allowed) if allowed else sorted(all_diff)
        violated_required = sorted(required_unchanged & all_diff)

        signal = {
            "added": added,
            "removed": removed,
            "changed": changed,
            "unauthorized": unauthorized,
            "violated_required": violated_required,
        }
        failed: list[str] = []
        if unauthorized:
            failed.append(f"unauthorized changes: {unauthorized}")
        if violated_required:
            failed.append(f"required-unchanged keys mutated: {violated_required}")
        if failed:
            return VerifyOutcome(validated=False, reason="; ".join(failed), signal=signal)
        return VerifyOutcome(validated=True, signal=signal)


__all__ = ["SideEffectGuardVerifier"]
