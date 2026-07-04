"""BrowserActionVerifier — replay type ``browser_actions``.

Drives ``secops.services.browser_actions.run_action_chain`` and asserts on
the resulting trace. Used by the new browser-exploit phase and any
probe (HTTP or otherwise) that emits a ``replay.type = "browser_actions"``
block.

Replay payload schema:

    url:        str (required) — initial page to open
    actions:    list[dict]      — action grammar in browser_actions
    artifact_dir: str (optional) — defaults to ctx.workspace_root/artifacts/browser
    expect:
        all_actions_succeed:    bool       — default True
        text_contains:          str        — substring in final page content
        url_contains:           str        — substring in final page URL
        dialogs_min:            int        — minimum alert/confirm dialogs caught
        screenshots_min:        int        — minimum screenshot files written
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from secops.services.scope_egress import ScopeEgressGuard
from secops.verify.base import ReplaySpec, ReplayVerifier, VerifyContext, VerifyOutcome


class BrowserActionVerifier(ReplayVerifier):
    type = "browser_actions"

    def verify(self, spec: ReplaySpec, ctx: VerifyContext) -> VerifyOutcome:
        from secops.services.browser_actions import run_action_chain

        payload = spec.payload
        url = str(payload.get("url") or "").strip()
        if not url:
            return VerifyOutcome(validated=False, reason="replay.url missing")
        guard = ScopeEgressGuard.from_context(ctx.extras)
        if guard is not None:
            decision = guard.check_url(url)
            if not decision.allowed:
                return VerifyOutcome(validated=False,
                                     reason=f"scope egress blocked: {decision.reason}",
                                     signal={"blocked": True, "url": url})
        actions = list(payload.get("actions") or [])
        expect = payload.get("expect") or {}
        artifact_dir = payload.get("artifact_dir")
        if not artifact_dir:
            root = getattr(ctx, "workspace_root", "") or "/tmp"
            artifact_dir = str(Path(root) / "artifacts" / "browser_actions")
        try:
            run = run_action_chain(entry_url=url, actions=actions,
                                   artifact_dir=artifact_dir)
        except Exception as exc:  # noqa: BLE001
            return VerifyOutcome(validated=False, reason=f"browser_actions failed: {exc}")

        signal: dict[str, Any] = {
            "final_url": run.final_url,
            "final_title": run.final_title,
            "dialogs_caught": len(run.dialogs_caught),
            "screenshots": run.screenshots,
            "trace": run.public()["trace"],
        }
        failed: list[str] = []
        if bool(expect.get("all_actions_succeed", True)) and not run.success:
            reason = run.failure_reason or "one or more actions failed"
            failed.append(reason)
        if (sub := expect.get("text_contains")) and sub not in (run.final_title or "") \
                and sub not in (run.final_url or ""):
            # text_contains primarily aims at final page body — we proxied via
            # text_contains action inside the chain; if not used, just check
            # the recorded title.
            joined_text = " ".join(r.detail for r in run.trace if r.success)
            if str(sub) not in joined_text:
                failed.append(f"text_contains {sub!r} not seen")
        if (sub := expect.get("url_contains")) and str(sub) not in (run.final_url or ""):
            failed.append(f"url_contains {sub!r} not in {run.final_url!r}")
        if (mn := expect.get("dialogs_min")) is not None and len(run.dialogs_caught) < int(mn):
            failed.append(f"dialogs {len(run.dialogs_caught)} < {mn}")
        if (mn := expect.get("screenshots_min")) is not None and len(run.screenshots) < int(mn):
            failed.append(f"screenshots {len(run.screenshots)} < {mn}")

        if failed:
            return VerifyOutcome(validated=False, reason="; ".join(failed), signal=signal)
        return VerifyOutcome(validated=True, signal=signal,
                             reproduction_script=f"sechive-browser actions {url}")
