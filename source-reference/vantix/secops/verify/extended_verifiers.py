"""Extended verifier fabric — 13 verifier types added per the 2026-05-15 audit.

Several of these (oauth_flow, mfa_flow, webhook_replay, race_window,
tenant_matrix, grpc_sequence, websocket_sequence, oob_callback) require
live infrastructure to fully execute. For those, the verifier performs
the strongest possible OFFLINE validation: replay-payload shape checks,
invariant assertions over captured request/response pairs, and structural
correctness. The remaining three (model_output_sink, redaction_invariant,
artifact_boundary) are fully realizable as static analyzers and are
implemented with real checks — these are the highest-value safety
verifiers and run with no live dependency.

All verifiers subclass ReplayVerifier and return a VerifyOutcome.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from secops.verify.base import ReplaySpec, ReplayVerifier, VerifyContext, VerifyOutcome


def _need(payload: dict[str, Any], *keys: str) -> str | None:
    missing = [k for k in keys if not payload.get(k)]
    return f"missing required replay fields: {missing}" if missing else None


class OAuthFlowVerifier(ReplayVerifier):
    """Validate an OAuth/OIDC flow capture for redirect/state/nonce/account-linking.

    Payload: { authorize_url, redirect_uri, state, nonce, registered_redirect_uris[],
               id_token_claims{}, expected_account_email }
    """

    type = "oauth_flow"

    def verify(self, spec: ReplaySpec, ctx: VerifyContext) -> VerifyOutcome:
        p = spec.payload
        err = _need(p, "redirect_uri", "registered_redirect_uris")
        if err:
            return VerifyOutcome(validated=False, reason=err)
        redirect = str(p["redirect_uri"])
        registered = [str(r) for r in p.get("registered_redirect_uris") or []]
        findings: list[str] = []
        # Loose redirect_uri match (the classic OAuth bug this verifier proves).
        if redirect not in registered:
            if any(redirect.startswith(r) for r in registered):
                findings.append("redirect_uri prefix-matches but is not an exact registered value")
            else:
                findings.append("redirect_uri is not in the registered allowlist")
        if not p.get("state"):
            findings.append("state parameter absent (CSRF on the OAuth callback)")
        claims = p.get("id_token_claims") or {}
        exp_email = str(p.get("expected_account_email") or "")
        if exp_email and claims.get("email") and claims["email"] != exp_email:
            findings.append("id_token email does not match the linking account (account-linking confusion)")
        if claims and not claims.get("nonce"):
            findings.append("id_token has no nonce binding (replay window)")
        if findings:
            return VerifyOutcome(validated=True, reason="; ".join(findings),
                                 signal={"oauth_findings": findings})
        return VerifyOutcome(validated=False, reason="oauth flow invariants hold")


class MfaFlowVerifier(ReplayVerifier):
    """Validate MFA setup/removal/recovery transitions for missing reauth.

    Payload: { transition, reauth_required (observed bool), recovery_code_used,
               session_age_seconds, max_reauth_age_seconds }
    """

    type = "mfa_flow"

    SENSITIVE = {"mfa_remove", "mfa_disable", "recovery_code_view", "backup_factor_add", "passkey_unlink"}

    def verify(self, spec: ReplaySpec, ctx: VerifyContext) -> VerifyOutcome:
        p = spec.payload
        transition = str(p.get("transition") or "").strip().lower()
        if not transition:
            return VerifyOutcome(validated=False, reason="missing replay.transition")
        if transition in self.SENSITIVE and not bool(p.get("reauth_required", True)):
            return VerifyOutcome(
                validated=True,
                reason=f"sensitive MFA transition '{transition}' performed WITHOUT reauthentication",
                signal={"transition": transition},
            )
        max_age = int(p.get("max_reauth_age_seconds") or 0)
        age = int(p.get("session_age_seconds") or 0)
        if transition in self.SENSITIVE and max_age and age > max_age:
            return VerifyOutcome(
                validated=True,
                reason=f"'{transition}' allowed with stale auth (age {age}s > max {max_age}s)",
                signal={"transition": transition, "age": age},
            )
        return VerifyOutcome(validated=False, reason="MFA transition required fresh reauth")


class WebhookReplayVerifier(ReplayVerifier):
    """Validate webhook signature/timestamp/idempotency replay protection.

    Payload: { signature_header, recomputed_signature, timestamp, now,
               max_skew_seconds, idempotency_key, prior_idempotency_keys[] }
    """

    type = "webhook_replay"

    def verify(self, spec: ReplaySpec, ctx: VerifyContext) -> VerifyOutcome:
        p = spec.payload
        findings: list[str] = []
        sig = str(p.get("signature_header") or "")
        recomputed = str(p.get("recomputed_signature") or "")
        if sig and recomputed and sig != recomputed:
            # Server still accepted it (caller asserts acceptance via accepted=True)
            if bool(p.get("accepted")):
                findings.append("server accepted a webhook whose signature does not verify")
        ts = p.get("timestamp")
        now = p.get("now")
        skew = int(p.get("max_skew_seconds") or 0)
        if ts is not None and now is not None and skew:
            if abs(int(now) - int(ts)) > skew and bool(p.get("accepted")):
                findings.append("server accepted a webhook outside the timestamp window (replay)")
        idem = p.get("idempotency_key")
        prior = set(p.get("prior_idempotency_keys") or [])
        if idem and idem in prior and bool(p.get("accepted")):
            findings.append("duplicate idempotency-key was processed twice (replay/double-effect)")
        if findings:
            return VerifyOutcome(validated=True, reason="; ".join(findings),
                                 signal={"webhook_findings": findings})
        return VerifyOutcome(validated=False, reason="webhook replay protections hold")


class RaceWindowVerifier(ReplayVerifier):
    """Validate a race-window capture: N parallel attempts, expected vs observed.

    Payload: { attempts (int), expected_success_count (int),
               observed_success_count (int), action }
    """

    type = "race_window"

    def verify(self, spec: ReplaySpec, ctx: VerifyContext) -> VerifyOutcome:
        p = spec.payload
        err = _need(p, "attempts", "expected_success_count", "observed_success_count")
        if err:
            return VerifyOutcome(validated=False, reason=err)
        expected = int(p["expected_success_count"])
        observed = int(p["observed_success_count"])
        if observed > expected:
            return VerifyOutcome(
                validated=True,
                reason=f"race confirmed: {observed} successes vs expected {expected} "
                       f"over {p['attempts']} parallel attempts ({p.get('action','action')})",
                signal={"expected": expected, "observed": observed, "attempts": p["attempts"]},
            )
        return VerifyOutcome(validated=False,
                             reason=f"no race: observed {observed} == expected {expected}")


class TenantMatrixVerifier(ReplayVerifier):
    """Validate a tenant/persona object-access matrix for cross-boundary leakage.

    Payload: { cells: [ {persona, object_owner, action, expected, observed} ... ] }
    """

    type = "tenant_matrix"

    def verify(self, spec: ReplaySpec, ctx: VerifyContext) -> VerifyOutcome:
        cells = spec.payload.get("cells") or []
        if not cells:
            return VerifyOutcome(validated=False, reason="missing replay.cells")
        violations = []
        for c in cells:
            exp = str(c.get("expected") or "deny").lower()
            obs = str(c.get("observed") or "").lower()
            if exp == "deny" and obs in {"allow", "read", "write", "delete", "200", "ok"}:
                violations.append(
                    f"{c.get('persona')} -> {c.get('object_owner')}'s object "
                    f"[{c.get('action')}]: expected deny, observed {obs}"
                )
        if violations:
            return VerifyOutcome(validated=True, reason="; ".join(violations[:5]),
                                 signal={"violations": violations})
        return VerifyOutcome(validated=False, reason="all matrix cells respected the boundary")


class FileUploadRoundtripVerifier(ReplayVerifier):
    """Validate upload -> processing -> serving safety.

    Payload: { uploaded_name, served_content_type, served_disposition,
               served_from_app_origin (bool), executed (bool) }
    """

    type = "file_upload_roundtrip"

    DANGEROUS_CT = {"text/html", "image/svg+xml", "application/xhtml+xml", "application/javascript"}

    def verify(self, spec: ReplaySpec, ctx: VerifyContext) -> VerifyOutcome:
        p = spec.payload
        findings: list[str] = []
        ct = str(p.get("served_content_type") or "").lower()
        disp = str(p.get("served_disposition") or "").lower()
        if ct in self.DANGEROUS_CT and "attachment" not in disp:
            findings.append(f"uploaded file served inline as {ct} (stored XSS sink)")
        if bool(p.get("served_from_app_origin")) and ct in self.DANGEROUS_CT:
            findings.append("dangerous content-type served from the app origin (not a sandboxed domain)")
        if bool(p.get("executed")):
            findings.append("uploaded file was executed server-side")
        if findings:
            return VerifyOutcome(validated=True, reason="; ".join(findings),
                                 signal={"upload_findings": findings})
        return VerifyOutcome(validated=False, reason="upload roundtrip is safe")


class CacheKeyDiffVerifier(ReplayVerifier):
    """Compare cache behavior across header/query/path variants.

    Payload: { variants: [ {label, cache_status, contained_private (bool)} ... ] }
    """

    type = "cache_key_diff"

    def verify(self, spec: ReplaySpec, ctx: VerifyContext) -> VerifyOutcome:
        variants = spec.payload.get("variants") or []
        if not variants:
            return VerifyOutcome(validated=False, reason="missing replay.variants")
        findings = []
        for v in variants:
            status = str(v.get("cache_status") or "").upper()
            if v.get("contained_private") and status in {"HIT", "STALE", "STORED"}:
                findings.append(f"variant '{v.get('label')}' cached private content (cache_status={status})")
        if findings:
            return VerifyOutcome(validated=True, reason="; ".join(findings),
                                 signal={"cache_findings": findings})
        return VerifyOutcome(validated=False, reason="no private content cached across variants")


class GrpcSequenceVerifier(ReplayVerifier):
    """Validate a gRPC/protobuf call-sequence capture for field-authz gaps.

    Payload: { method, sent_fields[], unauthorized_fields_echoed[],
               default_value_bypass (bool) }
    """

    type = "grpc_sequence"

    def verify(self, spec: ReplaySpec, ctx: VerifyContext) -> VerifyOutcome:
        p = spec.payload
        if not p.get("method"):
            return VerifyOutcome(validated=False, reason="missing replay.method")
        echoed = p.get("unauthorized_fields_echoed") or []
        findings = []
        if echoed:
            findings.append(f"server echoed fields the caller is not authorized for: {echoed}")
        if bool(p.get("default_value_bypass")):
            findings.append("proto default value (0/empty) bypassed a presence check (field-authz gap)")
        if findings:
            return VerifyOutcome(validated=True, reason="; ".join(findings),
                                 signal={"grpc_findings": findings})
        return VerifyOutcome(validated=False, reason="gRPC field authz held")


class WebsocketSequenceVerifier(ReplayVerifier):
    """Validate a websocket connect/subscribe/send/receive authz capture.

    Payload: { steps: [ {action, channel, persona, expected, observed} ... ] }
    """

    type = "websocket_sequence"

    def verify(self, spec: ReplaySpec, ctx: VerifyContext) -> VerifyOutcome:
        steps = spec.payload.get("steps") or []
        if not steps:
            return VerifyOutcome(validated=False, reason="missing replay.steps")
        violations = []
        for s in steps:
            exp = str(s.get("expected") or "deny").lower()
            obs = str(s.get("observed") or "").lower()
            if exp == "deny" and obs in {"allow", "delivered", "subscribed", "ok"}:
                violations.append(
                    f"{s.get('persona')} {s.get('action')} on {s.get('channel')}: "
                    f"expected deny, observed {obs}"
                )
        if violations:
            return VerifyOutcome(validated=True, reason="; ".join(violations[:5]),
                                 signal={"ws_violations": violations})
        return VerifyOutcome(validated=False, reason="websocket authz held across the sequence")


class OobCallbackVerifier(ReplayVerifier):
    """Correlate a blind OOB callback to a specific payload/vector/run.

    Payload: { callback_token, callbacks: [ {token, source_ip, protocol, ts} ... ],
               run_id }
    """

    type = "oob_callback"

    def verify(self, spec: ReplaySpec, ctx: VerifyContext) -> VerifyOutcome:
        p = spec.payload
        token = str(p.get("callback_token") or "")
        if not token:
            return VerifyOutcome(validated=False, reason="missing replay.callback_token")
        matches = [c for c in (p.get("callbacks") or []) if str(c.get("token")) == token]
        if not matches:
            return VerifyOutcome(validated=False,
                                 reason=f"no OOB callback observed for token {token[:12]}...")
        m = matches[0]
        return VerifyOutcome(
            validated=True,
            reason=f"OOB callback confirmed: {m.get('protocol')} from {m.get('source_ip')} "
                   f"correlated to token {token[:12]}...",
            signal={"callback": m, "run_id": p.get("run_id")},
        )


class ModelOutputSinkVerifier(ReplayVerifier):
    """Static check: LLM output must not become executable/rendered-unsafe content.

    Fully realizable offline. Payload: { output (str), render_context }
    render_context one of: markdown_html, html, csv, code_block, filename, plain
    """

    type = "model_output_sink"

    _HTML_EXEC = re.compile(r"<\s*script|on\w+\s*=|javascript:|<\s*img[^>]+onerror|<\s*svg[^>]*on\w+", re.I)
    _CSV_FORMULA = re.compile(r"^\s*[=+\-@]")
    _PATH_TRAVERSAL = re.compile(r"\.\.[/\\]|^/|^[A-Za-z]:[/\\]")

    def verify(self, spec: ReplaySpec, ctx: VerifyContext) -> VerifyOutcome:
        p = spec.payload
        out = str(p.get("output") or "")
        rc = str(p.get("render_context") or "plain").lower()
        if not out:
            return VerifyOutcome(validated=False, reason="missing replay.output")
        if rc in {"markdown_html", "html"} and self._HTML_EXEC.search(out):
            return VerifyOutcome(validated=True,
                                 reason="model output contains an HTML/JS execution sink",
                                 signal={"render_context": rc})
        if rc == "csv":
            for line in out.splitlines():
                for cell in line.split(","):
                    if self._CSV_FORMULA.match(cell):
                        return VerifyOutcome(validated=True,
                                             reason=f"model output has a CSV formula-injection cell: {cell[:32]!r}",
                                             signal={"render_context": rc})
        if rc == "filename" and self._PATH_TRAVERSAL.search(out):
            return VerifyOutcome(validated=True,
                                 reason="model-sourced filename contains path traversal / absolute path",
                                 signal={"render_context": rc})
        return VerifyOutcome(validated=False, reason="model output is safe for the render context")


class RedactionInvariantVerifier(ReplayVerifier):
    """Static check: an exported report must never contain secret/PII classes.

    Fully realizable offline. Payload: { content (str) } OR { path }
    """

    type = "redaction_invariant"

    PATTERNS = {
        "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
        "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
        "github_pat": re.compile(r"ghp_[A-Za-z0-9]{30,}"),
        "slack_token": re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
        "jwt": re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
        "email_pii": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "credit_card": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    }

    def verify(self, spec: ReplaySpec, ctx: VerifyContext) -> VerifyOutcome:
        p = spec.payload
        content = p.get("content")
        if content is None and p.get("path"):
            candidate = Path(str(p["path"]))
            if candidate.is_absolute():
                return VerifyOutcome(validated=False,
                                     reason="redaction check refuses absolute path; pass content or workspace-relative path")
            if ctx.workspace_root is None:
                return VerifyOutcome(validated=False, reason="workspace_root unset")
            root = Path(ctx.workspace_root).resolve()
            candidate = (root / candidate).resolve()
            try:
                candidate.relative_to(root)
            except ValueError:
                return VerifyOutcome(validated=False, reason="path escapes workspace_root")
            try:
                content = candidate.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                return VerifyOutcome(validated=False, reason=f"read failed: {exc}")
        content = str(content or "")
        leaked = [name for name, rx in self.PATTERNS.items() if rx.search(content)]
        if leaked:
            # validated=True means the INVARIANT VIOLATION is proven (this is a finding).
            return VerifyOutcome(
                validated=True,
                reason=f"redaction invariant VIOLATED: exported content contains {leaked}",
                signal={"leaked_classes": leaked},
            )
        return VerifyOutcome(validated=False, reason="redaction invariant holds (no secret/PII classes found)")


class ArtifactBoundaryVerifier(ReplayVerifier):
    """Static check: an artifact path must stay under the workspace root.

    Fully realizable offline. Payload: { path }
    """

    type = "artifact_boundary"

    def verify(self, spec: ReplaySpec, ctx: VerifyContext) -> VerifyOutcome:
        raw = str(spec.payload.get("path") or "").strip()
        if not raw:
            return VerifyOutcome(validated=False, reason="missing replay.path")
        candidate = Path(raw)
        if candidate.is_absolute():
            return VerifyOutcome(validated=True,
                                 reason="boundary VIOLATED: absolute artifact path",
                                 signal={"path": raw})
        if ctx.workspace_root is None:
            return VerifyOutcome(validated=False, reason="workspace_root unset; cannot resolve")
        root = Path(ctx.workspace_root).resolve()
        resolved = (root / candidate).resolve()
        try:
            resolved.relative_to(root)
        except ValueError:
            return VerifyOutcome(validated=True,
                                 reason="boundary VIOLATED: path escapes workspace_root",
                                 signal={"path": raw, "resolved": str(resolved)})
        return VerifyOutcome(validated=False, reason="artifact path stays within workspace_root")


ALL_EXTENDED_VERIFIERS = [
    OAuthFlowVerifier,
    MfaFlowVerifier,
    WebhookReplayVerifier,
    RaceWindowVerifier,
    TenantMatrixVerifier,
    FileUploadRoundtripVerifier,
    CacheKeyDiffVerifier,
    GrpcSequenceVerifier,
    WebsocketSequenceVerifier,
    OobCallbackVerifier,
    ModelOutputSinkVerifier,
    RedactionInvariantVerifier,
    ArtifactBoundaryVerifier,
]
