from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse

from sqlalchemy.orm import Session

from secops.models import Artifact, Fact, RunEvent, WorkspaceRun
from secops.skills.capabilities import extract_capabilities
from secops.skills.contracts import ReconFeatureSet


_PLUGIN_PATH_RE = re.compile(r"/wp-content/plugins/([a-z0-9_.-]+)", re.IGNORECASE)
_WORDPRESS_VERSION_RE = re.compile(r"wordpress(?:\s+|[/:_-]*)(\d+(?:\.\d+){1,3})", re.IGNORECASE)

_BUSINESS_TERMS = {
    "checkout",
    "cart",
    "order",
    "orders",
    "payment",
    "invoice",
    "receipt",
    "refund",
    "coupon",
    "subscription",
    "transfer",
    "wallet",
    "job",
    "private",
}
_CLOUD_TERMS = {"terraform", "kubernetes", "k8s", "iam", "s3", "bucket", "gcp", "aws", "azure", "helm"}
_AD_TERMS = {"ldap", "kerberos", "smb", "winrm", "ntlm", "domain controller", "active directory"}
_TLS_TERMS = {"tls", "ssl", "certificate", "cipher", "hsts", "subject alternative name", "expired cert", "weak cipher"}
_SCANNER_TERMS = {"scanner module", "scan module", "template match", "safe probe", "vulnerability scan", "module result"}
_ENTERPRISE_PROTOCOL_TERMS = {"sap", "saprouter", "sap router", "diag", "rfc", "enterprise protocol", "router string"}
_AGENTIC_SECURITY_TERMS = {
    "tool approval",
    "tool call",
    "autonomous action",
    "agent tool",
    "vector store",
    "embedding",
    "memory retrieval",
    "multi-agent",
    "worker agent",
    "goal drift",
}
_AUTH_TERMS = {"login", "logout", "session", "cookie", "jwt", "oauth", "bearer", "saml", "password", "token"}
_XSS_TERMS = {
    "xss",
    "cross-site scripting",
    "cross site scripting",
    "cwe-79",
    "alert(",
    "confirm(",
    "prompt(",
    "onload=",
    "onerror=",
    "onfocus=",
    "innerhtml",
    "phantomjs",
}
_LFI_TERMS = {
    "lfi",
    "local file inclusion",
    "local file read",
    "file read",
    "path traversal",
    "directory traversal",
    "send_from_directory",
    "sendfile",
    "filename=",
    "resource?filename",
    "/resource",
    "static resource",
    "etc/passwd",
}
_SSRF_TERMS = {
    "ssrf",
    "server-side request forgery",
    "server side request forgery",
    "internal service",
    "file_get_contents",
    "curl_exec",
    "fopen(",
    "requests.get",
    "requests.post",
    "http client",
    "fetch url",
    "url to fetch",
    "url parameter",
    "metadata service",
    "169.254.169.254",
    "localhost",
    "127.0.0.1",
}
_SSTI_TERMS = {
    "ssti",
    "server-side template",
    "server side template",
    "template injection",
    "jinja",
    "jinja2",
    "render_template",
    "render_template_string",
    "{% include",
    "{{",
    "{%",
    "template include",
    "dynamic include",
}
_BLIND_INFERENCE_TERMS = {
    "blind",
    "time-based",
    "timing delta",
    "boolean differential",
    "response length",
    "body length",
    "header changed",
    "no visible output",
    "oracle",
    "side channel",
}
_PAYLOAD_FILTER_TERMS = {
    "blocked",
    "filtered",
    "blacklist",
    "waf",
    "invalid character",
    "forbidden character",
    "parser error",
    "syntax error",
    "malformed",
    "quote",
    "encoding",
    "verifier oracle",
    "observed value",
    "expected value",
    "instead of",
}
_STAGNATION_TERMS = {
    "stagnation",
    "no new evidence",
    "same response",
    "repeated identical",
    "timed out",
    "timeout",
    "cancelled",
    "dead-end",
    "disproved",
}
_SESSION_STATE_TERMS = {
    "server-side session",
    "flask_session",
    "sqlalchemysessioninterface",
    "open_session",
    "read uncommitted",
    "same-session",
    "state desync",
    "session desync",
    "debug_session",
}
_SOURCE_EXT_LANG = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rb": "ruby",
    ".java": "java",
    ".kt": "kotlin",
    ".swift": "swift",
    ".php": "php",
    ".rs": "rust",
}
_ID_PARAM_RE = re.compile(r"(?:^|[?&/_-])(id|user_id|account_id|order_id|receipt_id|company_id|tenant_id|object_id)(?:=|$|[/_-])", re.I)


def _add_unique(values: list[str], item: Any, *, limit: int = 80) -> None:
    text = str(item or "").strip()
    if text and text not in values and len(values) < limit:
        values.append(text)


def _jsonish(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            data = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return data if isinstance(data, dict) else {}
    return {}


def _contains_term(text: str, term: str) -> bool:
    if not term:
        return False
    if re.search(r"[^a-z0-9 ]", term):
        return term in text
    return re.search(rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])", text) is not None


class ReconFeatureExtractor:
    def extract(self, db: Session, run: WorkspaceRun) -> ReconFeatureSet:
        facts = db.query(Fact).filter(Fact.run_id == run.id).order_by(Fact.created_at.asc()).all()
        events = db.query(RunEvent).filter(RunEvent.run_id == run.id).order_by(RunEvent.created_at.asc()).all()
        artifacts = db.query(Artifact).filter(Artifact.run_id == run.id).order_by(Artifact.created_at.asc()).all()
        features = ReconFeatureSet(run_id=run.id, mode=run.mode, target_kind=self._target_kind(run))
        source_counts: Counter[str] = Counter()
        feature_refs: dict[str, list[str]] = defaultdict(list)

        def mark(name: str, value: Any, ref: str) -> None:
            target = getattr(features, name)
            _add_unique(target, value)
            _add_unique(feature_refs[name], ref, limit=120)
            _add_unique(features.evidence_refs, ref, limit=300)

        self._seed_from_run(run, features, mark)
        for fact in facts:
            ref = f"fact:{fact.id}"
            source_counts[fact.source or "fact"] += 1
            self._from_fact(fact, features, mark, ref)
        for event in events[-250:]:
            ref = f"event:{event.id}"
            source_counts[f"event:{event.event_type}"] += 1
            self._from_text_blob(" ".join([event.event_type, event.message, json.dumps(event.payload_json or {})]), features, mark, ref)
        for artifact in artifacts[-200:]:
            ref = f"artifact:{artifact.id}"
            source_counts[f"artifact:{artifact.kind}"] += 1
            self._from_artifact(artifact, features, mark, ref)

        features.feature_refs = {key: value for key, value in sorted(feature_refs.items())}
        features.source_counts = dict(source_counts)
        return features

    def _target_kind(self, run: WorkspaceRun) -> str:
        target = str(run.target or run.repo_path or "").lower()
        if target.endswith(".apk"):
            return "apk"
        if target.startswith("http://") or target.startswith("https://"):
            return "web"
        if run.repo_path or target.startswith(".") or "/" in target:
            return "source"
        return "unknown"

    def _seed_from_run(self, run: WorkspaceRun, features: ReconFeatureSet, mark) -> None:
        for text in [run.target, run.objective, json.dumps(run.config_json or {})]:
            self._from_text_blob(str(text or ""), features, mark, "run:config")

    def _from_fact(self, fact: Fact, features: ReconFeatureSet, mark, ref: str) -> None:
        kind = str(fact.kind or "").lower()
        value = str(fact.value or "")
        meta = fact.metadata_json or {}
        tags = " ".join(str(item) for item in (fact.tags or []))
        blob = " ".join([kind, value, tags, json.dumps(meta)])
        is_coverage_inventory = kind == "coverage_check" or str(meta.get("status") or "").lower() == "inventory-reviewed"

        if kind in {"port"} or meta.get("port"):
            mark("ports", meta.get("port") or value, ref)
        if kind in {"service"} or meta.get("service"):
            mark("services", meta.get("service") or value, ref)
        if kind in {"version", "banner"} or meta.get("version"):
            mark("versions", meta.get("version") or value, ref)
        if kind in {"cms-indicator", "cms_indicator"}:
            mark("cms_indicators", value, ref)
        if kind in {"plugin-indicator", "plugin_indicator"}:
            mark("plugin_indicators", value, ref)
        if kind in {"http_endpoint", "endpoint", "route", "url"} or value.startswith(("http://", "https://", "/")):
            mark("web_endpoints", value, ref)
        if kind in {"http_header", "header"}:
            mark("headers", value, ref)
        if kind in {"form", "login_form"}:
            mark("forms", value, ref)
        if kind in {"api_schema", "openapi_schema"}:
            mark("api_schemas", value, ref)
        if "graphql" in blob.lower():
            mark("graphql", value or "graphql", ref)
        if kind in {"cve"}:
            mark("cves", value, ref)
        if kind in {"detection_engine_match"}:
            mark("detection_engine_matches", value, ref)
        if kind in {"negative_evidence"}:
            mark("negative_signals", value, ref)
        if kind in {"capability", "runtime-capability", "runtime_capability", "capability-candidate"}:
            mark("capabilities", value, ref)
            for skill_id in meta.get("recommended_skills") or []:
                if str(skill_id).strip() == "payload_crafter":
                    mark("payload_filter_signals", value, ref)
                if str(skill_id).strip() == "vuln_scanner":
                    mark("versions", value, ref)
            if value in {"object_access_delta", "role_property_control"}:
                mark("object_id_params", value, ref)
                mark("business_logic_terms", value, ref)
            if value == "blind_sql_injection_oracle":
                mark("blind_inference_signals", value, ref)
                mark("payload_filter_signals", value, ref)
                mark("business_logic_terms", value, ref)
            if value == "hash_disclosure_or_credential_material":
                mark("credential_indicators", value, ref)
                mark("auth_indicators", value, ref)
            if value == "mapped_side_service_candidate":
                mark("services", value, ref)
                mark("ports", value, ref)
            if value == "internal_api_operation_candidate":
                mark("api_schemas", value, ref)
                mark("ssrf_indicators", value, ref)
                mark("business_logic_terms", value, ref)
                mark("capabilities", value, ref)
            if value == "objective_proof_gap":
                mark("stagnation_signals", value, ref)
            if value == "server_side_fetch":
                mark("ssrf_indicators", value, ref)
            if value in {"template_or_include_path"}:
                mark("ssti_indicators", value, ref)
            if value in {"client_sink"}:
                mark("xss_indicators", value, ref)
        if kind in {"blind_inference_signal", "blind-inference-signal"}:
            mark("blind_inference_signals", value, ref)
        if kind in {"payload_filter_signal", "payload-filter-signal", "verifier_oracle_signal", "verifier-oracle-signal"}:
            mark("payload_filter_signals", value, ref)
            mark("blind_inference_signals", value, ref)
            mark("xss_indicators", value, ref)
        if kind in {"stagnation_signal", "stagnation-signal"}:
            mark("stagnation_signals", value, ref)
        if kind in {"source-candidate", "source_candidate", "source_file"}:
            self._source_from_value(value, features, mark, ref)
        if kind in {"apk_metadata"}:
            mark("apk_metadata", value, ref)
        if kind in {"apk_exported_component"}:
            mark("exported_android_components", value, ref)
        if kind in {"mobile_permission"}:
            mark("mobile_permissions", value, ref)
        if kind in {"tls_indicator", "transport_security"}:
            mark("tls_indicators", value, ref)
        if kind in {"scanner_indicator", "scanner_module", "detection_engine_match"}:
            mark("scanner_indicators", value, ref)
        if kind in {"enterprise_protocol", "protocol_service"}:
            mark("enterprise_protocol_indicators", value, ref)
        if kind in {"agentic_security", "agentic_boundary"}:
            mark("agentic_security_indicators", value, ref)
        self._from_text_blob(blob, features, mark, ref, allow_vuln_indicators=not is_coverage_inventory)

    def _from_artifact(self, artifact: Artifact, features: ReconFeatureSet, mark, ref: str) -> None:
        kind = str(artifact.kind or "").lower()
        path = Path(artifact.path)
        text = " ".join([kind, path.name, json.dumps(artifact.metadata_json or {})])
        if kind in {"route-discovery", "browser-session-summary", "network-summary", "form-map", "browser-js-signals"}:
            payload = self._artifact_json(path)
            self._from_json(payload, features, mark, ref)
        if kind == "http-validation" and path.name == "endpoint-candidates.json":
            payload = self._artifact_json(path)
            self._from_json(payload, features, mark, ref)
            by_method = payload.get("by_method") if isinstance(payload.get("by_method"), dict) else {}
            for method, paths in by_method.items():
                if not isinstance(paths, list):
                    continue
                for endpoint in paths[:120]:
                    mark("web_endpoints", f"{str(method).upper()} {endpoint}", ref)
        if kind in {"source-review-json", "source-analysis-json"}:
            payload = self._artifact_json(path)
            self._from_json(payload, features, mark, ref)
            for candidate in payload.get("candidates") or []:
                self._source_from_value(json.dumps(candidate), features, mark, ref)
        if kind in {"apk-metadata", "mobile-device-snapshot"}:
            mark("apk_metadata", path.name, ref)
        self._from_text_blob(text, features, mark, ref)

    def _artifact_json(self, path: Path) -> dict[str, Any]:
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except (OSError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    def _from_json(self, payload: dict[str, Any], features: ReconFeatureSet, mark, ref: str) -> None:
        blob = json.dumps(payload)
        self._from_text_blob(blob, features, mark, ref)
        for key in ("url", "current_url", "entry_url", "path", "endpoint"):
            if payload.get(key):
                mark("web_endpoints", payload[key], ref)
        for edge in payload.get("edges") or []:
            if isinstance(edge, dict):
                mark("web_endpoints", edge.get("to") or edge.get("url"), ref)
        for form in payload.get("forms") or []:
            if isinstance(form, dict):
                mark("forms", form.get("action") or form.get("name") or json.dumps(form), ref)
        for page in payload.get("pages") or []:
            if isinstance(page, dict):
                mark("web_endpoints", page.get("url"), ref)
                for hint in page.get("route_hints") or []:
                    mark("web_endpoints", hint, ref)
                for bundle in page.get("js_bundles") or []:
                    mark("js_bundles", bundle, ref)

    def _source_from_value(self, value: str, features: ReconFeatureSet, mark, ref: str) -> None:
        lowered = value.lower()
        for ext, language in _SOURCE_EXT_LANG.items():
            if ext in lowered:
                mark("source_languages", language, ref)
        if any(item in lowered for item in ("fastapi", "flask", "django", "express", "next", "spring", "rails")):
            mark("source_frameworks", value[:160], ref)
        if any(item in lowered for item in ("eval(", "exec(", "innerhtml", "rawsql", "select *", "subprocess", "pickle.loads")):
            mark("risky_source_sinks", value[:200], ref)
        if any(item in lowered for item in ("paramiko", "sshclient", "hardcoded password", "hardcoded credential", "base64.b64decode")):
            mark("credential_indicators", value[:200], ref)
            mark("capabilities", "side_service_credentials", ref)
        if any(item in lowered for item in ("paramiko", "sshclient", "local side service", "source-local service")) and any(
            item in lowered for item in ("localhost", "127.0.0.1", "container", "same-host")
        ):
            mark("capabilities", "source_local_side_service", ref)
        if any(item in lowered for item in ("backup archive", "backup-migration", "migration backup", "staging backup", "database dump")):
            mark("capabilities", "backup_exposure", ref)
        if any(item in lowered for item in _SESSION_STATE_TERMS):
            mark("auth_indicators", value[:200], ref)
            mark("capabilities", "session_state_desync", ref)
        if any(_contains_term(lowered, item) for item in _XSS_TERMS):
            mark("xss_indicators", value[:200], ref)
        if any(_contains_term(lowered, item) for item in _LFI_TERMS):
            mark("lfi_indicators", value[:200], ref)
        if any(_contains_term(lowered, item) for item in _SSRF_TERMS):
            mark("ssrf_indicators", value[:200], ref)
        if any(_contains_term(lowered, item) for item in _SSTI_TERMS):
            mark("ssti_indicators", value[:200], ref)
        if any(item in lowered for item in ("package.json", "requirements.txt", "pom.xml", "build.gradle", "go.mod", "cargo.toml")):
            mark("dependency_manifests", value[:160], ref)
        if any(item in lowered for item in (".github/workflows", "gitlab-ci", "jenkinsfile", "circleci", "azure-pipelines")):
            mark("cicd_files", value[:160], ref)
        if any(item in lowered for item in ("secret", "api_key", "token", "password", ".env", "private_key")):
            mark("secret_config_candidates", value[:200], ref)

    def _from_text_blob(self, blob: str, features: ReconFeatureSet, mark, ref: str, *, allow_vuln_indicators: bool = True) -> None:
        lowered = blob.lower()
        for capability in extract_capabilities(blob):
            mark("capabilities", capability, ref)
        for service in ("http", "https", "nginx", "apache", "werkzeug", "flask", "fastapi", "uvicorn", "express", "ssh", "ldap", "kerberos", "smb"):
            if _contains_term(lowered, service):
                mark("services", service, ref)
        for term in _AUTH_TERMS:
            if _contains_term(lowered, term):
                mark("auth_indicators", term, ref)
        self._cms_from_text(blob, features, mark, ref)
        if allow_vuln_indicators:
            for term in _XSS_TERMS:
                if _contains_term(lowered, term):
                    mark("xss_indicators", term, ref)
            for term in _LFI_TERMS:
                if _contains_term(lowered, term):
                    mark("lfi_indicators", term, ref)
            for term in _SSRF_TERMS:
                if _contains_term(lowered, term):
                    mark("ssrf_indicators", term, ref)
            for term in _SSTI_TERMS:
                if _contains_term(lowered, term):
                    mark("ssti_indicators", term, ref)
        for term in _BUSINESS_TERMS:
            if _contains_term(lowered, term):
                mark("business_logic_terms", term, ref)
        for term in _CLOUD_TERMS:
            if _contains_term(lowered, term):
                mark("cloud_indicators", term, ref)
        for term in _AD_TERMS:
            if _contains_term(lowered, term):
                mark("ad_indicators", term, ref)
        for term in _TLS_TERMS:
            if _contains_term(lowered, term):
                mark("tls_indicators", term, ref)
        for term in _SCANNER_TERMS:
            if _contains_term(lowered, term):
                mark("scanner_indicators", term, ref)
        for term in _ENTERPRISE_PROTOCOL_TERMS:
            if _contains_term(lowered, term):
                mark("enterprise_protocol_indicators", term, ref)
        for term in _AGENTIC_SECURITY_TERMS:
            if _contains_term(lowered, term):
                mark("agentic_security_indicators", term, ref)
        for term in ("default password", "default-login", "hash", "ntlm", "credential", "hardcoded password"):
            if _contains_term(lowered, term):
                mark("credential_indicators", term, ref)
        for term in _BLIND_INFERENCE_TERMS:
            if _contains_term(lowered, term):
                mark("blind_inference_signals", term, ref)
        for term in _PAYLOAD_FILTER_TERMS:
            if _contains_term(lowered, term):
                mark("payload_filter_signals", term, ref)
        for term in _STAGNATION_TERMS:
            if _contains_term(lowered, term):
                mark("stagnation_signals", term, ref)
        if any(item in lowered for item in _SESSION_STATE_TERMS):
            mark("auth_indicators", "server-side session state", ref)
            mark("capabilities", "session_state_desync", ref)
        if "graphql" in lowered:
            mark("graphql", "graphql", ref)
        if "openapi" in lowered or "swagger" in lowered:
            mark("api_schemas", "openapi/swagger", ref)
        if "android" in lowered or ".apk" in lowered:
            mark("apk_metadata", "android/apk", ref)
        for term in (
            "network security config",
            "cleartext",
            "certificate pinning",
            "certificate validation",
            "webview",
            "sharedpreferences",
            "keystore",
            "content provider",
            "intent-filter",
            "intent filter",
            "allowbackup",
            "debuggable",
        ):
            if term in lowered:
                mark("apk_metadata", term, ref)
        if "exported" in lowered and ("activity" in lowered or "receiver" in lowered or "service" in lowered):
            mark("exported_android_components", "exported component", ref)
        if "deeplink" in lowered or "deep link" in lowered:
            mark("mobile_deeplinks", "deeplink", ref)
        if "permission" in lowered and "android" in lowered:
            mark("mobile_permissions", "android permission", ref)
        for match in _ID_PARAM_RE.finditer(blob):
            mark("object_id_params", match.group(1), ref)
        parsed = urlparse(blob.strip()) if blob.strip().startswith(("http://", "https://")) else None
        if parsed:
            mark("web_endpoints", blob.strip(), ref)
            for key, _ in parse_qsl(parsed.query):
                if _ID_PARAM_RE.search(key):
                    mark("object_id_params", key, ref)

    def _cms_from_text(self, blob: str, features: ReconFeatureSet, mark, ref: str) -> None:
        lowered = blob.lower()
        looks_like_wordpress = (
            any(token in lowered for token in ("wp-json", "wp-content", "wp-includes", "xmlrpc.php", "rest_route=/wp/v2/", "/wp/v2/"))
            or bool(re.search(r'<meta[^>]+generator[^>]+wordpress', lowered))
            or (
                "wordpress" in lowered
                and bool(
                    re.search(r"\bwordpress\b.{0,120}\b(wp-admin|wp-login|wp-content|wp-json|xmlrpc|powered by)\b", lowered)
                    or re.search(r"\b(wp-admin|wp-login|wp-content|wp-json|xmlrpc|powered by)\b.{0,120}\bwordpress\b", lowered)
                )
            )
        )
        if looks_like_wordpress:
            mark("cms_indicators", "wordpress", ref)
            for match in _WORDPRESS_VERSION_RE.finditer(blob):
                mark("versions", f"wordpress {match.group(1)}", ref)
            for plugin in _PLUGIN_PATH_RE.findall(blob):
                if plugin:
                    mark("plugin_indicators", plugin, ref)
