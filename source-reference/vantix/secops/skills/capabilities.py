from __future__ import annotations

import re
from dataclasses import dataclass


CAPABILITY_PATTERNS: dict[str, tuple[str, ...]] = {
    "auth_bypass": ("auth bypass", "authorization bypass", "role escalation", "self-promote", "admin route"),
    "source_disclosure": ("source disclosure", "source leak", "exposed source", "debug source"),
    "backup_exposure": ("backup archive", "backup leak", "public backup", "migration backup", "staging backup", "database dump"),
    "file_upload": ("file upload", "upload sink", "multipart", "uploaded file"),
    "lfi": ("lfi", "local file", "path traversal", "directory traversal", "file inclusion"),
    "ssrf": ("ssrf", "server-side request", "localhost", "127.0.0.1", "metadata service"),
    "ssti": ("ssti", "template injection", "jinja", "render_template_string", "{{"),
    "xss": ("xss", "cross-site scripting", "onerror=", "onfocus=", "<script"),
    "command_injection": ("command injection", "cmd injection", "shell command", "exec(", "system("),
    "token_leak": ("token leak", "session token", "jwt", "bearer token", "api key"),
    "admin_route": ("admin panel", "admin route", "/admin", "administrator"),
    "side_service_credentials": ("hardcoded credential", "hardcoded password", "embedded credential", "paramiko", "sshclient", "same-host service"),
    "source_local_side_service": ("localhost:22", "localhost service", "local side service", "source-local service", "mapped side service", "container-internal service"),
    "session_state_desync": ("server-side session", "session desync", "state desync", "read uncommitted", "open_session", "same-session race"),
}


@dataclass(frozen=True)
class CapabilityNextStep:
    capability: str
    next_questions: list[str]


def extract_capabilities(text: str) -> list[str]:
    lowered = (text or "").lower()
    found: list[str] = []
    for capability, terms in CAPABILITY_PATTERNS.items():
        if any(term in lowered for term in terms):
            found.append(capability)
    return found


def next_steps_for_capability(capability: str) -> CapabilityNextStep:
    steps = {
        "auth_bypass": ["enumerate newly reachable routes", "test role-gated object access", "check upload/import/export/admin sinks"],
        "source_disclosure": ["extract routes/config/secrets safely", "map disclosed sinks to live endpoints", "validate one source-derived exploit path"],
        "backup_exposure": ["fetch headers and small archive inventory", "extract targeted config/user/plugin rows", "chain to the shortest live authenticated or file-read proof"],
        "file_upload": ["identify storage path", "check served content type", "test include/render/execute behavior with inert payload"],
        "lfi": ["read non-sensitive proof file first", "look for config/source disclosure", "chain to credentials or route secrets if live"],
        "ssrf": ["compare localhost/internal responses", "test metadata/internal admin reachability", "preserve baseline/probe deltas"],
        "ssti": ["confirm arithmetic/string evaluation", "identify engine", "test bounded sandbox escape only if allowed"],
        "xss": ["infer filter shape", "try compact allowed tag/event family", "verify server-recorded callback when present"],
        "command_injection": ["prefer direct output", "try web-visible output channel", "fall back to bounded timing oracle"],
        "token_leak": ["validate one session use", "capture role indicators", "perform compact post-auth sweep"],
        "admin_route": ["check access preconditions", "test low-noise admin actions", "inspect export/upload/config functions"],
        "side_service_credentials": ["decode or derive once", "validate only against the indicated in-scope service", "hand the live service capability to web/API chaining"],
        "source_local_side_service": ["map internal service reference to observed same-host exposed services", "run scoped same-host high-port inventory if recon is shallow", "match by protocol/banner before port number", "validate one read-only proof against each plausible mapped candidate"],
        "session_state_desync": ["capture low-privileged session baseline", "coordinate same-session state mutation and privileged route observation", "repeat once only if timing noise is plausible"],
    }.get(capability, ["record capability", "ask what it unlocks next"])
    return CapabilityNextStep(capability=capability, next_questions=steps)


def capability_from_fact_value(value: str) -> str:
    caps = extract_capabilities(value)
    return caps[0] if caps else re.sub(r"[^a-z0-9_]+", "_", value.lower()).strip("_")[:64]
