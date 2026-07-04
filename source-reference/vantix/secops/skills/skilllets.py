from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Skilllet:
    id: str
    parent_skill: str
    surface_types: tuple[str, ...]
    trigger_facts: tuple[str, ...]
    summary: str
    guidance: tuple[str, ...]
    allowed_followups: tuple[str, ...] = ()
    forbidden_branches: tuple[str, ...] = ()
    expected_proof: tuple[str, ...] = ()

    def public(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "parent_skill": self.parent_skill,
            "surface_types": list(self.surface_types),
            "trigger_facts": list(self.trigger_facts),
            "summary": self.summary,
            "guidance": list(self.guidance),
            "allowed_followups": list(self.allowed_followups),
            "forbidden_branches": list(self.forbidden_branches),
            "expected_proof": list(self.expected_proof),
        }


COMMON_FORBIDDEN = (
    "static asset guessing unrelated to the active surface",
    "cookie/domain/localStorage leak probes unless they prove the locked surface",
    "CMS/cloud/AD/CVE branching without current-run evidence for this surface",
    "auth or credential pivots that do not advance the active proof condition",
)


SKILLLETS: dict[str, Skilllet] = {
    "web.xss.verifier_oracle": Skilllet(
        id="web.xss.verifier_oracle",
        parent_skill="web_hunter",
        surface_types=("xss_verifier",),
        trigger_facts=("verifier_oracle_signal",),
        summary="Close a live XSS verifier/oracle lane before broadening.",
        guidance=(
            "Preserve the exact route, method, content type, and parameter shape that reached the verifier.",
            "Classify each payload response as neutral/not-parsed, reflected-inert, verifier-type-error, wrong-observed-value, or expected-proof.",
            "Mutate only the alert/verifier contract until proof or bounded negative evidence is reached.",
        ),
        allowed_followups=("payload.oracle_response_classes", "payload.filter_grammar", "proof.browser_verifier"),
        forbidden_branches=COMMON_FORBIDDEN,
        expected_proof=("server-recorded expected value", "browser-observed execution artifact", "objective proof artifact"),
    ),
    "web.xss.context_mapping": Skilllet(
        id="web.xss.context_mapping",
        parent_skill="web_hunter",
        surface_types=("client_sink", "xss_verifier"),
        trigger_facts=("capability-candidate:client_sink",),
        summary="Map client-side source-to-sink context before payload expansion.",
        guidance=(
            "Identify the source, sink, encoding context, and browser execution boundary.",
            "Use one context-matched payload family before trying alternate contexts.",
        ),
        allowed_followups=("payload.filter_grammar", "proof.browser_verifier"),
        forbidden_branches=COMMON_FORBIDDEN,
        expected_proof=("browser-observed execution artifact",),
    ),
    "web.xss.sanitizer_bypass": Skilllet(
        id="web.xss.sanitizer_bypass",
        parent_skill="payload_crafter",
        surface_types=("xss_verifier", "client_sink"),
        trigger_facts=("payload_filter_signal",),
        summary="Derive compact XSS bypasses from the observed sanitizer grammar.",
        guidance=(
            "Infer which characters, tags, attributes, or separators changed the response class.",
            "Try a compact mutation set derived from that grammar; do not spray generic payload lists.",
        ),
        allowed_followups=("payload.oracle_response_classes", "proof.browser_verifier"),
        forbidden_branches=COMMON_FORBIDDEN,
        expected_proof=("response-class transition", "browser-observed execution artifact"),
    ),
    "web.sqli.blind_oracle_matrix": Skilllet(
        id="web.sqli.blind_oracle_matrix",
        parent_skill="web_hunter",
        surface_types=("blind_sql_oracle",),
        trigger_facts=("capability-candidate:blind_sql_injection_oracle",),
        summary="Convert boolean/error/time SQLi signal into a compact oracle matrix.",
        guidance=(
            "Preserve the exact route, method, content type, parameter location, auth state, and baseline response class that produced the SQL signal.",
            "Build a tiny baseline/probe matrix: neutral value, syntactically broken value, true predicate, false predicate, comment variant, and one DBMS fingerprint if needed.",
            "Infer DBMS/query shape only from response deltas, status, timing, error text, or length classes; do not jump to broad extraction.",
            "Promote only data-minimizing proof, auth-state proof, or objective-specific proof; otherwise record bounded negative evidence with the matrix.",
        ),
        allowed_followups=("payload.sql_oracle_constraints", "proof.http_replay", "proof.negative_evidence"),
        forbidden_branches=("dumping unrelated tables", "large blind extraction before objective mapping", "credential guessing from SQLi alone"),
        expected_proof=("baseline/probe SQL oracle matrix", "data-minimizing proof artifact", "bounded negative evidence"),
    ),
    "payload.sql_oracle_constraints": Skilllet(
        id="payload.sql_oracle_constraints",
        parent_skill="payload_crafter",
        surface_types=("blind_sql_oracle",),
        trigger_facts=("capability-candidate:blind_sql_injection_oracle", "blind_inference_signal"),
        summary="Craft SQL oracle probes from observed parser and response constraints.",
        guidance=(
            "Classify quote style, comment syntax, parentheses balance, numeric/string context, whitespace behavior, and DBMS-specific error/timing support.",
            "Generate only compact variants that test one hypothesis each: closure shape, boolean predicate, projection width, or bounded single-field proof.",
            "For time probes, cap delay and attempts, compare against a baseline, and stop if timing is noisy or service stability is affected.",
        ),
        allowed_followups=("web.sqli.blind_oracle_matrix", "proof.http_replay"),
        forbidden_branches=("unbounded extraction", "destructive SQL", "load-inducing timing loops"),
        expected_proof=("payload constraint notes", "response-class transition", "bounded timing or boolean proof"),
    ),
    "auth.credential.hash_strategy": Skilllet(
        id="auth.credential.hash_strategy",
        parent_skill="credential_tester",
        surface_types=("credential_material",),
        trigger_facts=("capability-candidate:hash_disclosure_or_credential_material", "credential_indicators"),
        summary="Classify disclosed credential material and validate only bounded owned/in-scope hypotheses.",
        guidance=(
            "Classify whether material is a hash, token, session value, API key, password reset artifact, or inert sample before any validation attempt.",
            "Record algorithm, salt/pepper indicators, user/object association, source, redaction shape, and whether offline cracking is allowed by rules of engagement.",
            "Prefer no-crack proof when possible: demonstrate exposure, privilege association, or controlled owned-account acceptance without broad guessing.",
            "If cracking is authorized, use a tiny evidence-derived candidate set first and stop on budget, lockout, or no actor/object linkage.",
        ),
        allowed_followups=("chain.credential_to_session", "proof.http_replay", "proof.negative_evidence"),
        forbidden_branches=("password spraying", "credential stuffing", "raw secret echoing in reports", "large wordlists without explicit approval"),
        expected_proof=("redacted credential material classification", "owned-context validation or exposure proof", "negative/budget cap note"),
    ),
    "chain.credential_to_session": Skilllet(
        id="chain.credential_to_session",
        parent_skill="exploit_chainer",
        surface_types=("credential_material",),
        trigger_facts=("capability-candidate:hash_disclosure_or_credential_material", "capability:auth_bypass"),
        summary="Map credential material to the next lawful session or authorization proof.",
        guidance=(
            "Ask the next-unlock question first: does this material prove data exposure, unlock an owned session, unlock a role boundary, or only indicate risk?",
            "Use one controlled authentication/readback attempt only when authorized and tied to a specific actor or owned test account.",
            "If material cannot be linked to an actor, report exposure and cap the chain instead of guessing identities.",
        ),
        allowed_followups=("auth.credential.hash_strategy", "proof.http_replay"),
        forbidden_branches=("spraying discovered material across users", "cross-account login attempts without authorization"),
        expected_proof=("session/readback proof or explicit capped-chain note",),
    ),
    "host.same_host.side_service_mapping": Skilllet(
        id="host.same_host.side_service_mapping",
        parent_skill="recon_advisor",
        surface_types=("same_host_side_service",),
        trigger_facts=("capability-candidate:mapped_side_service_candidate", "capability:source_local_side_service"),
        summary="Map same-host or source-local service hints to externally reachable candidates.",
        guidance=(
            "Correlate source/config hints, protocol names, banners, container/deploy clues, and current host inventory before probing.",
            "When the port list is shallow and the rules allow host-level testing, loop back once to a scoped same-host high-port inventory.",
            "Validate one read-only request per plausible mapped candidate and record mapped-port negatives before changing lanes.",
        ),
        allowed_followups=("chain.same_host_service_pivot", "proof.http_replay", "proof.negative_evidence"),
        forbidden_branches=("out-of-scope host enumeration", "credential guessing", "service disruption or brute force"),
        expected_proof=("same-host service map", "banner/protocol correlation", "read-only validation or negative evidence"),
    ),
    "chain.same_host_service_pivot": Skilllet(
        id="chain.same_host_service_pivot",
        parent_skill="exploit_chainer",
        surface_types=("same_host_side_service",),
        trigger_facts=("capability-candidate:mapped_side_service_candidate", "capability:mapped_side_service"),
        summary="Chain a validated same-host service only when it advances the current objective.",
        guidance=(
            "State the objective relevance of the side service before validation: auth source, file source, admin API, callback sink, or proof readback.",
            "Use the least invasive read-only primitive and preserve a request/response pair for each accepted or rejected candidate.",
            "When SSRF or same-host mapping exposes internal API docs, required-parameter errors, or operation routes, build a method/content-type/body matrix before deciding the chain is capped.",
            "For stateful internal operations, use one unique canary plus readback and cleanup when authorized; only continue toward file read, command execution, or objective proof if the canary reveals a new sink or privileged read path.",
            "Cap the side-service lane when mapping is negative, unsupported by scope, or unrelated to the objective proof.",
        ),
        allowed_followups=("host.same_host.side_service_mapping", "proof.http_replay"),
        forbidden_branches=("pivoting to unrelated services", "write actions before read-only proof", "service brute force"),
        expected_proof=("objective-linked side-service proof or capped negative map",),
    ),
    "proof.objective_gap_mapper": Skilllet(
        id="proof.objective_gap_mapper",
        parent_skill="poc_validator",
        surface_types=("objective_proof_gap", "blind_sql_oracle", "same_host_side_service", "credential_material"),
        trigger_facts=("capability-candidate:objective_proof_gap", "stagnation_signal"),
        summary="Map validated capabilities to the exact proof artifact the operator or report needs.",
        guidance=(
            "Write the objective proof as a concrete artifact shape: response body marker, authenticated readback, state transition, screenshot, exported file, or negative closure note.",
            "Separate validated capabilities from unsupported claims; do not carry analyst prompts forward as proof without saved artifacts.",
            "Choose the shortest next replay that could bridge the gap, then either save the proof, save negative evidence, or cap the claim.",
        ),
        allowed_followups=("proof.http_replay", "proof.negative_evidence", "web.sqli.blind_oracle_matrix", "chain.same_host_service_pivot"),
        forbidden_branches=("reporting unproven capabilities as validated", "repeating the same failed probe without new evidence"),
        expected_proof=("objective-to-capability proof map", "saved proof artifact or capped reason"),
    ),
    "web.ssrf.fetch_sink": Skilllet(
        id="web.ssrf.fetch_sink",
        parent_skill="web_hunter",
        surface_types=("ssrf_fetch",),
        trigger_facts=("capability-candidate:server_side_fetch", "capability:server_side_fetch"),
        summary="Validate a URL fetch sink from current-run evidence only.",
        guidance=(
            "Start from the observed URL parameter and same-origin baseline.",
            "Try scoped parser, redirect, and disclosed internal-route deltas only.",
        ),
        allowed_followups=("payload.filter_grammar", "proof.http_replay", "intel.cve.versioned_component"),
        forbidden_branches=("cloud metadata probing without authorization", "unbounded internal network enumeration"),
        expected_proof=("in-band internal response", "scoped same-host/private-route fetch evidence"),
    ),
    "web.file.static_helper": Skilllet(
        id="web.file.static_helper",
        parent_skill="web_hunter",
        surface_types=("file_read_or_static_helper",),
        trigger_facts=("capability-candidate:file_listing_expansion", "lfi_indicators"),
        summary="Close file/static helper disclosure lanes with direct request/response proof.",
        guidance=(
            "Compare direct static access against the helper route.",
            "Try known in-root resource names and one normalization variant before broad traversal.",
        ),
        allowed_followups=("proof.http_replay",),
        forbidden_branches=("login guessing", "generic traversal fuzzing after helper negatives"),
        expected_proof=("scoped file/static helper disclosure", "request/response artifact"),
    ),
    "web.ssti.template_or_include": Skilllet(
        id="web.ssti.template_or_include",
        parent_skill="web_hunter",
        surface_types=("template_include",),
        trigger_facts=("capability-candidate:template_or_include_path", "ssti_indicators"),
        summary="Validate template/include behavior from observed engine and route evidence.",
        guidance=(
            "Test minimal inert expressions before impact payloads.",
            "Use only templates, uploads, include paths, or error details implied by live evidence.",
        ),
        allowed_followups=("payload.filter_grammar", "proof.http_replay"),
        forbidden_branches=("blind RCE first", "unrelated route guessing"),
        expected_proof=("render delta", "include-path proof"),
    ),
    "api.authz.object_access": Skilllet(
        id="api.authz.object_access",
        parent_skill="api_security",
        surface_types=("authz_object_or_role",),
        trigger_facts=("capability-candidate:object_access_delta",),
        summary="Validate object access with owned/unowned and malformed identifier comparisons.",
        guidance=(
            "Preserve the valid identifier shape and compare owned, unowned, malformed, and role-shifted requests.",
            "Record exact negative evidence for each comparison.",
        ),
        allowed_followups=("proof.http_replay",),
        forbidden_branches=("unbounded object enumeration",),
        expected_proof=("owned/unowned authorization delta",),
    ),
    "api.authz.role_property": Skilllet(
        id="api.authz.role_property",
        parent_skill="bizlogic_hunter",
        surface_types=("authz_object_or_role",),
        trigger_facts=("capability-candidate:role_property_control",),
        summary="Validate role or privilege-like property control server-side.",
        guidance=(
            "Compare accepted, ignored, rejected, and persisted role/property deltas.",
            "Use only current-account or explicitly authorized cross-account evidence.",
        ),
        allowed_followups=("proof.http_replay",),
        forbidden_branches=("privilege spraying", "unbounded state mutation"),
        expected_proof=("server-side role/property authorization delta",),
    ),
    "api.schema.endpoint_matrix": Skilllet(
        id="api.schema.endpoint_matrix",
        parent_skill="api_security",
        surface_types=("api_surface", "authz_object_or_role"),
        trigger_facts=("api_schema", "openapi_schema"),
        summary="Build compact endpoint, method, auth-state, and object-shape matrices.",
        guidance=("Probe method, content type, auth state, object id, and role delta for the strongest endpoint candidates.",),
        allowed_followups=("api.authz.object_access", "api.authz.role_property", "proof.http_replay"),
        expected_proof=("endpoint matrix with positives and negatives",),
    ),
    "api.authz.object_ownership": Skilllet(
        id="api.authz.object_ownership",
        parent_skill="api_security",
        surface_types=("authz_object_or_role", "api_surface"),
        trigger_facts=("capability-candidate:object_ownership_boundary", "object_id_params"),
        summary="Prove object ownership checks with valid identifier shapes.",
        guidance=(
            "Derive owned and unowned identifiers from normal app flows, list/search output, schemas, or client routes.",
            "Compare unauthenticated, owned, unowned, malformed, and wrong-role requests with the same method and parser shape.",
            "Close the endpoint family only after each object-bearing action is validated, negative, blocked, or capped.",
        ),
        allowed_followups=("api.schema.endpoint_matrix", "proof.http_replay"),
        forbidden_branches=("numeric object spraying", "testing incompatible identifier shapes before collecting valid IDs"),
        expected_proof=("owned/unowned response delta", "authorization replay matrix"),
    ),
    "api.authz.property_overposting": Skilllet(
        id="api.authz.property_overposting",
        parent_skill="bizlogic_hunter",
        surface_types=("api_surface", "authz_object_or_role"),
        trigger_facts=("capability-candidate:property_overposting", "openapi_schema", "api_schema"),
        summary="Validate whether privileged or server-owned properties can be overposted.",
        guidance=(
            "Start from fields observed in schemas, responses, hidden inputs, client bundles, or source models.",
            "Compare normal request bodies to compact expanded bodies containing only role, owner, status, price, balance, or workflow fields already evidenced.",
            "Promote only when the server accepts, persists, or acts on a client-supplied server-owned field.",
        ),
        allowed_followups=("api.schema.endpoint_matrix", "proof.http_replay"),
        forbidden_branches=("adding arbitrary field lists without evidence", "privilege spraying"),
        expected_proof=("baseline/probe request pair", "server-side persistence or action delta"),
    ),
    "api.data.response_minimization": Skilllet(
        id="api.data.response_minimization",
        parent_skill="api_security",
        surface_types=("api_surface",),
        trigger_facts=("capability-candidate:excessive_response_data", "api_schema", "graphql"),
        summary="Check whether API responses expose fields beyond the actor, object, or workflow need.",
        guidance=(
            "Compare list, detail, search, export, and nested object responses for private fields that are not rendered or needed by the caller.",
            "For GraphQL or field-selectable APIs, test field-level authorization separately from endpoint authorization.",
            "Preserve redacted key names, object relation, auth state, and response location rather than raw sensitive values.",
        ),
        allowed_followups=("api.authz.object_ownership", "proof.http_replay"),
        forbidden_branches=("reporting sensitive-looking fields without actor/object context",),
        expected_proof=("redacted response field evidence", "actor/object authorization context"),
    ),
    "web.coverage.route_family_closure": Skilllet(
        id="web.coverage.route_family_closure",
        parent_skill="web_hunter",
        surface_types=("web_route_family", "api_surface"),
        trigger_facts=("capability-candidate:route_family_gap", "stagnation_signal"),
        summary="Close route families explicitly before declaring surface coverage complete.",
        guidance=(
            "Group discovered routes by resource, method, auth state, parser/content type, and state-changing behavior.",
            "For each family, record validated, negative evidence, blocked, or capped status with the evidence that justifies closure.",
            "When browser coverage is thin, switch to raw HTTP/API replay from current route literals and forms before ending the lane.",
        ),
        allowed_followups=("api.schema.endpoint_matrix", "proof.negative_evidence", "proof.http_replay"),
        forbidden_branches=("declaring coverage complete from homepage-only browsing",),
        expected_proof=("route family closure matrix", "negative evidence or replay artifact"),
    ),
    "web.path.normalization_confusion": Skilllet(
        id="web.path.normalization_confusion",
        parent_skill="web_hunter",
        surface_types=("path_normalization", "file_read_or_static_helper"),
        trigger_facts=("capability-candidate:path_normalization_confusion", "lfi_indicators"),
        summary="Validate path normalization and routing confusion with adjacent safe resources.",
        guidance=(
            "Compare proxy, framework, static-file, and helper-route behavior for the same in-scope resource.",
            "Use one encoding, separator, or dot-segment family derived from current route behavior before trying another.",
            "Stop at route confusion or scoped disclosure proof; do not jump to sensitive file reads without authorization.",
        ),
        allowed_followups=("proof.http_replay", "payload.filter_grammar"),
        forbidden_branches=("sensitive path reads without scoped proof permission", "unbounded traversal fuzzing"),
        expected_proof=("baseline/confused-route response pair", "normalization delta"),
    ),
    "web.realtime.message_authz": Skilllet(
        id="web.realtime.message_authz",
        parent_skill="api_security",
        surface_types=("realtime_api", "api_surface"),
        trigger_facts=("capability-candidate:realtime_message_boundary", "graphql"),
        summary="Treat realtime transports as APIs with message-level authorization.",
        guidance=(
            "Capture handshake auth, origin, subprotocol, first normal message, and object identifiers.",
            "Build a compact message matrix for unauthenticated, stale, wrong-origin, owned, unowned, and role-gated actions.",
            "Pair state-changing messages with an HTTP/API readback so proof is visible.",
        ),
        allowed_followups=("api.authz.object_ownership", "proof.http_replay"),
        forbidden_branches=("stress/depth/load testing", "message flooding"),
        expected_proof=("handshake evidence", "message replay and readback artifact"),
    ),
    "web.browser.cross_origin_boundary": Skilllet(
        id="web.browser.cross_origin_boundary",
        parent_skill="web_hunter",
        surface_types=("browser_boundary", "api_surface"),
        trigger_facts=("capability-candidate:cross_origin_boundary", "headers"),
        summary="Validate browser cross-origin boundaries from feasible request shapes.",
        guidance=(
            "Check credential mode, method, content type, preflight, Origin/Referer handling, cookies, and fetch-metadata behavior together.",
            "Do not report missing headers alone; prove whether a browser from an untrusted origin can read data or change state.",
            "Use CSP/framing/header posture as exploit-shaping context, not standalone impact.",
        ),
        allowed_followups=("proof.browser_verifier", "proof.http_replay"),
        forbidden_branches=("header-only findings without a feasible browser action",),
        expected_proof=("browser-feasible cross-origin read or state-change evidence",),
    ),
    "web.upload.parser_boundary": Skilllet(
        id="web.upload.parser_boundary",
        parent_skill="web_hunter",
        surface_types=("upload_parser", "template_include", "file_read_or_static_helper"),
        trigger_facts=("capability-candidate:upload_parser_path",),
        summary="Map upload/import parser behavior through storage, validation, retrieval, and processing.",
        guidance=(
            "Record allowed extensions, MIME checks, archive/import behavior, storage location, retrieval route, and parser error classes.",
            "Test one harmless parser/storage delta before payload families or include/execution hypotheses.",
            "Route confirmed parser or retrieval deltas back to source, file, template, or API validation.",
        ),
        allowed_followups=("payload.filter_grammar", "proof.http_replay"),
        forbidden_branches=("polyglot or active payloads before harmless parser proof",),
        expected_proof=("upload baseline/probe pair", "retrieval or parser delta"),
    ),
    "tls.transport_configuration": Skilllet(
        id="tls.transport_configuration",
        parent_skill="vuln_scanner",
        surface_types=("tls_transport",),
        trigger_facts=("capability-candidate:transport_security_review", "service"),
        summary="Review transport configuration with low-noise certificate, protocol, and cipher evidence.",
        guidance=(
            "Collect hostname, certificate chain, expiry, SANs, supported protocols, weak ciphers, and redirect/HSTS posture.",
            "Separate cryptographic policy weakness from exploitable app impact unless session or sensitive data exposure is proven.",
            "Prefer a single safe handshake/cipher inventory over repeated active scanner runs.",
        ),
        allowed_followups=("proof.http_replay", "proof.negative_evidence"),
        forbidden_branches=("downgrade or stress testing", "traffic interception outside scope"),
        expected_proof=("certificate/protocol/cipher inventory", "affected host evidence"),
    ),
    "scanner.module_safety_triage": Skilllet(
        id="scanner.module_safety_triage",
        parent_skill="vuln_scanner",
        surface_types=("scanner_module", "component_intel"),
        trigger_facts=("capability-candidate:safe_scanner_module", "detection_engine_match"),
        summary="Choose scanner modules by scope, noise, and proof value before execution.",
        guidance=(
            "Classify modules as passive inventory, safe probe, active validation, brute force, or destructive.",
            "Run only modules whose target service, version, auth state, and proof condition match current evidence.",
            "Treat output as a hypothesis packet until replay or runtime proof validates the current target.",
        ),
        allowed_followups=("intel.cve.versioned_component", "proof.http_replay"),
        forbidden_branches=("brute-force modules without explicit approval", "destructive or DoS modules"),
        expected_proof=("module selection rationale", "validated replay or negative evidence"),
    ),
    "mobile.storage.log_disclosure": Skilllet(
        id="mobile.storage.log_disclosure",
        parent_skill="mobile_pentester",
        surface_types=("mobile_storage",),
        trigger_facts=("apk_metadata", "capability-candidate:mobile_storage_or_logs"),
        summary="Validate sensitive mobile data in logs or weak storage without preserving raw secrets.",
        guidance=(
            "Classify the data first: credential, token, session, PII, crypto material, endpoint config, or debug artifact.",
            "Separate static candidate paths from runtime writes; proof needs app context and redacted excerpt or trace.",
            "Record location, access model, lifecycle, and redaction shape, not raw secret values.",
        ),
        allowed_followups=("proof.negative_evidence",),
        forbidden_branches=("saving raw tokens or private app data in shared notes",),
        expected_proof=("redacted storage/log excerpt", "runtime or app-context evidence"),
    ),
    "mobile.network.trust_anchor_pinning": Skilllet(
        id="mobile.network.trust_anchor_pinning",
        parent_skill="mobile_pentester",
        surface_types=("mobile_network",),
        trigger_facts=("apk_metadata", "capability-candidate:mobile_network_trust"),
        summary="Review mobile certificate validation, trust anchors, and pinning behavior.",
        guidance=(
            "Identify cleartext policy, trust anchors, certificate validation paths, pinning libraries, proxy behavior, and backend host scope.",
            "Distinguish test-device/proxy setup failures from app trust decisions.",
            "Promote only when app behavior shows weak validation, bypassable pinning, or sensitive traffic exposure.",
        ),
        allowed_followups=("proof.negative_evidence", "api.schema.endpoint_matrix"),
        forbidden_branches=("intercepting unrelated user traffic", "reporting pinning absence without sensitive reachable traffic"),
        expected_proof=("network config or runtime trust trace", "affected host/API context"),
    ),
    "mobile.platform.exported_component": Skilllet(
        id="mobile.platform.exported_component",
        parent_skill="mobile_pentester",
        surface_types=("mobile_platform",),
        trigger_facts=("apk_exported_component", "capability-candidate:mobile_exported_component"),
        summary="Validate exported component and deep-link reachability with harmless invocations.",
        guidance=(
            "Record component name, exported status, required permission, intent/deep-link filters, and expected auth/session preconditions.",
            "Invoke one harmless action and preserve negative evidence when permission, auth, or non-exported boundaries block access.",
            "If the component reaches backend APIs, carry the mobile auth context into API validation.",
        ),
        allowed_followups=("api.schema.endpoint_matrix", "proof.negative_evidence"),
        forbidden_branches=("destructive intents", "private data extraction without explicit authorization"),
        expected_proof=("manifest/deep-link evidence", "component invocation result"),
    ),
    "mobile.webview.privileged_bridge": Skilllet(
        id="mobile.webview.privileged_bridge",
        parent_skill="mobile_pentester",
        surface_types=("mobile_webview", "client_sink"),
        trigger_facts=("apk_metadata", "capability-candidate:mobile_webview_bridge"),
        summary="Map WebView origin checks and native bridge exposure before payload work.",
        guidance=(
            "Identify bridge methods, allowed origins, file/content URL access, mixed content, JavaScript settings, and navigation controls.",
            "Prove whether untrusted content can reach privileged native APIs before treating it as impact.",
            "Route browser/client-sink proof only after the mobile origin boundary is established.",
        ),
        allowed_followups=("web.xss.context_mapping", "proof.browser_verifier"),
        forbidden_branches=("payload spraying before origin/bridge mapping",),
        expected_proof=("bridge/origin mapping", "reachable harmless native action or negative evidence"),
    ),
    "enterprise.sap_router_fingerprint": Skilllet(
        id="enterprise.sap_router_fingerprint",
        parent_skill="vuln_scanner",
        surface_types=("enterprise_protocol",),
        trigger_facts=("capability-candidate:enterprise_protocol_recon", "service"),
        summary="Fingerprint enterprise protocol services with safe banner and route evidence only.",
        guidance=(
            "Use service, port, banner, route string, and version-error evidence to classify the protocol boundary.",
            "Treat admin commands, brute force, malformed protocol fuzzing, and credential checks as blocked unless explicitly authorized.",
            "Produce a safe recon packet with observed service, version confidence, required authorization, and validation stop condition.",
        ),
        allowed_followups=("intel.cve.versioned_component", "proof.negative_evidence"),
        forbidden_branches=("admin commands", "credential brute force", "malformed packet fuzzing", "route table modification"),
        expected_proof=("banner/version fingerprint", "scope and permission note"),
    ),
    "agentic.tool_boundary_control": Skilllet(
        id="agentic.tool_boundary_control",
        parent_skill="threat_modeler",
        surface_types=("agentic_system",),
        trigger_facts=("capability-candidate:agentic_tool_boundary", "source_file"),
        summary="Threat-model autonomous tool use as a confused-deputy boundary.",
        guidance=(
            "Map who can request tool use, which tools mutate state, what approvals are required, and how outputs are validated.",
            "Look for prompt-to-tool privilege jumps, hidden instruction acceptance, untrusted content controlling tool args, and missing audit trails.",
            "Produce remediation packets for guardrail, approval, logging, and replay requirements before exploitation claims.",
        ),
        allowed_followups=("proof.negative_evidence",),
        forbidden_branches=("running destructive tools to prove governance gaps",),
        expected_proof=("tool boundary map", "approval or audit gap evidence"),
    ),
    "agentic.memory_isolation": Skilllet(
        id="agentic.memory_isolation",
        parent_skill="threat_modeler",
        surface_types=("agentic_system",),
        trigger_facts=("capability-candidate:agentic_memory_boundary", "source_file"),
        summary="Assess memory, embedding, and vector-store isolation by tenant, role, and run context.",
        guidance=(
            "Map memory write, retrieval, deletion, retention, embedding, and redaction paths.",
            "Compare tenant, workspace, role, and run identifiers at both write and retrieval time.",
            "Promote only when cross-context retrieval, stale memory influence, or secret retention is evidenced.",
        ),
        allowed_followups=("proof.negative_evidence",),
        forbidden_branches=("secret exfiltration from unrelated tenants",),
        expected_proof=("memory path map", "cross-context access control evidence"),
    ),
    "agentic.multi_agent_goal_control": Skilllet(
        id="agentic.multi_agent_goal_control",
        parent_skill="swarm_orchestrator",
        surface_types=("agentic_system",),
        trigger_facts=("capability-candidate:agentic_multi_agent_control", "source_file"),
        summary="Review multi-agent delegation, goal drift, and cross-agent trust boundaries.",
        guidance=(
            "Map controller, worker, reviewer, memory, and tool permissions separately.",
            "Check whether agents can change scope, reinterpret goals, hide uncertainty, or act on peer output without validation.",
            "Require visible handoff packets, surface locks, and closure conditions for high-risk delegated work.",
        ),
        allowed_followups=("agentic.tool_boundary_control", "agentic.memory_isolation"),
        forbidden_branches=("silent delegation without audit",),
        expected_proof=("agent trust-boundary map", "handoff or approval evidence"),
    ),
    "payload.oracle_response_classes": Skilllet(
        id="payload.oracle_response_classes",
        parent_skill="payload_crafter",
        surface_types=("xss_verifier", "client_sink"),
        trigger_facts=("verifier_oracle_signal",),
        summary="Group payload attempts by observed response class.",
        guidance=("Continue only payload classes that change observed value or parser state.",),
        allowed_followups=("payload.filter_grammar", "proof.browser_verifier"),
        forbidden_branches=COMMON_FORBIDDEN,
        expected_proof=("expected-proof response class", "wrong-observed-value transition"),
    ),
    "payload.filter_grammar": Skilllet(
        id="payload.filter_grammar",
        parent_skill="payload_crafter",
        surface_types=("xss_verifier", "client_sink", "ssrf_fetch", "template_include"),
        trigger_facts=("payload_filter_signal", "verifier_oracle_signal"),
        summary="Infer filter grammar and test one compact mutation family.",
        guidance=("Derive mutations from stripped characters, parser errors, blocked separators, encoding behavior, or fixed TypeErrors.",),
        allowed_followups=("payload.oracle_response_classes", "proof.browser_verifier", "proof.http_replay"),
        expected_proof=("response-class transition",),
    ),
    "payload.blind_inference": Skilllet(
        id="payload.blind_inference",
        parent_skill="payload_crafter",
        surface_types=("ssrf_fetch", "template_include", "api_surface"),
        trigger_facts=("blind_inference_signal",),
        summary="Use baseline/probe deltas for blind surfaces.",
        guidance=("Preserve status, headers, body length/hash, and timing; repeat only the strongest noisy signal.",),
        allowed_followups=("proof.http_replay",),
        expected_proof=("repeatable blind delta",),
    ),
    "proof.browser_verifier": Skilllet(
        id="proof.browser_verifier",
        parent_skill="poc_validator",
        surface_types=("xss_verifier", "client_sink"),
        trigger_facts=("verifier_oracle_signal", "capability-candidate:client_sink"),
        summary="Convert a browser/verifier signal into objective proof.",
        guidance=("Drive the same payload through the live browser/verifier path and preserve observed execution or server-recorded proof.",),
        allowed_followups=("payload.oracle_response_classes", "payload.filter_grammar"),
        forbidden_branches=COMMON_FORBIDDEN,
        expected_proof=("browser/verifier proof artifact",),
    ),
    "proof.http_replay": Skilllet(
        id="proof.http_replay",
        parent_skill="poc_validator",
        surface_types=("ssrf_fetch", "file_read_or_static_helper", "template_include", "authz_object_or_role", "api_surface"),
        trigger_facts=("capability-candidate", "payload_filter_signal"),
        summary="Preserve replayable HTTP proof and negative evidence.",
        guidance=("Record request, response, baseline, cleanup, and why the result proves or refutes the lane.",),
        expected_proof=("request/response replay artifact",),
    ),
    "proof.negative_evidence": Skilllet(
        id="proof.negative_evidence",
        parent_skill="poc_validator",
        surface_types=("xss_verifier", "ssrf_fetch", "file_read_or_static_helper", "template_include", "authz_object_or_role"),
        trigger_facts=("negative_evidence", "stagnation_signal"),
        summary="Close a lane cleanly when preconditions are disproven.",
        guidance=("State the bounded attempts, preserved artifacts, and exact condition that releases the surface lock.",),
        expected_proof=("bounded negative evidence",),
    ),
    "intel.cve.versioned_component": Skilllet(
        id="intel.cve.versioned_component",
        parent_skill="vuln_scanner",
        surface_types=("component_intel",),
        trigger_facts=("cve", "version", "runtime-intel-query"),
        summary="Run narrow component/version intel only from observed runtime evidence.",
        guidance=("Use product, version, plugin path, REST namespace, and changelog/readme evidence from the current target.",),
        allowed_followups=("cms.plugin_entrypoint", "proof.http_replay"),
        forbidden_branches=("benchmark/writeup lookup", "unversioned exploit guessing"),
        expected_proof=("lookup query and exact-version match or negative evidence",),
    ),
    "cms.plugin_entrypoint": Skilllet(
        id="cms.plugin_entrypoint",
        parent_skill="vuln_scanner",
        surface_types=("component_intel",),
        trigger_facts=("cms-indicator", "plugin-indicator"),
        summary="Validate a known plugin entrypoint from observed CMS/plugin evidence.",
        guidance=("Start with tiny reachability/behavior probes for current-target plugin entrypoints only.",),
        allowed_followups=("intel.cve.versioned_component", "proof.http_replay"),
        expected_proof=("plugin/version evidence and entrypoint request/response"),
    ),
    "cloud.metadata_boundary": Skilllet(
        id="cloud.metadata_boundary",
        parent_skill="cloud_security",
        surface_types=("cloud_boundary",),
        trigger_facts=("cloud_indicators",),
        summary="Review cloud metadata boundaries only when current evidence makes cloud scope explicit.",
        guidance=("Require observed cloud deployment or authorized metadata boundary evidence before probing.",),
        expected_proof=("authorized cloud-boundary evidence",),
    ),
    "ad.kerberos_ldap_boundary": Skilllet(
        id="ad.kerberos_ldap_boundary",
        parent_skill="ad_attacker",
        surface_types=("ad_boundary",),
        trigger_facts=("ad_indicators",),
        summary="Review AD boundaries only when LDAP/Kerberos/SMB evidence is live and scoped.",
        guidance=("Require live service evidence before Kerberos/LDAP enumeration.",),
        expected_proof=("scoped directory-service evidence",),
    ),
}


SURFACE_ALLOWED_SKILLLETS: dict[str, tuple[str, ...]] = {
    surface: tuple(skilllet.id for skilllet in SKILLLETS.values() if surface in skilllet.surface_types)
    for surface in {
        "xss_verifier",
        "client_sink",
        "ssrf_fetch",
        "file_read_or_static_helper",
        "template_include",
        "authz_object_or_role",
        "blind_sql_oracle",
        "credential_material",
        "same_host_side_service",
        "objective_proof_gap",
        "api_surface",
        "web_route_family",
        "path_normalization",
        "realtime_api",
        "browser_boundary",
        "upload_parser",
        "tls_transport",
        "scanner_module",
        "mobile_storage",
        "mobile_network",
        "mobile_platform",
        "mobile_webview",
        "enterprise_protocol",
        "agentic_system",
        "component_intel",
        "cloud_boundary",
        "ad_boundary",
    }
}


def skilllets_for_surface(surface_type: str) -> list[Skilllet]:
    ids = SURFACE_ALLOWED_SKILLLETS.get(str(surface_type or ""), ())
    return [SKILLLETS[item] for item in ids if item in SKILLLETS]


def skilllets_by_ids(ids: list[str] | tuple[str, ...]) -> list[Skilllet]:
    return [SKILLLETS[item] for item in ids if item in SKILLLETS]


def parent_skills_for_skilllets(ids: list[str] | tuple[str, ...]) -> set[str]:
    return {skilllet.parent_skill for skilllet in skilllets_by_ids(tuple(ids))}


def public_skilllets(ids: list[str] | tuple[str, ...]) -> list[dict[str, Any]]:
    return [skilllet.public() for skilllet in skilllets_by_ids(tuple(ids))]


def merge_skilllet_guidance(ids: list[str] | tuple[str, ...]) -> dict[str, Any]:
    skilllets = skilllets_by_ids(tuple(ids))
    allowed_followups: list[str] = []
    forbidden: list[str] = []
    proof: list[str] = []
    guidance: list[str] = []
    parents: list[str] = []
    for skilllet in skilllets:
        if skilllet.parent_skill not in parents:
            parents.append(skilllet.parent_skill)
        for item in skilllet.guidance:
            if item not in guidance:
                guidance.append(item)
        for item in skilllet.allowed_followups:
            if item not in allowed_followups:
                allowed_followups.append(item)
        for item in skilllet.forbidden_branches:
            if item not in forbidden:
                forbidden.append(item)
        for item in skilllet.expected_proof:
            if item not in proof:
                proof.append(item)
    return {
        "skilllets": [item.public() for item in skilllets],
        "parent_skills": parents,
        "guidance": guidance,
        "allowed_followups": allowed_followups,
        "forbidden_branches": forbidden,
        "expected_proof": proof,
    }
