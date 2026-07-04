"use strict";
// Response signal patterns used by the oracle classifier.
Object.defineProperty(exports, "__esModule", { value: true });
exports.REDIRECT_LOCATION_PATTERNS = exports.NOSQL_AUTH_BYPASS_PATTERNS = exports.XXE_REFLECTION_PATTERNS = exports.COMMAND_OUTPUT_PATTERNS = exports.FILE_CONTENT_PATTERNS = exports.SSTI_MATH_PATTERNS = exports.XSS_REFLECTION_PATTERNS = exports.SQL_ERROR_PATTERNS = void 0;
exports.matchesAnyPattern = matchesAnyPattern;
exports.simpleBodyHash = simpleBodyHash;
exports.SQL_ERROR_PATTERNS = [
    /sql syntax/i,
    /mysql.*error/i,
    /ora-\d{5}/i,
    /pg.*error/i,
    /sqlite.*error/i,
    /syntax error.*sql/i,
    /unclosed quotation mark/i,
    /division by zero/i,
    /you have an error in your sql/i,
    /quoted string not properly terminated/i,
    /odbc.*driver.*error/i,
    /microsoft.*sql.*server/i,
    /warning.*mysql/i,
    /supplied argument is not a valid mysql/i,
];
exports.XSS_REFLECTION_PATTERNS = [
    /<script[^>]*>alert\(/i,
    /onerror\s*=\s*alert\(/i,
    /onload\s*=\s*alert\(/i,
    /<svg[^>]*onload/i,
    /javascript:alert\(/i,
];
exports.SSTI_MATH_PATTERNS = [
    /\b49\b/, // 7*7 = 49
    /\b7777777\b/, // '7'*7 in Jinja2
];
exports.FILE_CONTENT_PATTERNS = [
    /root:x:0:0/,
    /bin\/bash/,
    /\[boot loader\]/i,
    /\[extensions\]/i,
    /\[386enh\]/i,
];
exports.COMMAND_OUTPUT_PATTERNS = [
    /uid=\d+\([^)]+\)/,
    /gid=\d+/,
    /proxyforge_cmd_probe/,
    /proxyforge_command_probe/,
];
exports.XXE_REFLECTION_PATTERNS = [
    /root:x:0:0/,
    /ENTITY.*SYSTEM/i,
];
exports.NOSQL_AUTH_BYPASS_PATTERNS = [
    /\[\s*\{/, // array of objects
    /"_id"\s*:/,
    /"__v"\s*:/,
];
exports.REDIRECT_LOCATION_PATTERNS = [
    /evil\.example\.com/i,
    /javascript:/i,
    /data:text\/html/i,
];
function matchesAnyPattern(text, patterns) {
    for (const pattern of patterns) {
        const match = text.match(pattern);
        if (match)
            return match[0];
    }
    return null;
}
function simpleBodyHash(text) {
    let h = 0x811c9dc5;
    for (let i = 0; i < text.length; i++) {
        h ^= text.charCodeAt(i);
        h = Math.imul(h, 0x01000193) >>> 0;
    }
    return h.toString(16).padStart(8, '0');
}
