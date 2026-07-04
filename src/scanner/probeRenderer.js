"use strict";
// Renders a mutated HTTP request for a given insertion point + payload variant.
// Adapted from source-reference/vantix/secops/skills/ probe_renderer concept.
// No runtime dependency on the vendored source.
Object.defineProperty(exports, "__esModule", { value: true });
exports.renderProbeForQuery = renderProbeForQuery;
exports.renderProbeForHeader = renderProbeForHeader;
exports.renderProbeForJsonField = renderProbeForJsonField;
exports.renderProbeForCookie = renderProbeForCookie;
exports.renderProbeForFormField = renderProbeForFormField;
exports.renderProbeForInsertionPoint = renderProbeForInsertionPoint;
function encodeVariantValue(variant) {
    switch (variant.encoding) {
        case 'url': return encodeURIComponent(variant.value);
        case 'double-url': return encodeURIComponent(encodeURIComponent(variant.value));
        case 'html': return variant.value
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
        case 'json-string': return JSON.stringify(variant.value).slice(1, -1);
        case 'header-safe': return variant.value.replace(/[\r\n]/g, ' ');
        default: return variant.value;
    }
}
function renderProbeForQuery(baseRequest, paramName, variant) {
    const url = new URL(baseRequest.url);
    const encodedValue = encodeVariantValue(variant);
    url.searchParams.set(paramName, variant.encoding === 'url' ? variant.value : variant.value);
    const mutatedUrl = url.toString().replace(`${encodeURIComponent(paramName)}=${encodeURIComponent(url.searchParams.get(paramName) ?? '')}`, `${encodeURIComponent(paramName)}=${encodedValue}`);
    const rawRequest = buildRawRequest(baseRequest.method, mutatedUrl, baseRequest.headers, baseRequest.body);
    return {
        variantId: variant.id,
        rawRequest,
        url: mutatedUrl,
        mutatedValue: encodedValue,
        insertionPointKind: 'query',
        insertionPointName: paramName,
    };
}
function renderProbeForHeader(baseRequest, headerName, variant) {
    const headers = { ...baseRequest.headers, [headerName]: encodeVariantValue(variant) };
    const rawRequest = buildRawRequest(baseRequest.method, baseRequest.url, headers, baseRequest.body);
    return {
        variantId: variant.id,
        rawRequest,
        url: baseRequest.url,
        mutatedValue: variant.value,
        insertionPointKind: 'header',
        insertionPointName: headerName,
    };
}
function renderProbeForJsonField(baseRequest, fieldPath, variant) {
    let body;
    try {
        body = JSON.parse(baseRequest.body);
    }
    catch {
        body = {};
    }
    setNestedValue(body, fieldPath, variant.value);
    const mutatedBody = JSON.stringify(body);
    const headers = { ...baseRequest.headers, 'content-length': String(mutatedBody.length) };
    const rawRequest = buildRawRequest(baseRequest.method, baseRequest.url, headers, mutatedBody);
    return {
        variantId: variant.id,
        rawRequest,
        url: baseRequest.url,
        mutatedValue: variant.value,
        insertionPointKind: 'json',
        insertionPointName: fieldPath,
    };
}
function renderProbeForCookie(baseRequest, cookieName, variant) {
    const existing = baseRequest.headers['cookie'] ?? baseRequest.headers['Cookie'] ?? '';
    const cookies = existing.split(';').map((c) => c.trim()).filter((c) => !c.startsWith(`${cookieName}=`));
    cookies.push(`${cookieName}=${encodeVariantValue(variant)}`);
    const headers = { ...baseRequest.headers, cookie: cookies.join('; ') };
    const rawRequest = buildRawRequest(baseRequest.method, baseRequest.url, headers, baseRequest.body);
    return {
        variantId: variant.id,
        rawRequest,
        url: baseRequest.url,
        mutatedValue: variant.value,
        insertionPointKind: 'cookie',
        insertionPointName: cookieName,
    };
}
function renderProbeForFormField(baseRequest, fieldName, variant) {
    const form = new URLSearchParams(baseRequest.body);
    form.set(fieldName, variant.value);
    const mutatedBody = form.toString();
    const headers = { ...baseRequest.headers, 'content-length': String(mutatedBody.length) };
    const rawRequest = buildRawRequest(baseRequest.method, baseRequest.url, headers, mutatedBody);
    return {
        variantId: variant.id,
        rawRequest,
        url: baseRequest.url,
        mutatedValue: variant.value,
        insertionPointKind: 'body',
        insertionPointName: fieldName,
    };
}
function renderProbeForInsertionPoint(baseRequest, kind, name, variant) {
    switch (kind) {
        case 'query': return renderProbeForQuery(baseRequest, name, variant);
        case 'header': return renderProbeForHeader(baseRequest, name, variant);
        case 'cookie': return renderProbeForCookie(baseRequest, name, variant);
        case 'json': return renderProbeForJsonField(baseRequest, name, variant);
        case 'form': return renderProbeForFormField(baseRequest, name, variant);
        default: return renderProbeForQuery(baseRequest, name, variant);
    }
}
function buildRawRequest(method, url, headers, body) {
    let urlObj;
    try {
        urlObj = new URL(url);
    }
    catch {
        urlObj = new URL(`https://target.invalid${url.startsWith('/') ? url : `/${url}`}`);
    }
    const path = `${urlObj.pathname}${urlObj.search}`;
    const lines = [`${method.toUpperCase()} ${path} HTTP/1.1`];
    for (const [name, value] of Object.entries(headers)) {
        if (name.toLowerCase() === 'content-length' && !body)
            continue;
        lines.push(`${name}: ${value}`);
    }
    if (!headers['host'] && !headers['Host']) {
        lines.push(`Host: ${urlObj.host}`);
    }
    if (body) {
        lines.push(`Content-Length: ${Buffer.byteLength(body, 'utf8')}`);
        lines.push('');
        lines.push(body);
    }
    else {
        lines.push('');
        lines.push('');
    }
    return lines.join('\r\n');
}
function setNestedValue(obj, path, value) {
    const parts = path.split('.');
    let current = obj;
    for (let i = 0; i < parts.length - 1; i++) {
        const part = parts[i];
        if (!isRecord(current[part]))
            current[part] = {};
        current = current[part];
    }
    current[parts[parts.length - 1]] = value;
}
function isRecord(value) {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}
