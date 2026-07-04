export type SessionInjectionMode = 'merge' | 'replace';
export type SessionInjectionTarget = 'headers' | 'cookies' | 'headers-and-cookies';

export interface RuntimeSessionProfile {
  id?: string;
  name?: string;
  headerText?: string;
  cookieText?: string;
}

export interface SessionApplyOptions {
  mode?: SessionInjectionMode;
  target?: SessionInjectionTarget;
}

export interface SessionApplicationTrace {
  applied: boolean;
  profileId?: string;
  profileName?: string;
  mode: SessionInjectionMode;
  target: SessionInjectionTarget;
  addedHeaders: string[];
  replacedHeaders: string[];
  preservedHeaders: string[];
  addedCookies: string[];
  replacedCookies: string[];
  preservedCookies: string[];
  operationalSecretSignals: string[];
  rawExecutorMaterialPreserved: boolean;
}

export interface SessionAppliedRequest {
  rawRequest: string;
  trace: SessionApplicationTrace;
}

interface HeaderLine {
  name: string;
  value: string;
}

export interface SessionCookieRecord {
  name: string;
  value: string;
  domain: string;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  hostOnly: boolean;
  sameSite?: string;
  expiresAt?: string;
  source: string;
  createdAt: string;
  updatedAt: string;
  lastSeenAt: string;
}

export interface SessionCookieCaptureResult {
  sourceUrl: string;
  source: string;
  addedCookies: string[];
  updatedCookies: string[];
  rejectedCookies: string[];
  cookieCount: number;
  operationalSecretSignals: string[];
}

export interface SharedCookieJarEvidencePackage {
  kind: 'proxyforge-shared-cookie-jar-evidence-package';
  schemaVersion: 1;
  generatedAt: string;
  cookieCount: number;
  captures: SessionCookieCaptureResult[];
  appliedRequests: Array<{
    tool: string;
    targetUrl: string;
    rawRequest: string;
    trace: SessionApplicationTrace;
  }>;
  cookies: SessionCookieRecord[];
  requirements: {
    setCookieCaptureCovered: boolean;
    requestCookieCaptureCovered: boolean;
    domainPathRulesCovered: boolean;
    secureTransportRulesCovered: boolean;
    repeaterReady: boolean;
    intruderReady: boolean;
    scannerReady: boolean;
    rawOperationalSecretsPreserved: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  summary: string;
  content: string;
}

export class SharedCookieJar {
  private readonly cookies = new Map<string, SessionCookieRecord>();

  constructor(cookies: SessionCookieRecord[] = []) {
    for (const cookie of cookies) {
      this.cookies.set(cookieKey(cookie.domain, cookie.path, cookie.name), { ...cookie });
    }
  }

  get size() {
    return this.cookies.size;
  }

  all(): SessionCookieRecord[] {
    return [...this.cookies.values()].sort((left, right) => (
      `${left.domain}\0${left.path}\0${left.name}`.localeCompare(`${right.domain}\0${right.path}\0${right.name}`)
    ));
  }

  captureFromSetCookie(setCookieHeaders: string | string[], sourceUrl: string, source = 'proxy-response'): SessionCookieCaptureResult {
    const headers = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
    const addedCookies: string[] = [];
    const updatedCookies: string[] = [];
    const rejectedCookies: string[] = [];
    const url = safeCookieUrl(sourceUrl);
    const now = new Date().toISOString();

    for (const header of headers) {
      const parsed = parseSetCookieHeader(header, url, source, now);
      if (!parsed) {
        rejectedCookies.push(header);
        continue;
      }
      const key = cookieKey(parsed.domain, parsed.path, parsed.name);
      if (parsed.expiresAt && Date.parse(parsed.expiresAt) <= Date.now()) {
        this.cookies.delete(key);
        updatedCookies.push(parsed.name);
        continue;
      }
      const existing = this.cookies.get(key);
      this.cookies.set(key, existing ? { ...parsed, createdAt: existing.createdAt } : parsed);
      (existing ? updatedCookies : addedCookies).push(parsed.name);
    }

    return cookieCaptureResult(sourceUrl, source, addedCookies, updatedCookies, rejectedCookies, this.all());
  }

  captureFromCookieHeader(cookieHeader: string, sourceUrl: string, source = 'proxy-request'): SessionCookieCaptureResult {
    const url = safeCookieUrl(sourceUrl);
    const now = new Date().toISOString();
    const addedCookies: string[] = [];
    const updatedCookies: string[] = [];
    const rejectedCookies: string[] = [];
    for (const [name, value] of parseCookies(cookieHeader)) {
      if (!name) {
        rejectedCookies.push(`${name}=${value}`);
        continue;
      }
      const cookie: SessionCookieRecord = {
        name,
        value,
        domain: url.hostname.toLowerCase(),
        path: defaultCookiePath(url.pathname),
        secure: url.protocol === 'https:',
        httpOnly: false,
        hostOnly: true,
        source,
        createdAt: now,
        updatedAt: now,
        lastSeenAt: now,
      };
      const key = cookieKey(cookie.domain, cookie.path, cookie.name);
      const existing = this.cookies.get(key);
      this.cookies.set(key, existing ? { ...cookie, createdAt: existing.createdAt } : cookie);
      (existing ? updatedCookies : addedCookies).push(cookie.name);
    }
    return cookieCaptureResult(sourceUrl, source, addedCookies, updatedCookies, rejectedCookies, this.all());
  }

  cookiesForUrl(targetUrl: string, now = new Date()): SessionCookieRecord[] {
    const url = safeCookieUrl(targetUrl);
    return this.all().filter((cookie) => cookieMatchesUrl(cookie, url, now));
  }

  cookieHeaderForUrl(targetUrl: string, now = new Date()): string {
    return renderCookieHeader(new Map(this.cookiesForUrl(targetUrl, now).map((cookie) => [cookie.name, cookie.value])));
  }

  applyToRawRequest(rawRequest: string, targetUrl: string, options: SessionApplyOptions = {}): SessionAppliedRequest {
    const cookieText = this.cookieHeaderForUrl(targetUrl);
    return applySessionProfileToRawRequest(rawRequest, {
      id: 'shared-cookie-jar',
      name: 'Shared Cookie Jar',
      cookieText,
    }, { mode: options.mode, target: options.target ?? 'cookies' });
  }
}

export function buildSharedCookieJarEvidencePackage(request: {
  jar: SharedCookieJar;
  captures: SessionCookieCaptureResult[];
  appliedRequests: Array<{
    tool: string;
    targetUrl: string;
    rawRequest: string;
    trace: SessionApplicationTrace;
  }>;
  generatedAt?: string;
}): SharedCookieJarEvidencePackage {
  const cookies = request.jar.all();
  const serialized = JSON.stringify({ cookies, captures: request.captures, appliedRequests: request.appliedRequests });
  const packageBody = {
    kind: 'proxyforge-shared-cookie-jar-evidence-package',
    schemaVersion: 1,
    generatedAt: request.generatedAt ?? new Date().toISOString(),
    cookieCount: cookies.length,
    captures: request.captures,
    appliedRequests: request.appliedRequests,
    cookies,
    requirements: {
      setCookieCaptureCovered: request.captures.some((capture) => capture.source === 'proxy-response' && capture.addedCookies.length > 0),
      requestCookieCaptureCovered: request.captures.some((capture) => capture.source === 'proxy-request' && capture.addedCookies.length > 0),
      domainPathRulesCovered: cookies.some((cookie) => !cookie.hostOnly) && cookies.some((cookie) => cookie.path !== '/'),
      secureTransportRulesCovered: cookies.some((cookie) => cookie.secure),
      repeaterReady: request.appliedRequests.some((item) => item.tool === 'repeater' && item.trace.applied),
      intruderReady: request.appliedRequests.some((item) => item.tool === 'intruder' && item.trace.applied),
      scannerReady: request.appliedRequests.some((item) => item.tool === 'scanner' && item.trace.applied),
      rawOperationalSecretsPreserved: /session=|csrf=|Bearer|token|secret|api[-_]?key|password/i.test(serialized),
      reportPhaseOnlyRedaction: true,
    },
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    summary: `Shared cookie jar evidence preserved ${cookies.length} cookie(s), ${request.captures.length} capture event(s), and ${request.appliedRequests.length} applied request(s).`,
  } as const;
  return {
    ...packageBody,
    content: JSON.stringify(packageBody, null, 2),
  };
}

export function applySessionProfileToRawRequest(
  rawRequest: string,
  profile?: RuntimeSessionProfile,
  options: SessionApplyOptions = {},
): SessionAppliedRequest {
  const mode = options.mode === 'replace' ? 'replace' : 'merge';
  const target = normalizeTarget(options.target);
  const trace: SessionApplicationTrace = {
    applied: false,
    profileId: profile?.id,
    profileName: profile?.name,
    mode,
    target,
    addedHeaders: [],
    replacedHeaders: [],
    preservedHeaders: [],
    addedCookies: [],
    replacedCookies: [],
    preservedCookies: [],
    operationalSecretSignals: [],
    rawExecutorMaterialPreserved: false,
  };

  if (!profile) return { rawRequest, trace };

  const parsed = parseRawRequestParts(rawRequest);
  const profileHeaders = parseHeaderText(profile.headerText ?? '');
  const profileCookieHeader = profileHeaders.find((header) => /^cookie$/i.test(header.name));
  const sessionHeaders = profileHeaders.filter((header) => !/^cookie$/i.test(header.name));
  const sessionCookies = parseCookies([
    profileCookieHeader?.value,
    profile.cookieText,
  ].filter(Boolean).join('; '));

  if (target !== 'cookies') {
    for (const header of sessionHeaders) {
      upsertHeader(parsed.headers, header, trace);
    }
  }

  if (target !== 'headers' && sessionCookies.size > 0) {
    upsertCookieHeader(parsed.headers, sessionCookies, mode, trace);
  }

  trace.applied = trace.addedHeaders.length > 0
    || trace.replacedHeaders.length > 0
    || trace.preservedHeaders.length > 0
    || trace.addedCookies.length > 0
    || trace.replacedCookies.length > 0
    || trace.preservedCookies.length > 0;
  trace.operationalSecretSignals = detectOperationalSecretSignals(parsed.headers);
  trace.rawExecutorMaterialPreserved = trace.applied && containsSessionMaterial(parsed.headers, sessionHeaders, sessionCookies);

  return {
    rawRequest: renderRawRequestParts(parsed.requestLine, parsed.headers, parsed.body),
    trace,
  };
}

function normalizeTarget(target?: SessionInjectionTarget): SessionInjectionTarget {
  return target === 'headers' || target === 'cookies' ? target : 'headers-and-cookies';
}

function parseRawRequestParts(rawRequest: string) {
  const separator = rawRequest.match(/\r?\n\r?\n/);
  const separatorIndex = separator?.index ?? -1;
  const separatorLength = separator ? separator[0].length : 0;
  const head = separatorIndex === -1 ? rawRequest : rawRequest.slice(0, separatorIndex);
  const body = separatorIndex === -1 ? '' : rawRequest.slice(separatorIndex + separatorLength);
  const lines = head.replace(/\r\n/g, '\n').split('\n').filter((line, index) => index === 0 || line.length > 0);
  const requestLine = lines.shift() || 'GET / HTTP/1.1';
  const headers = parseHeaderText(lines.join('\n'));
  return { requestLine, headers, body };
}

function parseHeaderText(text: string): HeaderLine[] {
  return text
    .replace(/\r\n/g, '\n')
    .split('\n')
    .map((line) => {
      const separator = line.indexOf(':');
      if (separator === -1) return null;
      const name = line.slice(0, separator).trim();
      const value = line.slice(separator + 1).trim();
      if (!name) return null;
      return { name, value };
    })
    .filter((header): header is HeaderLine => Boolean(header));
}

function upsertHeader(headers: HeaderLine[], next: HeaderLine, trace: SessionApplicationTrace) {
  const nameKey = normalizeHeaderName(next.name);
  const existingIndex = headers.findIndex((header) => normalizeHeaderName(header.name) === nameKey);
  if (existingIndex === -1) {
    headers.push(next);
    trace.addedHeaders.push(nameKey);
    return;
  }

  if (headers[existingIndex].value === next.value) {
    trace.preservedHeaders.push(nameKey);
  } else {
    trace.replacedHeaders.push(nameKey);
  }
  headers[existingIndex] = { name: headers[existingIndex].name, value: next.value };

  for (let index = headers.length - 1; index > existingIndex; index -= 1) {
    if (normalizeHeaderName(headers[index].name) === nameKey) headers.splice(index, 1);
  }
}

function upsertCookieHeader(
  headers: HeaderLine[],
  sessionCookies: Map<string, string>,
  mode: SessionInjectionMode,
  trace: SessionApplicationTrace,
) {
  const existingIndex = headers.findIndex((header) => /^cookie$/i.test(header.name));
  const existingCookies = existingIndex === -1 || mode === 'replace'
    ? new Map<string, string>()
    : parseCookies(headers[existingIndex].value);
  const nextCookies = new Map(existingCookies);

  for (const [name, value] of sessionCookies) {
    if (!existingCookies.has(name)) {
      trace.addedCookies.push(name);
    } else if (existingCookies.get(name) === value) {
      trace.preservedCookies.push(name);
    } else {
      trace.replacedCookies.push(name);
    }
    nextCookies.set(name, value);
  }

  const renderedCookie = renderCookieHeader(nextCookies);
  if (existingIndex === -1) {
    headers.push({ name: 'Cookie', value: renderedCookie });
  } else {
    headers[existingIndex] = { name: headers[existingIndex].name, value: renderedCookie };
  }
}

function parseCookies(text: string): Map<string, string> {
  const cookies = new Map<string, string>();
  for (const part of text.split(';')) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const separator = trimmed.indexOf('=');
    if (separator <= 0) continue;
    cookies.set(trimmed.slice(0, separator).trim(), trimmed.slice(separator + 1).trim());
  }
  return cookies;
}

function parseSetCookieHeader(header: string, url: URL, source: string, now: string): SessionCookieRecord | null {
  const parts = header.split(';').map((part) => part.trim()).filter(Boolean);
  const [nameValue, ...attributes] = parts;
  if (!nameValue) return null;
  const separator = nameValue.indexOf('=');
  if (separator <= 0) return null;
  const name = nameValue.slice(0, separator).trim();
  const value = nameValue.slice(separator + 1).trim();
  if (!name) return null;
  let domain = url.hostname.toLowerCase();
  let path = defaultCookiePath(url.pathname);
  let hostOnly = true;
  let secure = false;
  let httpOnly = false;
  let sameSite: string | undefined;
  let expiresAt: string | undefined;

  for (const attribute of attributes) {
    const attributeSeparator = attribute.indexOf('=');
    const attributeName = (attributeSeparator === -1 ? attribute : attribute.slice(0, attributeSeparator)).trim().toLowerCase();
    const attributeValue = attributeSeparator === -1 ? '' : attribute.slice(attributeSeparator + 1).trim();
    if (attributeName === 'domain' && attributeValue) {
      domain = attributeValue.replace(/^\./, '').toLowerCase();
      hostOnly = false;
    } else if (attributeName === 'path' && attributeValue.startsWith('/')) {
      path = attributeValue;
    } else if (attributeName === 'secure') {
      secure = true;
    } else if (attributeName === 'httponly') {
      httpOnly = true;
    } else if (attributeName === 'samesite' && attributeValue) {
      sameSite = attributeValue;
    } else if (attributeName === 'expires' && attributeValue) {
      const parsed = new Date(attributeValue);
      if (!Number.isNaN(parsed.getTime())) expiresAt = parsed.toISOString();
    } else if (attributeName === 'max-age' && /^-?\d+$/.test(attributeValue)) {
      expiresAt = new Date(Date.now() + Number(attributeValue) * 1000).toISOString();
    }
  }

  return {
    name,
    value,
    domain,
    path,
    secure,
    httpOnly,
    hostOnly,
    sameSite,
    expiresAt,
    source,
    createdAt: now,
    updatedAt: now,
    lastSeenAt: now,
  };
}

function cookieCaptureResult(
  sourceUrl: string,
  source: string,
  addedCookies: string[],
  updatedCookies: string[],
  rejectedCookies: string[],
  cookies: SessionCookieRecord[],
): SessionCookieCaptureResult {
  return {
    sourceUrl,
    source,
    addedCookies,
    updatedCookies,
    rejectedCookies,
    cookieCount: cookies.length,
    operationalSecretSignals: detectCookieSecretSignals(cookies),
  };
}

function cookieMatchesUrl(cookie: SessionCookieRecord, url: URL, now: Date): boolean {
  if (cookie.expiresAt && Date.parse(cookie.expiresAt) <= now.getTime()) return false;
  if (cookie.secure && url.protocol !== 'https:') return false;
  const host = url.hostname.toLowerCase();
  if (cookie.hostOnly) {
    if (host !== cookie.domain) return false;
  } else if (host !== cookie.domain && !host.endsWith(`.${cookie.domain}`)) {
    return false;
  }
  return pathMatchesCookiePath(url.pathname || '/', cookie.path);
}

function pathMatchesCookiePath(requestPath: string, cookiePath: string) {
  if (requestPath === cookiePath) return true;
  if (requestPath.startsWith(cookiePath.endsWith('/') ? cookiePath : `${cookiePath}/`)) return true;
  return cookiePath === '/' && requestPath.startsWith('/');
}

function defaultCookiePath(pathname: string) {
  if (!pathname || !pathname.startsWith('/')) return '/';
  if (pathname === '/') return '/';
  const slashIndex = pathname.lastIndexOf('/');
  return slashIndex <= 0 ? '/' : pathname.slice(0, slashIndex);
}

function cookieKey(domain: string, path: string, name: string) {
  return `${domain.toLowerCase()}\0${path}\0${name}`;
}

function safeCookieUrl(value: string) {
  try {
    return new URL(value);
  } catch {
    return new URL('http://invalid.local/');
  }
}

function detectCookieSecretSignals(cookies: SessionCookieRecord[]) {
  const signals = new Set<string>();
  for (const cookie of cookies) {
    if (/session/i.test(cookie.name)) signals.add('session-cookie');
    if (/csrf/i.test(cookie.name)) signals.add('csrf-cookie');
    if (/token|secret|api[-_]?key|password/i.test(cookie.name) || /token|secret|api[-_]?key|password/i.test(cookie.value)) {
      signals.add('operational-secret-material');
    }
  }
  return [...signals];
}

function renderCookieHeader(cookies: Map<string, string>) {
  return [...cookies.entries()].map(([name, value]) => `${name}=${value}`).join('; ');
}

function renderRawRequestParts(requestLine: string, headers: HeaderLine[], body: string) {
  return [
    requestLine,
    ...headers.map((header) => `${header.name}: ${header.value}`),
    '',
    body,
  ].join('\r\n');
}

function containsSessionMaterial(headers: HeaderLine[], sessionHeaders: HeaderLine[], sessionCookies: Map<string, string>) {
  const rendered = headers.map((header) => `${header.name}: ${header.value}`).join('\n');
  return sessionHeaders.every((header) => rendered.includes(`${header.name}: ${header.value}`))
    && [...sessionCookies.entries()].every(([name, value]) => rendered.includes(`${name}=${value}`));
}

function detectOperationalSecretSignals(headers: HeaderLine[]) {
  const signals = new Set<string>();
  for (const header of headers) {
    const key = normalizeHeaderName(header.name);
    const value = header.value;
    if (key === 'authorization' && /\S/.test(value)) signals.add('authorization-header');
    if (key === 'cookie' && /\S+=/.test(value)) signals.add('cookie-header');
    if (/api[-_]?key|x-api-key|token|secret/i.test(key)) signals.add(`${key}-header`);
    if (/(bearer\s+\S+|session=|token|secret|api[-_]?key)/i.test(value)) signals.add('operational-secret-material');
  }
  return [...signals];
}

function normalizeHeaderName(name: string) {
  return name.trim().toLowerCase();
}
