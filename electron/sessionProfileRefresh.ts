import http from 'node:http';
import https from 'node:https';

export interface RuntimeSessionProfile {
  id: string;
  name: string;
  role: string;
  targetUrl: string;
  source: 'manual' | 'browser' | 'traffic' | 'ci';
  status: 'ready' | 'stale' | 'needs-refresh';
  headerText: string;
  cookieText: string;
  createdAt: string;
  updatedAt: string;
  lastUsedAt?: string;
  headerCount: number;
  cookieCount: number;
  notes: string;
  refreshUrl?: string;
  expiresAt?: string;
  lastRefreshAt?: string;
  refreshStatus?: 'never' | 'refreshed' | 'unchanged' | 'failed';
  refreshCookieCount?: number;
  refreshMessage?: string;
}

export interface SessionProfileRefreshRequest {
  profile: RuntimeSessionProfile;
  timeoutMs?: number;
}

export interface SessionProfileRefreshResult {
  profile: RuntimeSessionProfile;
  status: 'refreshed' | 'unchanged' | 'failed';
  statusCode?: number;
  setCookieCount: number;
  headerCount: number;
  cookieCount: number;
  message: string;
  rawResponseHead: string;
}

export async function refreshSessionProfile(request: SessionProfileRefreshRequest): Promise<SessionProfileRefreshResult> {
  const startedAt = Date.now();
  const refreshUrl = request.profile.refreshUrl?.trim() || request.profile.targetUrl.trim();
  const now = new Date().toISOString();
  let target: URL;
  try {
    target = new URL(refreshUrl);
  } catch {
    return failedRefresh(request.profile, now, 'Session refresh URL is not a valid URL.');
  }

  try {
    const response = await requestRefreshEndpoint(target, request.profile, request.timeoutMs ?? 8000);
    const cookieMerge = mergeCookieHeader(request.profile.cookieText, response.setCookies);
    const updatedProfile = refreshSessionProfileCounts({
      ...request.profile,
      targetUrl: request.profile.targetUrl || target.toString(),
      refreshUrl: target.toString(),
      status: response.statusCode >= 400 ? 'needs-refresh' : 'ready',
      cookieText: cookieMerge.cookieText,
      expiresAt: cookieMerge.expiresAt ?? request.profile.expiresAt,
      lastRefreshAt: now,
      updatedAt: now,
      refreshStatus: cookieMerge.setCookieCount > 0 ? 'refreshed' : 'unchanged',
      refreshCookieCount: cookieMerge.setCookieCount,
      refreshMessage: cookieMerge.setCookieCount > 0
        ? `Refreshed ${cookieMerge.setCookieCount} cookie value${cookieMerge.setCookieCount === 1 ? '' : 's'} from ${target.host}.`
        : `Refresh completed with HTTP ${response.statusCode}, but no Set-Cookie headers were returned.`,
      notes: appendSessionNote(request.profile.notes, `Refresh ${response.statusCode} ${target.host}${target.pathname} in ${Date.now() - startedAt}ms`),
    });
    const status = cookieMerge.setCookieCount > 0 ? 'refreshed' : 'unchanged';
    return {
      profile: updatedProfile,
      status,
      statusCode: response.statusCode,
      setCookieCount: cookieMerge.setCookieCount,
      headerCount: updatedProfile.headerCount,
      cookieCount: updatedProfile.cookieCount,
      message: updatedProfile.refreshMessage ?? '',
      rawResponseHead: response.rawResponseHead,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return failedRefresh(request.profile, now, `Session refresh failed: ${message}`);
  }
}

function requestRefreshEndpoint(target: URL, profile: RuntimeSessionProfile, timeoutMs: number) {
  return new Promise<{ statusCode: number; setCookies: string[]; rawResponseHead: string }>((resolve, reject) => {
    const transport = target.protocol === 'https:' ? https : http;
    const headers = sessionHeadersFromProfile(profile);
    const request = transport.request(
      {
        protocol: target.protocol,
        hostname: target.hostname,
        port: target.port || (target.protocol === 'https:' ? 443 : 80),
        method: 'GET',
        path: `${target.pathname}${target.search}`,
        headers: {
          accept: 'text/html,application/json;q=0.9,*/*;q=0.8',
          ...headers,
        },
        timeout: timeoutMs,
      },
      (response) => {
        response.resume();
        response.on('end', () => {
          const setCookies = normalizeSetCookieHeaders(response.headers['set-cookie']);
          resolve({
            statusCode: response.statusCode ?? 0,
            setCookies,
            rawResponseHead: renderRawResponseHead(response.statusCode ?? 0, response.statusMessage ?? '', response.rawHeaders),
          });
        });
      },
    );
    request.on('timeout', () => {
      request.destroy(new Error(`Timed out after ${timeoutMs}ms`));
    });
    request.on('error', reject);
    request.end();
  });
}

function failedRefresh(profile: RuntimeSessionProfile, now: string, message: string): SessionProfileRefreshResult {
  const updatedProfile = refreshSessionProfileCounts({
    ...profile,
    status: 'needs-refresh',
    updatedAt: now,
    lastRefreshAt: now,
    refreshStatus: 'failed',
    refreshCookieCount: 0,
    refreshMessage: message,
  });
  return {
    profile: updatedProfile,
    status: 'failed',
    setCookieCount: 0,
    headerCount: updatedProfile.headerCount,
    cookieCount: updatedProfile.cookieCount,
    message,
    rawResponseHead: '',
  };
}

function sessionHeadersFromProfile(profile: RuntimeSessionProfile | undefined): Record<string, string> {
  if (!profile) return {};
  const headers = parseSessionHeaderText(profile.headerText);
  const cookieHeader = normalizeCookieHeader(profile.cookieText);
  if (cookieHeader) headers.Cookie = cookieHeader;
  return headers;
}

function parseSessionHeaderText(headerText: string) {
  const headers: Record<string, string> = {};
  for (const line of headerText.split(/\r?\n/)) {
    const separator = line.indexOf(':');
    if (separator <= 0) continue;
    const name = line.slice(0, separator).trim();
    const value = line.slice(separator + 1).trim();
    if (!isAllowedSessionHeader(name) || !value || /[\r\n]/.test(value)) continue;
    headers[name] = value;
  }
  return headers;
}

function isAllowedSessionHeader(name: string) {
  return /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name)
    && !/^(host|content-length|transfer-encoding|connection|proxy-connection|proxy-authorization)$/i.test(name);
}

function refreshSessionProfileCounts(profile: RuntimeSessionProfile): RuntimeSessionProfile {
  const headers = sessionHeadersFromProfile(profile);
  return {
    ...profile,
    headerCount: Object.keys(headers).length,
    cookieCount: countCookiePairs(headers.Cookie ?? headers.cookie ?? profile.cookieText),
  };
}

function normalizeCookieHeader(cookieText: string) {
  return cookieText
    .replace(/^cookie:\s*/i, '')
    .split(/[;\n]+/)
    .map((item) => item.trim())
    .filter((item) => item && item.includes('=') && !/[\r\n]/.test(item))
    .join('; ');
}

function countCookiePairs(cookieText: string) {
  const normalized = normalizeCookieHeader(cookieText);
  return normalized ? normalized.split(';').filter((item) => item.trim()).length : 0;
}

function mergeCookieHeader(existingCookieText: string, setCookies: string[]) {
  const cookies = new Map<string, string>();
  for (const cookie of normalizeCookieHeader(existingCookieText).split(';').map((item) => item.trim()).filter(Boolean)) {
    const [name, ...valueParts] = cookie.split('=');
    if (name && valueParts.length) cookies.set(name.trim(), valueParts.join('=').trim());
  }

  let setCookieCount = 0;
  let expiresAt: string | undefined;
  for (const setCookie of setCookies) {
    const [pair, ...attributes] = setCookie.split(';').map((item) => item.trim());
    const [name, ...valueParts] = pair.split('=');
    if (!name || valueParts.length === 0 || /[\r\n;]/.test(name)) continue;
    cookies.set(name, valueParts.join('='));
    setCookieCount += 1;
    const expiresAttribute = attributes.find((attribute) => /^expires=/i.test(attribute));
    if (expiresAttribute) {
      const parsed = new Date(expiresAttribute.slice(expiresAttribute.indexOf('=') + 1));
      if (!Number.isNaN(parsed.getTime())) expiresAt = parsed.toISOString();
    }
  }

  return {
    cookieText: Array.from(cookies.entries()).map(([name, value]) => `${name}=${value}`).join('; '),
    setCookieCount,
    expiresAt,
  };
}

function normalizeSetCookieHeaders(header: string | string[] | undefined) {
  if (!header) return [];
  return Array.isArray(header) ? header : [header];
}

function renderRawResponseHead(statusCode: number, statusMessage: string, rawHeaders: string[]) {
  const lines = [`HTTP/1.1 ${statusCode} ${statusMessage}`.trim()];
  for (let index = 0; index < rawHeaders.length; index += 2) {
    lines.push(`${rawHeaders[index]}: ${rawHeaders[index + 1] ?? ''}`);
  }
  return `${lines.join('\n')}\n\n`;
}

function appendSessionNote(notes: string, next: string) {
  const trimmed = notes.trim();
  return trimmed ? `${trimmed} ${next}.` : `${next}.`;
}
