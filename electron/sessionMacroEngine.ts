import http from 'node:http';
import https from 'node:https';
import { applySessionProfileToRawRequest, type RuntimeSessionProfile, type SessionApplicationTrace } from './sessionEngine';

export type SessionMacroExtractorSource = 'body' | 'headers';
export type SessionMacroExtractorTarget = 'header' | 'cookie';

export interface SessionMacroExtractor {
  id: string;
  name: string;
  source: SessionMacroExtractorSource;
  pattern: string;
  flags?: string;
  group?: number;
  target: SessionMacroExtractorTarget;
  targetName: string;
}

export interface SessionMacroStep {
  id: string;
  name: string;
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: string;
  extractors?: SessionMacroExtractor[];
}

export interface SessionMacroDefinition {
  id: string;
  name: string;
  scopeAllowlist: string[];
  steps: SessionMacroStep[];
}

export interface SessionMacroProfile extends RuntimeSessionProfile {
  role?: string;
  targetUrl?: string;
  source?: string;
  status?: 'ready' | 'stale' | 'needs-refresh';
  createdAt?: string;
  updatedAt?: string;
  headerCount?: number;
  cookieCount?: number;
  notes?: string;
}

export interface SessionMacroStepResult {
  stepId: string;
  name: string;
  status: 'complete' | 'blocked' | 'failed';
  statusCode?: number;
  targetUrl: string;
  rawRequest: string;
  rawResponse: string;
  extracted: Array<{
    extractorId: string;
    name: string;
    target: SessionMacroExtractorTarget;
    targetName: string;
    value: string;
  }>;
  setCookieNames: string[];
  message: string;
}

export interface SessionMacroRunResult {
  kind: 'proxyforge-session-macro-run';
  macroId: string;
  macroName: string;
  startedAt: string;
  completedAt: string;
  status: 'complete' | 'blocked' | 'failed';
  profile: SessionMacroProfile;
  steps: SessionMacroStepResult[];
  extractedTokenCount: number;
  setCookieCount: number;
  operationalSecretSignals: string[];
  rawExecutorMaterialPreserved: boolean;
  reportRedactionBoundary: 'redact-only-during-report-export';
  message: string;
}

export interface SessionMacroRunRequest {
  macro: SessionMacroDefinition;
  profile: SessionMacroProfile;
  timeoutMs?: number;
}

export interface SessionMacroEvidencePackage {
  kind: 'proxyforge-session-macro-evidence-package';
  schemaVersion: 1;
  generatedAt: string;
  macro: SessionMacroDefinition;
  result: SessionMacroRunResult;
  appliedRequests: Array<{
    tool: string;
    targetUrl: string;
    rawRequest: string;
    trace: SessionApplicationTrace;
  }>;
  requirements: {
    scopedExecutionCovered: boolean;
    macroStepExecutionCovered: boolean;
    tokenExtractionCovered: boolean;
    cookieRefreshCovered: boolean;
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

export async function runSessionMacro(request: SessionMacroRunRequest): Promise<SessionMacroRunResult> {
  const startedAt = new Date().toISOString();
  let profile = refreshProfileCounts({ ...request.profile });
  const steps: SessionMacroStepResult[] = [];
  let status: SessionMacroRunResult['status'] = 'complete';

  for (const step of request.macro.steps) {
    const target = safeUrl(step.url);
    if (!isInScope(target, request.macro.scopeAllowlist)) {
      status = 'blocked';
      steps.push({
        stepId: step.id,
        name: step.name,
        status: 'blocked',
        targetUrl: step.url,
        rawRequest: '',
        rawResponse: '',
        extracted: [],
        setCookieNames: [],
        message: `${target.host} is outside the macro scope allowlist.`,
      });
      break;
    }

    try {
      const response = await executeMacroStep(step, target, profile, request.timeoutMs ?? 8000);
      const cookieMerge = mergeSetCookies(profile.cookieText ?? '', response.setCookies);
      const extracted = extractMacroTokens(step.extractors ?? [], response.rawResponse, response.body);
      const headerText = mergeExtractedHeaders(profile.headerText ?? '', extracted);
      const cookieText = mergeExtractedCookies(cookieMerge.cookieText, extracted);
      profile = refreshProfileCounts({
        ...profile,
        headerText,
        cookieText,
        status: response.statusCode >= 400 ? 'needs-refresh' : 'ready',
        updatedAt: new Date().toISOString(),
      });
      steps.push({
        stepId: step.id,
        name: step.name,
        status: 'complete',
        statusCode: response.statusCode,
        targetUrl: target.toString(),
        rawRequest: response.rawRequest,
        rawResponse: response.rawResponse,
        extracted,
        setCookieNames: cookieMerge.setCookieNames,
        message: `Macro step completed with HTTP ${response.statusCode}, ${extracted.length} token(s), and ${cookieMerge.setCookieNames.length} cookie(s).`,
      });
    } catch (error) {
      status = 'failed';
      steps.push({
        stepId: step.id,
        name: step.name,
        status: 'failed',
        targetUrl: target.toString(),
        rawRequest: '',
        rawResponse: '',
        extracted: [],
        setCookieNames: [],
        message: error instanceof Error ? error.message : String(error),
      });
      break;
    }
  }

  const serialized = JSON.stringify({ profile, steps });
  const completedAt = new Date().toISOString();
  return {
    kind: 'proxyforge-session-macro-run',
    macroId: request.macro.id,
    macroName: request.macro.name,
    startedAt,
    completedAt,
    status,
    profile,
    steps,
    extractedTokenCount: steps.reduce((total, step) => total + step.extracted.length, 0),
    setCookieCount: steps.reduce((total, step) => total + step.setCookieNames.length, 0),
    operationalSecretSignals: detectMacroSecretSignals(serialized),
    rawExecutorMaterialPreserved: /Authorization:|Cookie:|session=|csrf=|Bearer|token|secret/i.test(serialized),
    reportRedactionBoundary: 'redact-only-during-report-export',
    message: `Session macro ${request.macro.name} ${status}.`,
  };
}

export function buildSessionMacroEvidencePackage(request: {
  macro: SessionMacroDefinition;
  result: SessionMacroRunResult;
  appliedRequests: Array<{
    tool: string;
    targetUrl: string;
    rawRequest: string;
    trace: SessionApplicationTrace;
  }>;
  generatedAt?: string;
}): SessionMacroEvidencePackage {
  const serialized = JSON.stringify(request);
  const packageBody = {
    kind: 'proxyforge-session-macro-evidence-package',
    schemaVersion: 1,
    generatedAt: request.generatedAt ?? new Date().toISOString(),
    macro: request.macro,
    result: request.result,
    appliedRequests: request.appliedRequests,
    requirements: {
      scopedExecutionCovered: request.result.steps.every((step) => step.status !== 'blocked') && request.macro.scopeAllowlist.length > 0,
      macroStepExecutionCovered: request.result.steps.some((step) => step.status === 'complete'),
      tokenExtractionCovered: request.result.extractedTokenCount > 0,
      cookieRefreshCovered: request.result.setCookieCount > 0,
      repeaterReady: request.appliedRequests.some((item) => item.tool === 'repeater' && item.trace.applied),
      intruderReady: request.appliedRequests.some((item) => item.tool === 'intruder' && item.trace.applied),
      scannerReady: request.appliedRequests.some((item) => item.tool === 'scanner' && item.trace.applied),
      rawOperationalSecretsPreserved: /Authorization:|Cookie:|session=|csrf=|Bearer|token|secret/i.test(serialized),
      reportPhaseOnlyRedaction: true,
    },
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    summary: `Session macro evidence preserved ${request.result.steps.length} step(s), ${request.result.extractedTokenCount} extracted token(s), and ${request.appliedRequests.length} applied request(s).`,
  } as const;
  return {
    ...packageBody,
    content: JSON.stringify(packageBody, null, 2),
  };
}

export function applyMacroProfileToToolRequest(rawRequest: string, targetUrl: string, profile: RuntimeSessionProfile) {
  return applySessionProfileToRawRequest(rawRequest, profile, { mode: 'merge', target: 'headers-and-cookies' });
}

function executeMacroStep(step: SessionMacroStep, target: URL, profile: RuntimeSessionProfile, timeoutMs: number) {
  return new Promise<{
    statusCode: number;
    body: string;
    setCookies: string[];
    rawRequest: string;
    rawResponse: string;
  }>((resolve, reject) => {
    const transport = target.protocol === 'https:' ? https : http;
    const body = step.body ?? '';
    const headers = {
      accept: 'text/html,application/json;q=0.9,*/*;q=0.8',
      ...sessionHeadersFromProfile(profile),
      ...(step.headers ?? {}),
      ...(body ? { 'content-length': Buffer.byteLength(body) } : {}),
    };
    const method = step.method.trim().toUpperCase() || 'GET';
    const rawRequest = renderRawRequest(method, target, headers, body);
    const clientRequest = transport.request({
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port || (target.protocol === 'https:' ? 443 : 80),
      method,
      path: `${target.pathname}${target.search}`,
      headers,
      timeout: timeoutMs,
    }, (response) => {
      const chunks: Buffer[] = [];
      response.on('data', (chunk: Buffer) => chunks.push(chunk));
      response.on('end', () => {
        const responseBody = Buffer.concat(chunks).toString('utf8');
        const rawResponse = `${renderRawResponseHead(response.statusCode ?? 0, response.statusMessage ?? '', response.rawHeaders)}${responseBody}`;
        resolve({
          statusCode: response.statusCode ?? 0,
          body: responseBody,
          setCookies: normalizeSetCookieHeaders(response.headers['set-cookie']),
          rawRequest,
          rawResponse,
        });
      });
    });
    clientRequest.on('timeout', () => clientRequest.destroy(new Error(`Timed out after ${timeoutMs}ms`)));
    clientRequest.on('error', reject);
    if (body) clientRequest.write(body);
    clientRequest.end();
  });
}

function extractMacroTokens(extractors: SessionMacroExtractor[], rawResponse: string, body: string) {
  const extracted: SessionMacroStepResult['extracted'] = [];
  for (const extractor of extractors) {
    const haystack = extractor.source === 'headers' ? rawResponse.split(/\r?\n\r?\n/, 1)[0] ?? rawResponse : body;
    const match = haystack.match(new RegExp(extractor.pattern, extractor.flags ?? 'i'));
    const value = match?.[extractor.group ?? 1];
    if (!value) continue;
    extracted.push({
      extractorId: extractor.id,
      name: extractor.name,
      target: extractor.target,
      targetName: extractor.targetName,
      value,
    });
  }
  return extracted;
}

function mergeExtractedHeaders(headerText: string, extracted: SessionMacroStepResult['extracted']) {
  const headers = parseHeaderLines(headerText);
  for (const item of extracted.filter((candidate) => candidate.target === 'header')) {
    headers.set(item.targetName, item.value);
  }
  return [...headers.entries()].map(([name, value]) => `${name}: ${value}`).join('\n');
}

function mergeExtractedCookies(cookieText: string, extracted: SessionMacroStepResult['extracted']) {
  const cookies = parseCookies(cookieText);
  for (const item of extracted.filter((candidate) => candidate.target === 'cookie')) {
    cookies.set(item.targetName, item.value);
  }
  return renderCookieHeader(cookies);
}

function mergeSetCookies(existingCookieText: string, setCookies: string[]) {
  const cookies = parseCookies(existingCookieText);
  const setCookieNames: string[] = [];
  for (const setCookie of setCookies) {
    const [pair] = setCookie.split(';');
    const separator = pair.indexOf('=');
    if (separator <= 0) continue;
    const name = pair.slice(0, separator).trim();
    const value = pair.slice(separator + 1).trim();
    if (!name || /[\r\n;]/.test(name)) continue;
    cookies.set(name, value);
    setCookieNames.push(name);
  }
  return {
    cookieText: renderCookieHeader(cookies),
    setCookieNames,
  };
}

function sessionHeadersFromProfile(profile: RuntimeSessionProfile): Record<string, string> {
  const headers = Object.fromEntries(parseHeaderLines(profile.headerText ?? ''));
  const cookieHeader = normalizeCookieHeader(profile.cookieText ?? '');
  if (cookieHeader) headers.Cookie = cookieHeader;
  return headers;
}

function parseHeaderLines(headerText: string) {
  const headers = new Map<string, string>();
  for (const line of headerText.split(/\r?\n/)) {
    const separator = line.indexOf(':');
    if (separator <= 0) continue;
    const name = line.slice(0, separator).trim();
    const value = line.slice(separator + 1).trim();
    if (!name || !value || /[\r\n]/.test(name) || /[\r\n]/.test(value)) continue;
    headers.set(name, value);
  }
  return headers;
}

function parseCookies(cookieText: string) {
  const cookies = new Map<string, string>();
  for (const cookie of normalizeCookieHeader(cookieText).split(';').map((item) => item.trim()).filter(Boolean)) {
    const separator = cookie.indexOf('=');
    if (separator <= 0) continue;
    cookies.set(cookie.slice(0, separator).trim(), cookie.slice(separator + 1).trim());
  }
  return cookies;
}

function renderCookieHeader(cookies: Map<string, string>) {
  return [...cookies.entries()].map(([name, value]) => `${name}=${value}`).join('; ');
}

function normalizeCookieHeader(cookieText: string) {
  return cookieText
    .replace(/^cookie:\s*/i, '')
    .split(/[;\n]+/)
    .map((item) => item.trim())
    .filter((item) => item && item.includes('=') && !/[\r\n]/.test(item))
    .join('; ');
}

function refreshProfileCounts(profile: SessionMacroProfile): SessionMacroProfile {
  const headers = sessionHeadersFromProfile(profile);
  return {
    ...profile,
    headerCount: Object.keys(headers).length,
    cookieCount: normalizeCookieHeader(profile.cookieText ?? '').split(';').filter((item) => item.trim()).length,
  };
}

function renderRawRequest(method: string, target: URL, headers: Record<string, string | number>, body: string) {
  return [
    `${method} ${target.pathname}${target.search} HTTP/1.1`,
    `Host: ${target.host}`,
    ...Object.entries(headers).map(([name, value]) => `${name}: ${value}`),
    '',
    body,
  ].join('\r\n');
}

function renderRawResponseHead(statusCode: number, statusMessage: string, rawHeaders: string[]) {
  const lines = [`HTTP/1.1 ${statusCode} ${statusMessage}`.trim()];
  for (let index = 0; index < rawHeaders.length; index += 2) {
    lines.push(`${rawHeaders[index]}: ${rawHeaders[index + 1] ?? ''}`);
  }
  return `${lines.join('\r\n')}\r\n\r\n`;
}

function normalizeSetCookieHeaders(header: string | string[] | undefined) {
  if (!header) return [];
  return Array.isArray(header) ? header : [header];
}

function isInScope(target: URL, scopeAllowlist: string[]) {
  if (scopeAllowlist.length === 0) return false;
  return scopeAllowlist.some((pattern) => {
    const normalized = pattern.trim().toLowerCase();
    if (!normalized) return false;
    if (normalized === target.hostname.toLowerCase() || normalized === target.host.toLowerCase()) return true;
    if (normalized.startsWith('*.')) return target.hostname.toLowerCase().endsWith(normalized.slice(1));
    return false;
  });
}

function safeUrl(value: string) {
  try {
    return new URL(value);
  } catch {
    return new URL('http://invalid.local/');
  }
}

function detectMacroSecretSignals(value: string) {
  const signals = new Set<string>();
  if (/Authorization:/i.test(value)) signals.add('authorization-header');
  if (/Cookie:/i.test(value)) signals.add('cookie-header');
  if (/session=/i.test(value)) signals.add('session-cookie');
  if (/csrf/i.test(value)) signals.add('csrf-token');
  if (/Bearer|token|secret|api[-_]?key|password/i.test(value)) signals.add('operational-secret-material');
  return [...signals];
}
