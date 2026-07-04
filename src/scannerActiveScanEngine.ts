import type {
  ActiveScanCheckId,
  ActiveScanFinding,
  ActiveScanSummary,
  CallbackInteraction,
  CallbackPayload,
  CrawlInsertionPoint,
  HttpExchange,
  Issue,
  ScannerActiveScanEvidencePackage,
  ScannerActiveScanPlan,
  ScannerAuthenticatedStateMatrix,
  ScannerAuthenticatedStateMatrixRow,
  ScannerInsertionPointReview,
  ScannerInsertionPointReviewRow,
  ScannerLiveTargetProfilePackage,
  ScannerOastIssuePromotionPackage,
  ScannerReplayCheckPackage,
  SessionProfile,
  Severity,
} from './types';
import { extractInsertionPointsFromExchanges } from './insertionPointEngine';

export interface ScannerActiveScanEngineRequest {
  exchanges: HttpExchange[];
  selectedExchange?: HttpExchange;
  selectedExchangeId?: string;
  checks?: ActiveScanCheckId[];
  checkPackId?: string;
  checkPackLabel?: string;
  scopeAllowlist?: string[];
  throttleMs?: number;
  maxRequests?: number;
  insertionPoints?: CrawlInsertionPoint[];
  sessionProfile?: SessionProfile;
  sessionProfiles?: SessionProfile[];
  activeScanSummary?: ActiveScanSummary | null;
  plan?: ScannerActiveScanPlan;
  insertionPointReview?: ScannerInsertionPointReview;
  authenticatedStateMatrix?: ScannerAuthenticatedStateMatrix;
  replayCheckPackage?: ScannerReplayCheckPackage;
  now?: string;
}

type ScannerOastExchangeInput = Partial<Omit<HttpExchange, 'requestRaw' | 'responseRaw'>> & {
  requestRaw?: unknown;
  responseRaw?: unknown;
};

export interface ScannerOastIssuePromotionRequest {
  projectName?: string;
  sourceExchange?: ScannerOastExchangeInput;
  scannerExchange: ScannerOastExchangeInput;
  payload: Partial<CallbackPayload>;
  interaction: Partial<Omit<CallbackInteraction, 'raw'>> & { raw?: unknown; token?: string };
  finding?: Partial<ActiveScanFinding>;
  activeScanSummary?: Pick<ActiveScanSummary, 'id' | 'targetUrl' | 'totalRequests' | 'message'> | null;
  generatedAt?: string;
  scopeAllowlist?: string[];
}

export interface ScannerLinkedEvidencePackage {
  id?: string;
  kind?: string;
  content?: string;
  reportReady?: boolean;
  status?: string;
  requirements?: Record<string, boolean>;
  summary?: string;
}

export interface ScannerLiveTargetProfileRequest {
  activeScanEvidencePackages: ScannerActiveScanEvidencePackage[];
  activeScanSummaries: ActiveScanSummary[];
  passiveDedupePackages?: ScannerLinkedEvidencePackage[];
  insertionInventoryPackages?: ScannerLinkedEvidencePackage[];
  oastIssuePromotionPackages?: ScannerOastIssuePromotionPackage[];
  anvilCompatibilityPackages?: ScannerLinkedEvidencePackage[];
  retestPackages?: ScannerLinkedEvidencePackage[];
  calibrationPackages?: ScannerLinkedEvidencePackage[];
  generatedAt?: string;
  minTargetHosts?: number;
  minRoutes?: number;
  minRequests?: number;
  minCheckFamilies?: number;
  minTuningProfiles?: number;
  operationalSecretSamples?: string[];
}

type ScannerInsertionInput = Partial<CrawlInsertionPoint> & {
  exchangeId?: string;
  location?: string;
  parameter?: string;
  route?: string;
  risk?: Severity;
  notes?: string;
};

const severityRank: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

const checkLabels: Record<ActiveScanCheckId, string> = {
  'security-headers': 'Security headers',
  'cors-origin': 'CORS origin',
  'cache-key': 'Cache key',
  'method-options': 'OPTIONS methods',
  'authz-diff': 'Authenticated-state comparison',
  'jwt-claims': 'JWT claim review',
  'graphql-introspection': 'GraphQL introspection',
  'oast-ssrf': 'OAST SSRF callback',
  'reflected-xss': 'Reflected XSS',
  'sql-injection': 'SQL injection',
  'path-traversal': 'Path traversal',
  'open-redirect': 'Open redirect',
  'command-injection': 'Command injection',
};

function simpleDigest(value: string) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `${hash.toString(16).padStart(8, '0')}${value.length.toString(16).padStart(8, '0')}`;
}

function selectedExchange(request: ScannerActiveScanEngineRequest) {
  return request.selectedExchange
    ?? request.exchanges.find((exchange) => exchange.id === request.selectedExchangeId)
    ?? request.exchanges.find((exchange) => exchange.tags.includes('authz'))
    ?? request.exchanges[0];
}

function normalizedChecks(request: ScannerActiveScanEngineRequest): ActiveScanCheckId[] {
  const policyChecks = (request as unknown as { activeScanPolicy?: { checks?: string[] } }).activeScanPolicy?.checks ?? [];
  const packChecks = ((request as unknown as { checkPacks?: Array<{ checks?: string[] }> }).checkPacks ?? []).flatMap((pack) => pack.checks ?? []);
  const rawChecks = request.checks?.length ? request.checks : [...policyChecks, ...packChecks];
  const allowed = new Set<ActiveScanCheckId>([
    'security-headers',
    'cors-origin',
    'cache-key',
    'method-options',
    'authz-diff',
    'jwt-claims',
    'graphql-introspection',
    'oast-ssrf',
    'reflected-xss',
    'sql-injection',
    'path-traversal',
    'open-redirect',
    'command-injection',
  ]);
  const checks = rawChecks.filter((check): check is ActiveScanCheckId => allowed.has(check as ActiveScanCheckId));
  return Array.from(new Set(checks.length ? checks : ['security-headers', 'cors-origin', 'cache-key', 'method-options']));
}

function routeKey(exchange: Pick<HttpExchange, 'method' | 'host' | 'path'>) {
  return `${exchange.method.toUpperCase()} ${exchange.host}${exchange.path}`;
}

function pathFromUrl(value: string) {
  try {
    return new URL(value).pathname || '/';
  } catch {
    return value.split('?')[0] || '/';
  }
}

function hostFromUrl(value: string) {
  try {
    return new URL(value).host;
  } catch {
    return '';
  }
}

function inScope(url: string, scopeAllowlist: string[]) {
  if (!scopeAllowlist.length) return true;
  const host = hostFromUrl(url);
  return scopeAllowlist.some((scope) => {
    const normalized = scope.replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase();
    if (normalized.startsWith('*.')) return host.toLowerCase().endsWith(normalized.slice(1));
    return host.toLowerCase() === normalized || host.toLowerCase().endsWith(`.${normalized}`);
  });
}

function replayCandidates(request: ScannerActiveScanEngineRequest) {
  const selected = selectedExchange(request);
  const candidates = request.exchanges.filter((exchange) => (
    exchange.source === 'repeater'
    || exchange.source === 'scanner'
    || exchange.tags.some((tag) => /authz|replay|candidate|scanner|matrix/i.test(tag))
    || exchange.id === selected?.id
  ));
  return candidates.length ? candidates : selected ? [selected] : [];
}

function insertionInputs(request: ScannerActiveScanEngineRequest): ScannerInsertionInput[] {
  if (request.insertionPoints?.length) return request.insertionPoints as ScannerInsertionInput[];
  return extractInsertionPointsFromExchanges(request.exchanges, {
    includeHeaders: true,
    includePathSegments: true,
    maxPointsPerExchange: 80,
  }) as ScannerInsertionInput[];
}

function insertionPointUrl(point: ScannerInsertionInput, request: ScannerActiveScanEngineRequest) {
  if (point.url) return point.url;
  const exchange = request.exchanges.find((candidate) => candidate.id === point.exchangeId);
  return exchange?.url ?? selectedExchange(request)?.url ?? 'https://target.invalid/';
}

function insertionPointMethod(point: ScannerInsertionInput, request: ScannerActiveScanEngineRequest) {
  if (point.method) return point.method;
  const exchange = request.exchanges.find((candidate) => candidate.id === point.exchangeId);
  return exchange?.method ?? String(point.route ?? 'GET').split(/\s+/, 1)[0] ?? 'GET';
}

function insertionPointName(point: ScannerInsertionInput) {
  return point.name ?? point.parameter ?? point.location ?? 'selected insertion point';
}

function recommendedChecksForExchange(exchange: HttpExchange, selectedChecks: ActiveScanCheckId[]) {
  const checks = new Set<ActiveScanCheckId>(selectedChecks);
  if (/authorization:|cookie:|session|bearer/i.test(exchange.requestRaw)) checks.add('authz-diff');
  if (/eyJ[A-Za-z0-9_-]+\./.test(exchange.requestRaw + exchange.responseRaw)) checks.add('jwt-claims');
  if (/graphql|__schema|query\s*\{/i.test(`${exchange.url}\n${exchange.requestRaw}\n${exchange.responseRaw}`)) checks.add('graphql-introspection');
  if (/[?&](q|query|search|term|input|name)=|<input|textarea|contenteditable/i.test(`${exchange.url}\n${exchange.requestRaw}\n${exchange.responseRaw}`)) checks.add('reflected-xss');
  if (/[?&](id|sort|filter|where)=|select\s+.+\s+from|sql|database/i.test(`${exchange.url}\n${exchange.requestRaw}\n${exchange.responseRaw}`)) checks.add('sql-injection');
  if (/[?&](file|path|download|template)=|\.\.\//i.test(`${exchange.url}\n${exchange.requestRaw}`)) checks.add('path-traversal');
  if (/[?&](next|redirect|redir|redirectUrl|redirect_url|redirect_uri|redirectTo|return|returnUrl|return_url|returnTo|continue|url|dest|destination|forward|forwardUrl|callback|callbackUrl|goto|target|targetUrl)=/i.test(`${exchange.url}\n${exchange.requestRaw}`)) checks.add('open-redirect');
  if (/[?&](cmd|exec|command|ping|host)=|shell|system\(/i.test(`${exchange.url}\n${exchange.requestRaw}`)) checks.add('command-injection');
  if (exchange.method !== 'GET') checks.add('method-options');
  return Array.from(checks);
}

function highestSeverity(rows: Array<{ risk?: Severity }>, fallback: Severity = 'medium') {
  return rows.reduce<Severity>((highest, row) => (
    row.risk && severityRank[row.risk] > severityRank[highest] ? row.risk : highest
  ), fallback);
}

function countValues<T extends string>(values: T[]): Partial<Record<T, number>> {
  return values.reduce<Partial<Record<T, number>>>((memo, value) => ({
    ...memo,
    [value]: (memo[value] ?? 0) + 1,
  }), {});
}

function uniqueValues<T>(values: T[]) {
  return Array.from(new Set(values));
}

function scannerOperationalSecretSignals(...rawValues: string[]) {
  const text = rawValues.join('\n');
  const signals: string[] = [];
  if (/^authorization:\s*\S+/im.test(text)) signals.push('authorization-header');
  if (/^cookie:\s*\S+/im.test(text)) signals.push('cookie-header');
  if (/^x-api-key:\s*\S+/im.test(text)) signals.push('x-api-key-header');
  if (/^idempotency-key:\s*\S+/im.test(text)) signals.push('idempotency-key-header');
  if (/(bearer\s+[a-z0-9._~+/=-]+|api[_-]?key|access[_-]?token|refresh[_-]?token|secret|session=|eyJ[a-z0-9_-]+\.)/i.test(text)) {
    signals.push('secret-like-material');
  }
  return Array.from(new Set(signals));
}

function scannerRawValueToText(value: unknown) {
  if (typeof value === 'string') return value;
  if (value == null) return '';
  if (value instanceof Uint8Array) {
    try {
      return new TextDecoder().decode(value);
    } catch {
      return Array.from(value).map((byte) => String.fromCharCode(byte)).join('');
    }
  }
  if (typeof value === 'object') {
    const stringifier = (value as { toString?: () => string }).toString;
    if (typeof stringifier === 'function' && stringifier !== Object.prototype.toString) {
      return stringifier.call(value);
    }
  }
  return String(value);
}

function statusClass(status?: number) {
  if (!status || status < 100) return 'unknown';
  return `${Math.floor(status / 100)}xx`;
}

function parseScannerJsonRecord(value?: string): Record<string, unknown> | undefined {
  if (!value) return undefined;
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as Record<string, unknown> : undefined;
  } catch {
    return undefined;
  }
}

function scannerLinkedPackageId(item: ScannerLinkedEvidencePackage, fallbackIndex: number, prefix: string) {
  return item.id ?? `${prefix}-${fallbackIndex + 1}`;
}

function scannerLinkedPackageKind(item: ScannerLinkedEvidencePackage, fallback: string) {
  return item.kind ?? fallback;
}

function scannerLinkedPackageReady(item: ScannerLinkedEvidencePackage) {
  const requirementValues = item.requirements ? Object.values(item.requirements) : [];
  return item.reportReady !== false
    && !/fail|failed|blocked|stale|mismatch/i.test(item.status ?? '')
    && requirementValues.every(Boolean);
}

function scannerLinkedPackageText(item: ScannerLinkedEvidencePackage) {
  return [
    item.id,
    item.kind,
    item.status,
    item.summary,
    item.content,
    item.requirements ? JSON.stringify(item.requirements) : '',
  ].filter(Boolean).join('\n');
}

function scannerOastExchangeEvidence(exchange: ScannerOastExchangeInput) {
  return {
    id: exchange.id,
    method: exchange.method,
    url: exchange.url,
    host: exchange.host,
    path: exchange.path,
    status: exchange.status,
    requestRaw: scannerRawValueToText(exchange.requestRaw),
    responseRaw: scannerRawValueToText(exchange.responseRaw),
  };
}

export function buildScannerActiveScanPlan(request: ScannerActiveScanEngineRequest): ScannerActiveScanPlan {
  const now = request.now ?? new Date().toISOString();
  const selected = selectedExchange(request);
  const checks = normalizedChecks(request);
  const replayCount = replayCandidates(request).length;
  const insertionPoints = insertionInputs(request);
  const targetUrl = selected?.url ?? request.activeScanSummary?.targetUrl ?? 'https://target.invalid/';
  const targetHostCandidate = selected?.host ?? hostFromUrl(targetUrl);
  const targetHost = targetHostCandidate ? targetHostCandidate : 'target.invalid';
  const targetPath = selected?.path ?? pathFromUrl(targetUrl);
  const firstPack = (request as unknown as { checkPacks?: Array<{ id?: string; name?: string }> }).checkPacks?.[0];
  const policy = (request as unknown as { activeScanPolicy?: { id?: string; name?: string; throttleMs?: number; maxRequests?: number } }).activeScanPolicy;
  const checkPackLabel = request.checkPackLabel ?? firstPack?.name ?? policy?.name ?? request.checkPackId ?? 'Custom active scan pack';
  const digestPreview = simpleDigest(`${targetUrl}|${checks.join(',')}|${request.throttleMs}|${request.maxRequests}`);
  const stamp = now.replace(/[:.]/g, '-');
  const content = JSON.stringify({
    kind: 'proxyforge-scanner-active-scan-plan',
    createdAt: now,
    reportReady: true,
    targetUrl,
    targetHost,
    targetPath,
    checkPack: {
      id: request.checkPackId ?? 'custom',
      label: checkPackLabel,
      checks: checks.map((check) => ({ id: check, label: checkLabels[check] })),
    },
    scopeAllowlist: request.scopeAllowlist ?? [],
    throttleMs: request.throttleMs ?? policy?.throttleMs ?? 300,
    maxRequests: request.maxRequests ?? policy?.maxRequests ?? checks.length,
    sessionProfileName: request.sessionProfile?.name,
    insertionPointCount: insertionPoints.length,
    insertionPoints: insertionPoints.slice(0, 12).map((point) => ({
      id: point.id,
      name: insertionPointName(point),
      location: point.location ?? point.type,
      parameter: point.parameter ?? point.name,
      route: point.route ?? `${insertionPointMethod(point, request)} ${pathFromUrl(insertionPointUrl(point, request))}`,
      notes: point.notes,
    })),
    replayCandidateCount: replayCount,
    schedule: [
      'scope preflight',
      'active insertion-point review',
      'authenticated-state comparison',
      'replay-derived checks',
      'CI/headless report handoff',
    ],
  }, null, 2);
  return {
    id: `scanner-active-plan-${digestPreview.slice(0, 12)}`,
    title: 'Scanner active scan plan',
    fileName: `proxyforge-scanner-active-scan-plan-${stamp}.json`,
    path: `scanner/proxyforge-scanner-active-scan-plan-${stamp}.json`,
    createdAt: now,
    checkPackId: request.checkPackId ?? firstPack?.id ?? policy?.id ?? 'custom',
    checkPackLabel,
    checkIds: checks,
    targetUrl,
    targetHost,
    targetPath,
    scopeAllowlist: request.scopeAllowlist ?? [],
    throttleMs: request.throttleMs ?? policy?.throttleMs ?? 300,
    maxRequests: request.maxRequests ?? policy?.maxRequests ?? checks.length,
    sessionProfileName: request.sessionProfile?.name,
    insertionPointCount: insertionPoints.length,
    replayCandidateCount: replayCount,
    reportReady: true,
    summary: `${checkPackLabel} stages ${checks.length} active scan check(s), ${insertionPoints.length} insertion point(s), ${replayCount} replay-derived candidate(s), and CI/headless report handoff for ${targetHost}${targetPath}.`,
    content,
  };
}

export function buildScannerInsertionPointReview(request: ScannerActiveScanEngineRequest): ScannerInsertionPointReview {
  const now = request.now ?? new Date().toISOString();
  const checks = normalizedChecks(request);
  const selected = selectedExchange(request);
  const scopeAllowlist = request.scopeAllowlist ?? [];
  const activePaths = new Set((request.activeScanSummary?.exchanges ?? []).map((exchange) => `${exchange.method.toUpperCase()} ${exchange.host}${exchange.path}`));
  const seen = new Set<string>();
  const crawlRows: ScannerInsertionPointReviewRow[] = insertionInputs(request).map((point, index) => {
    const url = insertionPointUrl(point, request);
    const method = insertionPointMethod(point, request);
    const host = hostFromUrl(url);
    const path = pathFromUrl(url);
    const name = insertionPointName(point);
    const key = `${point.type ?? point.location}:${name}:${method}:${host}:${path}`.toLowerCase();
    const duplicate = seen.has(key);
    seen.add(key);
    const covered = activePaths.has(`${method.toUpperCase()} ${host}${path}`) || index < (request.activeScanSummary?.totalRequests ?? 0);
    const status: ScannerInsertionPointReviewRow['status'] = duplicate
      ? 'duplicate'
      : !inScope(url, scopeAllowlist)
        ? 'skipped'
        : covered
          ? 'covered'
          : 'untested';
    return {
      id: point.id ?? `insertion-point-${simpleDigest(key).slice(0, 12)}`,
      label: `${method} ${path} ${name}`,
      type: point.type ?? (point.location === 'header' ? 'header' : point.location === 'cookie' ? 'cookie' : point.location === 'path' ? 'path' : point.location === 'form' ? 'form' : 'selected-request'),
      method,
      url,
      source: 'crawler',
      status,
      checks: checks.slice(index % Math.max(checks.length, 1), index % Math.max(checks.length, 1) + 1),
      reason: status === 'covered'
        ? 'Active scan or crawl audit touched this insertion point.'
        : status === 'skipped'
          ? 'Insertion point is outside the active scan scope allowlist.'
          : status === 'duplicate'
            ? 'Duplicate crawler insertion point merged for review.'
            : `Candidate remains queued for targeted active scan review at ${point.location ?? point.type ?? 'request'} ${point.parameter ?? point.name ?? 'parameter'}. ${point.notes ?? ''}`.trim(),
    };
  });
  const replayRows: ScannerInsertionPointReviewRow[] = replayCandidates(request).slice(0, 8).map((exchange, index) => {
    const key = `${exchange.method}:${exchange.host}:${exchange.path}:replay`.toLowerCase();
    const duplicate = seen.has(key);
    seen.add(key);
    return {
      id: `replay-point-${exchange.id}`,
      label: `${exchange.method} ${exchange.path} replay-derived`,
      type: exchange.id === selected?.id ? 'selected-request' : 'replay',
      method: exchange.method,
      url: exchange.url,
      source: exchange.id === selected?.id ? 'selected-request' : 'replay',
      status: duplicate ? 'duplicate' : inScope(exchange.url, scopeAllowlist) ? 'untested' : 'skipped',
      checks: recommendedChecksForExchange(exchange, checks).slice(0, 3),
      reason: 'Replay-derived request promoted into active insertion-point review.',
    };
  });
  const rows = [...crawlRows, ...replayRows].slice(0, 80);
  const counts = rows.reduce(
    (memo, row) => ({ ...memo, [row.status]: memo[row.status] + 1 }),
    { covered: 0, duplicate: 0, skipped: 0, untested: 0 },
  );
  const stamp = now.replace(/[:.]/g, '-');
  const digestPreview = simpleDigest(JSON.stringify(rows));
  const content = JSON.stringify({
    kind: 'proxyforge-scanner-insertion-point-review',
    createdAt: now,
    reportReady: true,
    checkPackId: request.checkPackId ?? 'custom',
    scopeAllowlist,
    counts,
    rows,
  }, null, 2);
  return {
    id: `scanner-insertion-review-${digestPreview.slice(0, 12)}`,
    title: 'Scanner insertion point review',
    fileName: `proxyforge-scanner-insertion-point-review-${stamp}.json`,
    path: `scanner/proxyforge-scanner-insertion-point-review-${stamp}.json`,
    createdAt: now,
    totalCount: rows.length,
    coveredCount: counts.covered,
    untestedCount: counts.untested,
    skippedCount: counts.skipped,
    duplicateCount: counts.duplicate,
    rows,
    reportReady: true,
    summary: `Scanner insertion-point review covers ${rows.length} candidate(s): ${counts.covered} covered, ${counts.untested} untested, ${counts.skipped} skipped, and ${counts.duplicate} duplicate.`,
    content,
  };
}

export function buildScannerAuthenticatedStateMatrix(request: ScannerActiveScanEngineRequest): ScannerAuthenticatedStateMatrix {
  const now = request.now ?? new Date().toISOString();
  const checks = normalizedChecks(request);
  const stateInputs = (request as unknown as { authenticatedStates?: Array<{ label?: string; role?: string; statusByRoute?: Record<string, number>; exchangeIds?: string[] }> }).authenticatedStates ?? [];
  const baselineProfile = request.sessionProfile ?? request.sessionProfiles?.[0];
  const alternateProfile = request.sessionProfiles?.find((profile) => profile.id !== baselineProfile?.id && /admin|support|staff|privileged/i.test(`${profile.name} ${profile.role}`))
    ?? request.sessionProfiles?.find((profile) => profile.id !== baselineProfile?.id)
    ?? baselineProfile;
  const baselineState = stateInputs[0];
  const alternateState = stateInputs.find((state) => state !== baselineState && /admin|support|alternate|privileged/i.test(`${state.label} ${state.role}`)) ?? stateInputs[1];
  const baselineName = baselineProfile?.name ?? baselineState?.label ?? 'Baseline session';
  const alternateName = alternateProfile?.name ?? alternateState?.label ?? 'Alternate session';
  const baselineRole = baselineProfile?.role ?? baselineState?.role ?? 'baseline';
  const alternateRole = alternateProfile?.role ?? alternateState?.role ?? 'alternate';
  const routes = new Map<string, HttpExchange[]>();
  for (const exchange of request.exchanges) {
    const key = routeKey(exchange);
    routes.set(key, [...(routes.get(key) ?? []), exchange]);
  }
  const rows: ScannerAuthenticatedStateMatrixRow[] = Array.from(routes.entries()).slice(0, 40).map(([route, routeExchanges]) => {
    const baseline = routeExchanges.find((exchange) => exchange.source === 'proxy')
      ?? routeExchanges.find((exchange) => !/admin|support|replay/i.test(`${exchange.notes} ${exchange.tags.join(' ')}`))
      ?? routeExchanges[0];
    const alternate = routeExchanges.find((exchange) => exchange.source === 'repeater' || /admin|support|replay|authz/i.test(`${exchange.notes} ${exchange.tags.join(' ')}`))
      ?? routeExchanges[1];
    const rawPath = baseline?.path ?? alternate?.path ?? route.replace(/^\S+\s+\S+?/, '');
    const path = rawPath ? rawPath : '/';
    const baselineStatus = baselineState?.statusByRoute?.[path] ?? baseline?.status;
    const alternateStatus = alternateState?.statusByRoute?.[path] ?? alternate?.status;
    const statusDrift = baselineStatus !== undefined && alternateStatus !== undefined && baselineStatus !== alternateStatus;
    const privilegeDrift = Boolean(alternate && /support_admin|admin|privileged|allowed|approved/i.test(`${alternate.responseRaw} ${alternate.notes}`));
    const delta: ScannerAuthenticatedStateMatrixRow['delta'] = !baseline
      ? 'missing-baseline'
      : !alternate
        ? 'missing-alternate'
        : privilegeDrift
          ? 'privilege-drift'
          : statusDrift
            ? 'status-drift'
            : 'same';
    const risk: Severity = delta === 'privilege-drift' ? 'high' : delta === 'status-drift' ? 'medium' : highestSeverity(routeExchanges, 'info');
    return {
      id: `auth-state-${simpleDigest(route).slice(0, 12)}`,
      route,
      baselineRole,
      alternateRole,
      baselineStatus,
      alternateStatus,
      baselineExchangeId: baseline?.id,
      alternateExchangeId: alternate?.id,
      delta,
      risk,
      checks: checks.includes('authz-diff') ? ['authz-diff', ...checks.filter((check) => check !== 'authz-diff').slice(0, 2)] : checks.slice(0, 3),
      summary: `${route} authenticated-state comparison is ${delta.replace('-', ' ')} between ${baselineName} and ${alternateName}; authorization boundary/authz review remains linked to active scan checks.`,
    };
  });
  const driftRows = rows.filter((row) => row.delta !== 'same');
  const stamp = now.replace(/[:.]/g, '-');
  const digestPreview = simpleDigest(JSON.stringify(rows));
  const content = JSON.stringify({
    kind: 'proxyforge-scanner-authenticated-state-matrix',
    createdAt: now,
    reportReady: true,
    baselineProfile: baselineName,
    alternateProfile: alternateName,
    rows,
    driftCount: driftRows.length,
  }, null, 2);
  return {
    id: `scanner-auth-state-${digestPreview.slice(0, 12)}`,
    title: 'Scanner authenticated-state comparison matrix',
    fileName: `proxyforge-scanner-authenticated-state-matrix-${stamp}.json`,
    path: `scanner/proxyforge-scanner-authenticated-state-matrix-${stamp}.json`,
    createdAt: now,
    baselineProfileName: baselineName,
    alternateProfileName: alternateName,
    rowCount: rows.length,
    driftCount: driftRows.length,
    highRiskCount: rows.filter((row) => severityRank[row.risk] >= severityRank.high).length,
    rows,
    reportReady: true,
    summary: `Authenticated-state comparison reviewed ${rows.length} route(s), ${driftRows.length} drift(s), and ${rows.filter((row) => severityRank[row.risk] >= severityRank.high).length} high-risk auth state candidate(s).`,
    content,
  };
}

export function buildScannerReplayCheckPackage(request: ScannerActiveScanEngineRequest): ScannerReplayCheckPackage {
  const now = request.now ?? new Date().toISOString();
  const checks = normalizedChecks(request);
  const candidates = replayCandidates(request).slice(0, 80);
  const generatedChecks = Array.from(new Set(candidates.flatMap((exchange) => recommendedChecksForExchange(exchange, checks))));
  const sourceSet = new Set(candidates.map((exchange) => exchange.source));
  const replaySource: ScannerReplayCheckPackage['replaySource'] = sourceSet.size === 1 && sourceSet.has('repeater')
    ? 'repeater'
    : sourceSet.size === 1 && sourceSet.has('scanner')
      ? 'scanner'
      : sourceSet.has('repeater') || sourceSet.has('scanner')
        ? 'mixed'
        : 'proxy-history';
  const authzCount = candidates.filter((exchange) => exchange.tags.includes('authz') || /authorization:|missing_permission|support_admin/i.test(`${exchange.requestRaw}\n${exchange.responseRaw}`)).length;
  const stamp = now.replace(/[:.]/g, '-');
  const digestPreview = simpleDigest(candidates.map((exchange) => exchange.id).join('|') + generatedChecks.join(','));
  const content = JSON.stringify({
    kind: 'proxyforge-scanner-replay-check-package',
    createdAt: now,
    reportReady: true,
    replaySource,
    checkPackId: request.checkPackId ?? 'custom',
    generatedChecks: generatedChecks.map((check) => ({ id: check, label: checkLabels[check] })),
    authorizationCandidateCount: authzCount,
    exchanges: candidates.map((exchange) => ({
      id: exchange.id,
      route: routeKey(exchange),
      source: exchange.source,
      status: exchange.status,
      tags: exchange.tags,
    })),
  }, null, 2);
  return {
    id: `scanner-replay-package-${digestPreview.slice(0, 12)}`,
    title: 'Scanner replay-derived check package',
    fileName: `proxyforge-scanner-replay-check-package-${stamp}.json`,
    path: `scanner/proxyforge-scanner-replay-check-package-${stamp}.json`,
    createdAt: now,
    replaySource,
    exchangeIds: candidates.map((exchange) => exchange.id),
    generatedChecks,
    replayDerivedCheckCount: generatedChecks.length,
    authorizationCandidateCount: authzCount,
    reportReady: true,
    summary: `Replay-derived Scanner package promotes ${candidates.length} exchange(s), ${generatedChecks.length} generated check(s), and ${authzCount} authorization candidate(s).`,
    content,
  };
}

export function buildScannerActiveScanEvidencePackage(request: ScannerActiveScanEngineRequest): ScannerActiveScanEvidencePackage {
  const now = request.now ?? new Date().toISOString();
  const plan = request.plan ?? buildScannerActiveScanPlan(request);
  const insertionPointReview = request.insertionPointReview ?? buildScannerInsertionPointReview(request);
  const authenticatedStateMatrix = request.authenticatedStateMatrix ?? buildScannerAuthenticatedStateMatrix(request);
  const replayCheckPackage = request.replayCheckPackage ?? buildScannerReplayCheckPackage(request);
  const findings = request.activeScanSummary?.findings ?? [];
  const suppressedFindings = request.activeScanSummary?.suppressedFindings ?? [];
  const exchangeIds = Array.from(new Set([
    ...(request.activeScanSummary?.exchanges ?? []).map((exchange) => exchange.id),
    ...replayCheckPackage.exchangeIds,
  ])).slice(0, 200);
  const exchangeById = new Map([
    ...request.exchanges,
    ...(request.activeScanSummary?.exchanges ?? []),
  ].map((exchange) => [exchange.id, exchange]));
  const rawExchangeSamples = exchangeIds
    .map((id) => exchangeById.get(id))
    .filter((exchange): exchange is HttpExchange => Boolean(exchange))
    .slice(0, 12)
    .map((exchange) => ({
      id: exchange.id,
      method: exchange.method,
      host: exchange.host,
      path: exchange.path,
      status: exchange.status,
      source: exchange.source,
      tags: exchange.tags,
      requestRaw: exchange.requestRaw,
      responseRaw: exchange.responseRaw,
    }));
  const operationalSecretSignals = Array.from(new Set(rawExchangeSamples.flatMap((sample) => (
    scannerOperationalSecretSignals(sample.requestRaw, sample.responseRaw)
  ))));
  const highestFindingSeverity = findings.reduce<Severity>((highest, finding) => (
    severityRank[finding.severity] > severityRank[highest] ? finding.severity : highest
  ), 'info');
  const findingStatusSummary = {
    total: findings.length,
    severityCounts: countValues(findings.map((finding) => finding.severity)),
    confidenceCounts: countValues(findings.map((finding) => finding.confidence)),
    suppressedFindingCount: suppressedFindings.length,
    highestSeverity: highestFindingSeverity,
    affectedExchangeIds: Array.from(new Set(findings.map((finding) => finding.evidenceExchangeId).filter((id): id is string => Boolean(id)))),
  };
  const primaryScope = plan.scopeAllowlist[0] ?? plan.targetHost;
  const ciCommand = [
    'proxyforge headless',
    `--target ${plan.targetUrl}`,
    `--scope ${primaryScope}`,
    `--checks ${plan.checkIds.join(',')}`,
    `--throttle-ms ${plan.throttleMs}`,
    `--max-requests ${plan.maxRequests}`,
    '--report json,bundle',
    '--sarif',
    '--junit',
    '--fail-on high',
  ].join(' ');
  const stamp = now.replace(/[:.]/g, '-');
  const reportAttachments = [
    {
      id: `${plan.id}-attachment`,
      kind: 'active-scan-plan' as const,
      artifactId: plan.id,
      fileName: plan.fileName,
      reportReady: plan.reportReady,
      redactionPhase: 'report-export-only' as const,
    },
    {
      id: `${insertionPointReview.id}-attachment`,
      kind: 'insertion-point-review' as const,
      artifactId: insertionPointReview.id,
      fileName: insertionPointReview.fileName,
      reportReady: insertionPointReview.reportReady,
      redactionPhase: 'report-export-only' as const,
    },
    {
      id: `${authenticatedStateMatrix.id}-attachment`,
      kind: 'authenticated-state-matrix' as const,
      artifactId: authenticatedStateMatrix.id,
      fileName: authenticatedStateMatrix.fileName,
      reportReady: authenticatedStateMatrix.reportReady,
      redactionPhase: 'report-export-only' as const,
    },
    {
      id: `${replayCheckPackage.id}-attachment`,
      kind: 'replay-check-package' as const,
      artifactId: replayCheckPackage.id,
      fileName: replayCheckPackage.fileName,
      reportReady: replayCheckPackage.reportReady,
      redactionPhase: 'report-export-only' as const,
    },
    ...(request.activeScanSummary ? [{
      id: `${request.activeScanSummary.id}-attachment`,
      kind: 'active-scan-summary' as const,
      artifactId: request.activeScanSummary.id,
      fileName: `proxyforge-scanner-active-scan-summary-${stamp}.json`,
      reportReady: true,
      redactionPhase: 'report-export-only' as const,
    }] : []),
  ];
  const requirements = {
    activeScanPlanLinked: Boolean(plan.id && plan.checkIds.length),
    insertionPointReviewLinked: insertionPointReview.totalCount > 0,
    authenticatedStateMatrixLinked: authenticatedStateMatrix.rowCount > 0,
    replayChecksLinked: replayCheckPackage.replayDerivedCheckCount > 0 && replayCheckPackage.exchangeIds.length > 0,
    ciHeadlessHandoffCovered: /--report\s+json,bundle/.test(ciCommand) && /--sarif/.test(ciCommand) && /--junit/.test(ciCommand),
    reportAttachmentsLinked: reportAttachments.length >= 4 && reportAttachments.every((attachment) => attachment.reportReady && attachment.redactionPhase === 'report-export-only'),
    issueConfidencePreserved: findings.length === 0 || findings.every((finding) => Boolean(finding.title && finding.severity && finding.confidence && finding.evidenceExchangeId)),
    rawExchangeSamplesPreserved: rawExchangeSamples.some((sample) => sample.requestRaw.trim() && sample.responseRaw.trim()),
    operationalSecretsPreserved: operationalSecretSignals.length > 0,
    reportPhaseOnlyRedaction: true,
  };
  const content = JSON.stringify({
    kind: 'proxyforge-scanner-active-scan-evidence-package',
    createdAt: now,
    reportReady: true,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    ciHeadlessHandoff: {
      command: ciCommand,
      reports: ['json', 'bundle', 'sarif', 'junit'],
      gate: 'fail-on high',
    },
    plan,
    insertionPointReview,
    authenticatedStateMatrix,
    replayCheckPackage,
    activeScanSummary: request.activeScanSummary ? {
      id: request.activeScanSummary.id,
      targetUrl: request.activeScanSummary.targetUrl,
      totalRequests: request.activeScanSummary.totalRequests,
      blocked: request.activeScanSummary.blocked,
      findingCount: request.activeScanSummary.findings.length,
      message: request.activeScanSummary.message,
    } : undefined,
    findingStatusSummary,
    rawExchangeSamples,
    operationalSecretSignals,
    reportAttachments,
    requirements,
    exchangeIds,
  }, null, 2);
  const digestPreview = simpleDigest(content);
  return {
    id: `scanner-active-evidence-${digestPreview.slice(0, 12)}`,
    kind: 'proxyforge-scanner-active-scan-evidence-package',
    title: 'Scanner Active Scan Evidence Package',
    fileName: `proxyforge-scanner-active-scan-evidence-${stamp}.json`,
    path: `reports/proxyforge-scanner-active-scan-evidence-${stamp}.json`,
    createdAt: now,
    planId: plan.id,
    insertionPointReviewId: insertionPointReview.id,
    authenticatedStateMatrixId: authenticatedStateMatrix.id,
    replayCheckPackageId: replayCheckPackage.id,
    activeScanSummaryId: request.activeScanSummary?.id,
    findingCount: request.activeScanSummary?.findings.length ?? 0,
    exchangeIds,
    ciCommand,
    rawExchangeSamples,
    operationalSecretSignals,
    findingStatusSummary,
    reportAttachments,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: true,
    summary: `Scanner Active Scan Evidence Package is report-ready and links ${plan.checkIds.length} check(s), ${insertionPointReview.totalCount} insertion point(s), ${authenticatedStateMatrix.driftCount} auth-state drift(s), ${replayCheckPackage.replayDerivedCheckCount} replay-derived check(s), ${operationalSecretSignals.length} operational secret signal(s), full-fidelity raw samples, and CI/headless report handoff.`,
    content,
  };
}

export function buildScannerLiveTargetProfilePackage(request: ScannerLiveTargetProfileRequest): ScannerLiveTargetProfilePackage {
  const generatedAt = request.generatedAt ?? new Date().toISOString();
  const stamp = generatedAt.replace(/[:.]/g, '-');
  const minTargetHosts = request.minTargetHosts ?? 2;
  const minRoutes = request.minRoutes ?? 3;
  const minRequests = request.minRequests ?? 10;
  const minCheckFamilies = request.minCheckFamilies ?? 8;
  const minTuningProfiles = request.minTuningProfiles ?? 1;
  const activeScanEvidencePackages = request.activeScanEvidencePackages ?? [];
  const activeScanSummaries = request.activeScanSummaries ?? [];
  const passiveDedupePackages = request.passiveDedupePackages ?? [];
  const insertionInventoryPackages = request.insertionInventoryPackages ?? [];
  const oastIssuePromotionPackages = request.oastIssuePromotionPackages ?? [];
  const anvilCompatibilityPackages = request.anvilCompatibilityPackages ?? [];
  const retestPackages = request.retestPackages ?? [];
  const calibrationPackages = request.calibrationPackages ?? [];
  const summaryExchanges = activeScanSummaries.flatMap((summary) => summary.exchanges ?? []);
  const rawSamples = activeScanEvidencePackages.flatMap((pkg) => pkg.rawExchangeSamples ?? []);
  const hosts = uniqueValues([
    ...activeScanSummaries.map((summary) => hostFromUrl(summary.targetUrl)).filter(Boolean),
    ...summaryExchanges.map((exchange) => exchange.host).filter(Boolean),
    ...rawSamples.map((sample) => sample.host).filter(Boolean),
  ]);
  const targetUrls = uniqueValues(activeScanSummaries.map((summary) => summary.targetUrl).filter(Boolean));
  const routes = uniqueValues([
    ...summaryExchanges.map((exchange) => `${exchange.method.toUpperCase()} ${exchange.host}${exchange.path}`),
    ...rawSamples.map((sample) => `${sample.method.toUpperCase()} ${sample.host}${sample.path}`),
  ]);
  const statusClasses = uniqueValues([
    ...summaryExchanges.map((exchange) => statusClass(exchange.status)),
    ...rawSamples.map((sample) => statusClass(sample.status)),
  ]).filter((value) => value !== 'unknown');
  const parsedEvidencePackages = activeScanEvidencePackages.map((pkg) => parseScannerJsonRecord(pkg.content));
  const contentPlanChecks = parsedEvidencePackages.flatMap((parsed) => {
    const plan = parsed?.plan;
    if (!plan || typeof plan !== 'object' || Array.isArray(plan)) return [];
    const checkIds = (plan as { checkIds?: unknown }).checkIds;
    return Array.isArray(checkIds) ? checkIds.filter((check): check is ActiveScanCheckId => typeof check === 'string') : [];
  });
  const checkCoverage = uniqueValues([
    ...contentPlanChecks,
    ...activeScanSummaries.flatMap((summary) => summary.findings.map((finding) => finding.checkId)),
  ]);
  const totalRequests = activeScanSummaries.reduce((total, summary) => total + (summary.totalRequests ?? 0), 0);
  const findingCount = activeScanSummaries.reduce((total, summary) => total + (summary.findings?.length ?? 0), 0);
  const suppressedFindingCount = activeScanSummaries.reduce((total, summary) => total + (summary.suppressedFindings?.length ?? 0), 0);
  const tuning = activeScanSummaries.map((summary) => summary.tuning).filter((item): item is NonNullable<ActiveScanSummary['tuning']> => Boolean(item));
  const tuningProfiles = uniqueValues(tuning.map((item) => item.profile));
  const falsePositiveControls = uniqueValues(tuning.flatMap((item) => item.falsePositiveControls));
  const linkedPackages: Array<{ item: ScannerLinkedEvidencePackage; fallbackKind: string; prefix: string }> = [
    ...passiveDedupePackages.map((item) => ({ item, fallbackKind: 'proxyforge-scanner-passive-dedupe-parity-package', prefix: 'scanner-passive-dedupe' })),
    ...insertionInventoryPackages.map((item) => ({ item, fallbackKind: 'proxyforge-insertion-point-inventory-package', prefix: 'scanner-insertion-inventory' })),
    ...activeScanEvidencePackages.map((item) => ({ item, fallbackKind: 'proxyforge-scanner-active-scan-evidence-package', prefix: 'scanner-active-evidence' })),
    ...oastIssuePromotionPackages.map((item) => ({ item, fallbackKind: 'proxyforge-scanner-oast-issue-promotion-package', prefix: 'scanner-oast-promotion' })),
    ...anvilCompatibilityPackages.map((item) => ({ item, fallbackKind: 'proxyforge-anvil-custom-check-parity-package', prefix: 'scanner-anvil' })),
    ...retestPackages.map((item) => ({ item, fallbackKind: 'proxyforge-scanner-retest-evidence-delta-package', prefix: 'scanner-retest' })),
    ...calibrationPackages.map((item) => ({ item, fallbackKind: 'proxyforge-agent-scanner-live-calibration-soak-package', prefix: 'scanner-calibration' })),
  ];
  const linkedPackageDigests = linkedPackages.map(({ item, fallbackKind, prefix }, index) => {
    const id = scannerLinkedPackageId(item, index, prefix);
    const kind = scannerLinkedPackageKind(item, fallbackKind);
    return {
      id,
      kind,
      digest: simpleDigest(scannerLinkedPackageText(item)),
      reportReady: scannerLinkedPackageReady(item),
    };
  });
  const linkedPackageKinds = uniqueValues(linkedPackageDigests.map((item) => item.kind));
  const stalePackageIds = linkedPackageDigests.filter((item) => !item.reportReady).map((item) => item.id);
  const rawMaterial = [
    ...passiveDedupePackages.map(scannerLinkedPackageText),
    ...insertionInventoryPackages.map(scannerLinkedPackageText),
    JSON.stringify(activeScanEvidencePackages),
    JSON.stringify(activeScanSummaries),
    JSON.stringify(oastIssuePromotionPackages),
    ...anvilCompatibilityPackages.map(scannerLinkedPackageText),
    ...retestPackages.map(scannerLinkedPackageText),
    ...calibrationPackages.map(scannerLinkedPackageText),
    ...(request.operationalSecretSamples ?? []),
  ].join('\n');
  const passiveText = passiveDedupePackages.map(scannerLinkedPackageText).join('\n');
  const insertionText = insertionInventoryPackages.map(scannerLinkedPackageText).join('\n');
  const anvilText = anvilCompatibilityPackages.map(scannerLinkedPackageText).join('\n');
  const retestText = retestPackages.map(scannerLinkedPackageText).join('\n');
  const calibrationText = calibrationPackages.map(scannerLinkedPackageText).join('\n');
  const packageRefreshProof = {
    refreshedAt: generatedAt,
    linkedPackageIds: linkedPackageDigests.map((item) => item.id),
    linkedPackageKinds,
    linkedPackageDigests,
    stalePackageIds,
    freshDigest: simpleDigest(linkedPackageDigests.map((item) => `${item.id}:${item.kind}:${item.digest}:${item.reportReady}`).join('|')),
  };
  const operationalSecretSamples = (request.operationalSecretSamples ?? []).map((sample) => sample.trim()).filter(Boolean);
  const requirements = {
    liveTargetDiversityCovered: hosts.length >= minTargetHosts
      && routes.length >= minRoutes
      && statusClasses.length >= 2,
    checkPackDepthCovered: checkCoverage.length >= minCheckFamilies
      && activeScanEvidencePackages.some((pkg) => pkg.requirements.activeScanPlanLinked && pkg.requirements.replayChecksLinked),
    longRunningTuningCovered: totalRequests >= minRequests
      && tuningProfiles.length >= minTuningProfiles
      && /suppress|confidence|dedupe|calibration|false-positive/i.test(`${falsePositiveControls.join(' ')}\n${calibrationText}`),
    passiveDedupeCovered: passiveDedupePackages.length > 0
      && /proxyforge-scanner-passive-dedupe-parity-package|passiveChecksCovered|routeVariantDedupeCovered|confidenceSummaryCovered|falsePositiveTuningCovered/i.test(passiveText),
    insertionInventoryCovered: insertionInventoryPackages.length > 0
      && /proxyforge-insertion-point-inventory-package|queryParametersCovered|headerParametersCovered|graphqlParametersCovered|scannerReadyCorpus/i.test(insertionText),
    anvilCompatibilityCovered: anvilCompatibilityPackages.length > 0
      && /proxyforge-anvil-custom-check-parity-package|plainTextDefinitionPreserved|positiveNegativeFixturesCovered|headlessCustomOnlyCovered|signedPackageReviewCovered/i.test(anvilText),
    oastPromotionCovered: oastIssuePromotionPackages.some((pkg) => pkg.reportReady && pkg.kind === 'proxyforge-scanner-oast-issue-promotion-package'),
    retestEvidenceCovered: retestPackages.length > 0
      && /proxyforge-scanner-retest-evidence-delta-package|fixed|regressed|still-vulnerable|outcome/i.test(retestText),
    reportAttachmentScaleCovered: activeScanEvidencePackages.some((pkg) => pkg.reportAttachments.length >= 5 && pkg.reportAttachments.every((attachment) => attachment.reportReady)),
    packageRefreshCovered: linkedPackageKinds.includes('proxyforge-scanner-passive-dedupe-parity-package')
      && linkedPackageKinds.includes('proxyforge-insertion-point-inventory-package')
      && linkedPackageKinds.includes('proxyforge-scanner-active-scan-evidence-package')
      && linkedPackageKinds.includes('proxyforge-scanner-oast-issue-promotion-package')
      && linkedPackageKinds.includes('proxyforge-anvil-custom-check-parity-package')
      && linkedPackageKinds.includes('proxyforge-scanner-retest-evidence-delta-package')
      && stalePackageIds.length === 0
      && linkedPackageDigests.length >= 6,
    rawExecutorMaterialPreserved: /HTTP\/[12]|Authorization:|Cookie:|X-API-Key:|rawRequest|rawResponse|Bearer/i.test(rawMaterial),
    operationalSecretsPreserved: operationalSecretSamples.length > 0
      && operationalSecretSamples.every((sample) => rawMaterial.includes(sample)),
    reportPhaseOnlyRedaction: /redact-only-during-report-export|report-export-only/i.test(rawMaterial),
  };
  const digestPreview = simpleDigest(JSON.stringify({
    generatedAt,
    targetUrls,
    hosts,
    routes,
    checkCoverage,
    packageRefreshProof,
    requirements,
  }));
  const content = JSON.stringify({
    kind: 'proxyforge-scanner-live-target-profile-package',
    generatedAt,
    targetUrls,
    targetHosts: hosts,
    routes,
    statusClasses,
    totalRequests,
    findingCount,
    suppressedFindingCount,
    checkCoverage,
    tuningProfiles,
    falsePositiveControls,
    packageRefreshProof,
    requirements,
    operationalSecretSamples,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    digestPreview,
  }, null, 2);

  return {
    id: `scanner-live-target-profile-${digestPreview.slice(0, 12)}`,
    kind: 'proxyforge-scanner-live-target-profile-package',
    title: 'Scanner live-target production profile',
    fileName: `proxyforge-scanner-live-target-profile-${stamp}.json`,
    path: `scanner/proxyforge-scanner-live-target-profile-${stamp}.json`,
    generatedAt,
    targetUrlCount: targetUrls.length,
    targetHostCount: hosts.length,
    routeCount: routes.length,
    statusClasses,
    totalRequests,
    findingCount,
    suppressedFindingCount,
    checkCoverage,
    tuningProfiles,
    falsePositiveControls,
    packageRefreshProof,
    requirements,
    operationalSecretSamples,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
    summary: `Scanner live-target profile links ${hosts.length} host(s), ${routes.length} route(s), ${checkCoverage.length} check family/families, ${totalRequests} request(s), ${linkedPackageDigests.length} refreshed package digest(s), passive dedupe, insertion inventory, Anvil/OAST/retest evidence, and report-export-only redaction.`,
    content,
  };
}

export function buildScannerCiReportHandoff(request: ScannerActiveScanEngineRequest): ScannerActiveScanEvidencePackage {
  return buildScannerActiveScanEvidencePackage(request);
}

export function buildScannerActiveScanIssuePromotion(request: ScannerActiveScanEngineRequest): Issue {
  const evidence = buildScannerActiveScanEvidencePackage(request);
  const plan = request.plan ?? buildScannerActiveScanPlan(request);
  const matrix = request.authenticatedStateMatrix ?? buildScannerAuthenticatedStateMatrix(request);
  const highestRisk = highestSeverity(matrix.rows, matrix.highRiskCount ? 'high' : 'medium');
  return {
    id: `scanner-active-promotion-${simpleDigest(evidence.id).slice(0, 12)}`,
    title: 'Scanner active scan evidence ready for triage',
    severity: highestRisk,
    host: plan.targetHost,
    path: plan.targetPath,
    confidence: evidence.findingCount > 0 || matrix.driftCount > 0 ? 'firm' : 'tentative',
    status: 'triaged',
    detail: `${evidence.summary} Report-ready active scan evidence includes check-pack planning, insertion-point coverage, authenticated-state comparison, replay-derived checks, and CI/headless handoff.`,
    remediation: 'Review active scanner results, confirm affected insertion points, rerun authenticated-state profiles after remediation, and keep CI/headless checks enabled for regression coverage.',
    triageNote: `Promoted from ${evidence.fileName}. CI command: ${evidence.ciCommand}`,
    lastTriagedAt: request.now ?? new Date().toISOString(),
  };
}

export function buildScannerOastIssuePromotionPackage(request: ScannerOastIssuePromotionRequest): ScannerOastIssuePromotionPackage {
  const createdAt = request.generatedAt ?? new Date().toISOString();
  const sourceEvidence = request.sourceExchange ? scannerOastExchangeEvidence(request.sourceExchange) : undefined;
  const scannerEvidence = scannerOastExchangeEvidence(request.scannerExchange);
  const interactionRaw = scannerRawValueToText(request.interaction.raw);
  const token = request.payload.token ?? request.interaction.token ?? '';
  const payloadIdentifier = request.payload.id ?? (token || request.payload.endpoint || 'callback');
  const payloadDisplay = request.payload.id ?? (token || 'unknown');
  const targetUrl = scannerEvidence.url ?? request.activeScanSummary?.targetUrl ?? request.payload.endpoint ?? 'https://target.invalid/';
  const host = request.finding?.host ?? scannerEvidence.host ?? hostFromUrl(targetUrl) ?? request.payload.sourceHost ?? 'target.invalid';
  const targetPath = request.finding?.path ?? scannerEvidence.path ?? pathFromUrl(targetUrl) ?? request.payload.sourcePath ?? '/';
  const checkId = request.finding?.checkId ?? 'oast-ssrf';
  const findingTitle = request.finding?.title ?? checkLabels[checkId] ?? 'OAST callback was triggered by Scanner';
  const severity = request.finding?.severity ?? request.interaction.severity ?? 'high';
  const confidence = request.finding?.confidence ?? (interactionRaw && token && interactionRaw.includes(token) ? 'certain' : 'firm');
  const dedupeKey = request.finding?.dedupeKey
    ?? `${checkId}:${host}:${targetPath}:${payloadIdentifier}`;
  const issue: Issue = {
    id: `issue-scanner-oast-${simpleDigest(`${dedupeKey}|${request.interaction.id ?? interactionRaw}`).slice(0, 12)}`,
    title: findingTitle,
    severity,
    host,
    path: targetPath,
    confidence,
    status: 'triaged',
    detail: [
      request.finding?.detail ?? 'Scanner observed an out-of-band callback from an injected OAST payload.',
      `Payload ${payloadDisplay} was sent in scanner exchange ${scannerEvidence.id ?? 'unknown'} and observed in callback interaction ${request.interaction.id ?? 'unknown'}.`,
      'Full raw scanner request, scanner response, callback interaction, and linked source request are preserved for executor replay.',
    ].join(' '),
    remediation: request.finding?.remediation ?? 'Validate the server-side fetch/callback sink, restrict outbound destinations, block user-controlled callback URLs, and retest with a fresh OAST payload.',
    triageNote: `Promoted from Scanner OAST evidence package; redaction is deferred until report export. Dedupe: ${dedupeKey}.`,
    lastTriagedAt: createdAt,
  };
  const operationalSecretSignals = Array.from(new Set([
    ...scannerOperationalSecretSignals(scannerEvidence.requestRaw, scannerEvidence.responseRaw),
    ...scannerOperationalSecretSignals(sourceEvidence?.requestRaw ?? '', sourceEvidence?.responseRaw ?? ''),
    ...scannerOperationalSecretSignals(interactionRaw),
  ]));
  const reportAttachments = [
    ...(sourceEvidence?.id ? [{
      id: `attachment-${sourceEvidence.id}`,
      kind: 'source-exchange' as const,
      artifactId: sourceEvidence.id,
      reportReady: true,
      redactionPhase: 'report-export-only' as const,
    }] : []),
    {
      id: `attachment-${scannerEvidence.id ?? issue.id}-scanner`,
      kind: 'scanner-exchange' as const,
      artifactId: scannerEvidence.id ?? issue.id,
      reportReady: true,
      redactionPhase: 'report-export-only' as const,
    },
    {
      id: `attachment-${payloadIdentifier}-payload`,
      kind: 'callback-payload' as const,
      artifactId: payloadIdentifier,
      reportReady: true,
      redactionPhase: 'report-export-only' as const,
    },
    {
      id: `attachment-${request.interaction.id ?? issue.id}-interaction`,
      kind: 'callback-interaction' as const,
      artifactId: request.interaction.id ?? issue.id,
      reportReady: true,
      redactionPhase: 'report-export-only' as const,
    },
    {
      id: `attachment-${issue.id}`,
      kind: 'issue-draft' as const,
      artifactId: issue.id,
      reportReady: true,
      redactionPhase: 'report-export-only' as const,
    },
  ];
  const reproductionSteps = [
    `Start or select callback payload ${payloadDisplay} at ${request.payload.endpoint ?? 'the configured OAST endpoint'}.`,
    `Replay scanner exchange ${scannerEvidence.id ?? 'unknown'} against ${targetUrl} with the preserved raw Authorization, Cookie, API-key, body, and OAST token material.`,
    `Poll callback/OAST interactions and confirm ${request.interaction.id ?? 'the observed interaction'} contains ${token || 'the payload token'}.`,
    `Promote ${issue.id} only after the callback can be correlated to the source/scanner exchange and the affected endpoint remains in scope.`,
  ];
  const retestCommands = [
    `proxyforge-agent scanner-run --project <project> --request-id ${scannerEvidence.id ?? '<scanner-exchange-id>'} --checks oast-ssrf --scope ${request.scopeAllowlist?.[0] ?? host} --execute --json`,
    `proxyforge-agent callback-poll --workspace <callbacks.json> --json`,
    `proxyforge-agent scanner-oast-promote --project <project> --payload-id ${request.payload.id ?? '<payload-id>'} --interaction-id ${request.interaction.id ?? '<interaction-id>'} --json`,
  ];
  const requirements = {
    sourceExchangeLinked: Boolean(sourceEvidence?.id || request.payload.sourceExchangeId),
    scannerExchangeLinked: Boolean(scannerEvidence.id || scannerEvidence.requestRaw),
    callbackPayloadLinked: Boolean(request.payload.id || token || request.payload.endpoint),
    callbackInteractionLinked: Boolean(request.interaction.id || interactionRaw),
    activeFindingLinked: Boolean(request.finding?.id || request.finding?.title),
    oastTokenObserved: Boolean(token && [scannerEvidence.requestRaw, scannerEvidence.responseRaw, interactionRaw].some((value) => value.includes(token))),
    rawScannerRequestPreserved: scannerEvidence.requestRaw.trim().length > 0,
    rawScannerResponsePreserved: scannerEvidence.responseRaw.trim().length > 0,
    rawCallbackInteractionPreserved: interactionRaw.trim().length > 0,
    issueDraftReady: Boolean(issue.id && issue.title && issue.host && issue.path && issue.detail && issue.remediation),
    dedupeKeyStable: Boolean(dedupeKey && dedupeKey.includes(checkId) && dedupeKey.includes(host)),
    reportAttachmentsLinked: reportAttachments.length >= 4 && reportAttachments.every((attachment) => attachment.reportReady && attachment.redactionPhase === 'report-export-only'),
    operationalSecretsPreserved: operationalSecretSignals.length > 0 || Boolean(token && [scannerEvidence.requestRaw, interactionRaw].some((value) => value.includes(token))),
    reportPhaseOnlyRedaction: true,
  };
  const body = {
    kind: 'proxyforge-scanner-oast-issue-promotion-package' as const,
    createdAt,
    projectName: request.projectName ?? 'ProxyForge Scanner OAST Project',
    issue,
    finding: request.finding,
    activeScanSummary: request.activeScanSummary,
    sourceExchangeId: sourceEvidence?.id ?? request.payload.sourceExchangeId,
    scannerExchangeId: scannerEvidence.id ?? issue.id,
    callbackPayloadId: payloadIdentifier,
    callbackInteractionId: request.interaction.id ?? issue.id,
    dedupeKey,
    evidence: {
      sourceExchange: sourceEvidence ? {
        id: sourceEvidence.id,
        method: sourceEvidence.method,
        url: sourceEvidence.url,
        host: sourceEvidence.host,
        path: sourceEvidence.path,
        requestRaw: sourceEvidence.requestRaw,
        responseRaw: sourceEvidence.responseRaw,
      } : undefined,
      scannerExchange: scannerEvidence,
      callbackPayload: {
        id: request.payload.id,
        token: request.payload.token,
        protocol: request.payload.protocol,
        endpoint: request.payload.endpoint,
        sourceExchangeId: request.payload.sourceExchangeId,
        sourceHost: request.payload.sourceHost,
        sourcePath: request.payload.sourcePath,
        status: request.payload.status,
        notes: request.payload.notes,
      },
      callbackInteraction: {
        id: request.interaction.id,
        payloadId: request.interaction.payloadId,
        protocol: request.interaction.protocol,
        observedAt: request.interaction.observedAt,
        sourceIp: request.interaction.sourceIp,
        sourceHost: request.interaction.sourceHost,
        requestLine: request.interaction.requestLine,
        userAgent: request.interaction.userAgent,
        raw: interactionRaw,
        severity: request.interaction.severity,
        tags: request.interaction.tags,
      },
    },
    reproductionSteps,
    retestCommands,
    reportAttachments,
    operationalSecretSignals,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved' as const,
    reportRedactionBoundary: 'redact-only-during-report-export' as const,
    reportReady: Object.values(requirements).every(Boolean),
  };
  const content = JSON.stringify(body, null, 2);
  const stamp = createdAt.replace(/[:.]/g, '-');
  return {
    id: `scanner-oast-promotion-${simpleDigest(content).slice(0, 12)}`,
    title: 'Scanner OAST issue promotion package',
    fileName: `proxyforge-scanner-oast-issue-promotion-${stamp}.json`,
    path: `scanner/proxyforge-scanner-oast-issue-promotion-${stamp}.json`,
    summary: `Scanner OAST issue promotion linked issue ${issue.id}, scanner exchange ${body.scannerExchangeId}, payload ${body.callbackPayloadId}, interaction ${body.callbackInteractionId}, ${operationalSecretSignals.length} operational secret signal(s), and report-export-only redaction.`,
    content,
    ...body,
  };
}
