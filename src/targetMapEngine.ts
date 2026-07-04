import type {
  CrawlInsertionPoint,
  CrawlRoute,
  CrawlRouteSource,
  CrawlSummary,
  Issue,
  Severity,
  TargetAccessControlDrift,
  TargetAccessControlExpectation,
  TargetAccessControlObservation,
  TargetAccessControlReviewLane,
  TargetAccessControlRouteDecision,
  TargetContentDiscoveryCandidate,
  TargetContentDiscoveryHandoff,
  TargetPackageRefreshProof,
  TargetParameterInsight,
  TargetRouteFindingOverlay,
  TargetSiteMapAnalysisPackage,
  TargetSiteMapComparisonDelta,
  TargetSiteMapComparisonPackage,
  TargetSiteMapEvidenceAttachment,
  TargetSiteMapSourceFilter,
  TargetSiteMapStatusFilter,
  TargetTechnologyInsight,
} from './types';

export interface TargetSiteMapEngineRequest {
  crawl?: Partial<CrawlSummary> | null;
  routes?: CrawlRoute[];
  insertionPoints?: CrawlInsertionPoint[];
  issues?: Issue[];
  scopeAllowlist?: string[];
  filters?: {
    url?: string;
    source?: TargetSiteMapSourceFilter | string;
    status?: TargetSiteMapStatusFilter | string;
    mime?: string;
  };
  baseline?: {
    name?: string;
    routeIds?: string[];
    routes?: CrawlRoute[];
    capturedAt?: string;
  };
  candidate?: {
    name?: string;
    routeIds?: string[];
    routes?: CrawlRoute[];
    capturedAt?: string;
  };
  accessControlProfiles?: string[];
  accessControlRoleMaps?: Array<{
    role: string;
    name?: string;
    routeIds?: string[];
    visibleRouteIds?: string[];
    deniedRouteIds?: string[];
    hiddenRouteIds?: string[];
    statusByRoute?: Record<string, number>;
    exchangeIds?: string[];
    capturedAt?: string;
    expectedVisiblePatterns?: string[];
    expectedDeniedPatterns?: string[];
  }>;
  throttleMs?: number;
  now?: string;
}

export interface TargetSiteMapViewModel {
  title: string;
  summary: string;
  routeCount: number;
  hostCount: number;
  filteredRouteCount: number;
  filters: Required<NonNullable<TargetSiteMapEngineRequest['filters']>>;
  hosts: Array<{ host: string; routeCount: number; issueCount: number; routes: CrawlRoute[] }>;
  crawlPath: Array<{ id: string; label: string; route: string; parent: string; source: CrawlRouteSource; depth: number }>;
}

export interface TargetAuthenticatedSessionEvidence {
  profileIds: string[];
  refreshedCookieNames?: string[];
  reusedExchangeIds?: string[];
  scannerProfileIds?: string[];
  crawlerProfileIds?: string[];
  notes?: string[];
}

export interface TargetParityEvidenceRequest extends TargetSiteMapEngineRequest {
  viewModel?: TargetSiteMapViewModel;
  analysisPackage?: TargetSiteMapAnalysisPackage;
  comparisonPackage?: TargetSiteMapComparisonPackage;
  evidenceAttachment?: TargetSiteMapEvidenceAttachment;
  authenticatedSessionEvidence?: TargetAuthenticatedSessionEvidence;
  operationalSecretSamples?: string[];
}

export interface TargetParityEvidencePackage {
  id: string;
  kind: 'proxyforge-target-parity-evidence-package';
  title: string;
  fileName: string;
  path: string;
  createdAt: string;
  routeCount: number;
  hostCount: number;
  crawlPathCount: number;
  insertionPointCount: number;
  technologyCount: number;
  parameterCount: number;
  artifactIds: {
    analysisPackageId?: string;
    comparisonPackageId?: string;
    evidenceAttachmentId?: string;
    contentDiscoveryHandoffId?: string;
  };
  requirements: {
    siteMapUrlTreeCovered: boolean;
    crawlPathViewCovered: boolean;
    scopedCrawlerCovered: boolean;
    authenticatedSessionReuseCovered: boolean;
    technologyInventoryCovered: boolean;
    parameterInsertionInventoryCovered: boolean;
    contentDiscoveryHandoffCovered: boolean;
    accessControlReviewCovered: boolean;
    siteMapComparisonCovered: boolean;
    reportsHandoffCovered: boolean;
    packageRefreshCovered: boolean;
    rawExecutorMaterialPreserved: boolean;
    operationalSecretsPreserved: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  reportReady: boolean;
  digestPreview: string;
  packageRefreshProof: TargetPackageRefreshProof;
  summary: string;
  content: string;
}

function routeKey(route: Pick<CrawlRoute, 'method' | 'host' | 'path'>) {
  return `${route.method.toUpperCase()} ${route.host}${route.path}`;
}

function routeUrl(route: Pick<CrawlRoute, 'url' | 'host' | 'path'>) {
  return route.url || `https://${route.host}${route.path}`;
}

function normalizeRoutes(request: TargetSiteMapEngineRequest): CrawlRoute[] {
  const routes = request.routes ?? request.crawl?.routes ?? [];
  const byKey = new Map<string, CrawlRoute>();
  for (const route of routes) byKey.set(routeKey(route).toLowerCase(), route);
  return Array.from(byKey.values());
}

function normalizeInsertionPoints(request: TargetSiteMapEngineRequest): CrawlInsertionPoint[] {
  return request.insertionPoints ?? request.crawl?.insertionPoints ?? [];
}

function normalizeFilters(filters?: TargetSiteMapEngineRequest['filters']): Required<NonNullable<TargetSiteMapEngineRequest['filters']>> {
  return {
    url: filters?.url?.trim() ?? '',
    source: filters?.source?.trim() || 'all',
    status: filters?.status?.trim() || 'all',
    mime: filters?.mime?.trim() ?? '',
  };
}

function routeMatchesStatusFilter(route: CrawlRoute, filter: string, insertionPointCount: number) {
  if (!filter || filter === 'all') return true;
  if (filter === 'with-params') return insertionPointCount > 0;
  if (filter === 'errors') return route.status >= 400 || route.status === 0;
  if (/^[1-5]xx$/.test(filter)) return Math.floor(route.status / 100) === Number(filter[0]);
  if (/^\d{3}$/.test(filter)) return route.status === Number(filter);
  return true;
}

function filterRoutes(routes: CrawlRoute[], insertionPoints: CrawlInsertionPoint[], filters?: TargetSiteMapEngineRequest['filters']) {
  const normalized = normalizeFilters(filters);
  const insertionCountByRoute = insertionPoints.reduce((counts, point) => {
    counts.set(point.routeId, (counts.get(point.routeId) ?? 0) + 1);
    return counts;
  }, new Map<string, number>());
  const urlNeedle = normalized.url.toLowerCase();
  const mimeNeedle = normalized.mime.toLowerCase();

  return routes.filter((route) => {
    if (urlNeedle && ![route.url, route.host, route.path, route.title].some((value) => value.toLowerCase().includes(urlNeedle))) return false;
    if (normalized.source !== 'all' && route.source !== normalized.source) return false;
    if (mimeNeedle && !route.mime.toLowerCase().includes(mimeNeedle)) return false;
    return routeMatchesStatusFilter(route, normalized.status, insertionCountByRoute.get(route.id) ?? route.insertionPoints.length);
  });
}

function safePathFromUrl(value: string) {
  try {
    const url = new URL(value);
    return `${url.pathname}${url.search}`;
  } catch {
    return value;
  }
}

function hostFromUrl(value: string) {
  try {
    return new URL(value).hostname;
  } catch {
    return value;
  }
}

function hostMatchesScope(host: string, scope: string) {
  const normalizedHost = host.toLowerCase().replace(/:\d+$/, '');
  const normalizedScope = scope.toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
  if (!normalizedHost || !normalizedScope) return false;
  if (normalizedScope.startsWith('*.')) {
    const suffix = normalizedScope.slice(1);
    return normalizedHost.endsWith(suffix);
  }
  return normalizedHost === normalizedScope || normalizedHost.endsWith(`.${normalizedScope}`);
}

function severityForRoute(route: CrawlRoute): Severity {
  if (route.path.includes('/admin') || route.method !== 'GET') return 'high';
  if (route.status >= 500) return 'high';
  if (route.status >= 400 || route.status === 0) return 'medium';
  if (route.path.includes('/api/') || route.path.includes('/graphql')) return 'medium';
  return 'info';
}

function severityRank(severity: Severity) {
  return { info: 0, low: 1, medium: 2, high: 3, critical: 4 }[severity] ?? 0;
}

function addTechnology(insights: Map<string, TargetTechnologyInsight>, insight: TargetTechnologyInsight) {
  const existing = insights.get(insight.id);
  if (!existing) {
    insights.set(insight.id, insight);
    return;
  }
  insights.set(insight.id, {
    ...existing,
    routeCount: Math.max(existing.routeCount, insight.routeCount),
    evidence: Array.from(new Set([existing.evidence, insight.evidence])).join('; '),
  });
}

function simpleDigest(value: string) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `${hash.toString(16).padStart(8, '0')}${value.length.toString(16).padStart(8, '0')}`;
}

function uniqueStrings(values: string[]) {
  return Array.from(new Set(values.filter(Boolean)));
}

interface TargetLinkedPackageInput {
  id?: string;
  kind: string;
  content?: string;
  summary?: string;
  reportReady?: boolean;
}

function buildTargetPackageRefreshProof(
  refreshedAt: string,
  linkedPackages: TargetLinkedPackageInput[],
  rawMaterial: string,
  counts: Partial<Pick<TargetPackageRefreshProof, 'sourceRouteCount' | 'sourceInsertionPointCount' | 'sourceRoleCount' | 'sourceCandidateCount'>> = {},
): TargetPackageRefreshProof {
  const linkedPackageDigests = linkedPackages.map((item, index) => {
    const id = item.id ?? `${item.kind}-${index + 1}`;
    const content = [item.content ?? '', item.summary ?? ''].join('\n');
    return {
      id,
      kind: item.kind,
      digest: simpleDigest(content),
      reportReady: item.reportReady !== false,
    };
  });
  return {
    refreshedAt,
    linkedPackageKinds: uniqueStrings(linkedPackageDigests.map((item) => item.kind)),
    linkedPackageDigests,
    stalePackageIds: linkedPackageDigests.filter((item) => !item.reportReady).map((item) => item.id),
    freshDigest: simpleDigest(linkedPackageDigests.map((item) => `${item.id}:${item.kind}:${item.digest}:${item.reportReady}`).join('|')),
    rawMaterialDigestPreview: simpleDigest(rawMaterial),
    ...counts,
  };
}

function routeSubset(routes: CrawlRoute[], selector?: { routeIds?: string[]; routes?: CrawlRoute[] }) {
  if (selector?.routes?.length) return selector.routes;
  if (selector?.routeIds?.length) {
    const wanted = new Set(selector.routeIds);
    return routes.filter((route) => wanted.has(route.id));
  }
  return routes;
}

function routeParameterNames(route: CrawlRoute, insertionPoints: CrawlInsertionPoint[] = []) {
  const names = new Set<string>();
  for (const point of insertionPoints.filter((point) => point.routeId === route.id)) names.add(`${point.type}:${point.name}`);
  for (const point of route.insertionPoints ?? []) names.add(String(point));
  try {
    const url = new URL(routeUrl(route));
    for (const name of url.searchParams.keys()) names.add(`query:${name}`);
  } catch {
    // Partial imported route without a parseable URL; route insertion-point ids still count.
  }
  return Array.from(names).sort();
}

function routeAuthzSensitive(route: CrawlRoute) {
  return /admin|support|finance|refund|graphql|oauth|sso|session|account|export|audit|impersonate|\/api\//i.test(`${route.method} ${route.path} ${route.title}`)
    || route.method !== 'GET'
    || route.status === 401
    || route.status === 403;
}

function comparisonDeltaSeverity(route: CrawlRoute, changeTypes: string[]): Severity {
  if (changeTypes.includes('authz')) return 'high';
  if (changeTypes.includes('status') && (route.status === 401 || route.status === 403 || route.status >= 500)) return 'high';
  if (changeTypes.includes('parameter') || changeTypes.includes('method')) return 'medium';
  return severityForRoute(route);
}

export function buildTargetSiteMapViewModel(request: TargetSiteMapEngineRequest): TargetSiteMapViewModel {
  const routes = normalizeRoutes(request);
  const insertionPoints = normalizeInsertionPoints(request);
  const filteredRoutes = filterRoutes(routes, insertionPoints, request.filters);
  const issues = request.issues ?? [];
  const hosts = Array.from(filteredRoutes.reduce((byHost, route) => {
    const current = byHost.get(route.host) ?? [];
    current.push(route);
    byHost.set(route.host, current);
    return byHost;
  }, new Map<string, CrawlRoute[]>())).map(([host, hostRoutes]) => ({
    host,
    routeCount: hostRoutes.length,
    issueCount: issues.filter((issue) => issue.host === host).length,
    routes: hostRoutes,
  }));

  return {
    title: 'Target site map URL view and Crawl-path map',
    summary: `URL view grouped by ${hosts.length} host(s); Crawl-path view tracks ${filteredRoutes.length} route(s), crawler source, depth, parameters, and filter state.`,
    routeCount: routes.length,
    hostCount: hosts.length,
    filteredRouteCount: filteredRoutes.length,
    filters: normalizeFilters(request.filters),
    hosts,
    crawlPath: filteredRoutes
      .slice()
      .sort((left, right) => left.depth - right.depth || routeKey(left).localeCompare(routeKey(right)))
      .map((route) => ({
        id: route.id,
        label: `${route.depth === 0 ? 'crawler seed' : `${route.source} discovery`} -> ${route.method} ${route.path}`,
        route: routeKey(route),
        parent: route.parentUrl ? safePathFromUrl(route.parentUrl) : 'crawler root',
        source: route.source,
        depth: route.depth,
      })),
  };
}

export function buildTargetTechnologyInventory(request: TargetSiteMapEngineRequest): TargetTechnologyInsight[] {
  const routes = normalizeRoutes(request);
  const insights = new Map<string, TargetTechnologyInsight>();
  const jsRoutes = routes.filter((route) => /javascript|ecmascript/i.test(route.mime) || /\.m?js(?:\?|$)/i.test(route.path));
  const jsonRoutes = routes.filter((route) => /json/i.test(route.mime) || /\/api\//i.test(route.path));
  const graphqlRoutes = routes.filter((route) => /graphql/i.test(route.path) || /graphql/i.test(route.title));
  const htmlRoutes = routes.filter((route) => /html/i.test(route.mime));
  const assetRoutes = routes.filter((route) => /\/assets\/|cdn\.|favicon|\.css|\.png|\.svg|\.ico/i.test(`${route.host}${route.path}`));

  if (routes.length) {
    addTechnology(insights, {
      id: 'http2-transport',
      label: 'HTTP/2 transport',
      category: 'transport',
      confidence: 'firm',
      routeCount: routes.length,
      evidence: `${routes.length} route(s) keep report-ready HTTP/2 request metadata for replay and scanner handoff.`,
    });
  }
  if (htmlRoutes.length) {
    addTechnology(insights, {
      id: 'html-application',
      label: 'HTML application surface',
      category: 'client',
      confidence: 'firm',
      routeCount: htmlRoutes.length,
      evidence: `${htmlRoutes.length} text/html route(s) expose browser-reviewable pages.`,
    });
  }
  if (jsRoutes.length) {
    addTechnology(insights, {
      id: 'javascript-react-bundles',
      label: 'JavaScript / React bundle',
      category: 'client',
      confidence: 'firm',
      routeCount: jsRoutes.length,
      evidence: `${jsRoutes.map((route) => route.path).slice(0, 3).join(', ')} script route(s) suggest JavaScript and React client review.`,
    });
  }
  if (jsonRoutes.length) {
    addTechnology(insights, {
      id: 'json-api',
      label: 'JSON API',
      category: 'api',
      confidence: 'firm',
      routeCount: jsonRoutes.length,
      evidence: `${jsonRoutes.length} API/JSON route(s) are ready for parameter and authorization review.`,
    });
  }
  if (graphqlRoutes.length) {
    addTechnology(insights, {
      id: 'graphql-api',
      label: 'GraphQL API',
      category: 'api',
      confidence: 'certain',
      routeCount: graphqlRoutes.length,
      evidence: `${graphqlRoutes.map((route) => route.path).join(', ')} exposes GraphQL route inventory.`,
    });
  }
  if (assetRoutes.length) {
    addTechnology(insights, {
      id: 'static-asset-cdn',
      label: 'Static asset/CDN surface',
      category: 'asset',
      confidence: 'firm',
      routeCount: assetRoutes.length,
      evidence: `${assetRoutes.length} static route(s) can seed source-map and hidden-route discovery.`,
    });
  }

  return Array.from(insights.values());
}

export function buildTargetParameterInventory(request: TargetSiteMapEngineRequest): TargetParameterInsight[] {
  const routes = normalizeRoutes(request);
  const insertionPoints = normalizeInsertionPoints(request);
  const routeById = new Map(routes.map((route) => [route.id, route]));
  const parameterMap = new Map<string, TargetParameterInsight>();

  const addParameter = (name: string, location: string, method: string, route: CrawlRoute | undefined, evidence: string) => {
    const id = `${location}:${name}:${method}`.toLowerCase();
    const existing = parameterMap.get(id);
    const routeLabel = route ? routeKey(route) : 'manual route';
    parameterMap.set(id, {
      id,
      name,
      location,
      method,
      routeCount: existing ? existing.routeCount + (existing.routes.includes(routeLabel) ? 0 : 1) : 1,
      routes: Array.from(new Set([...(existing?.routes ?? []), routeLabel])).slice(0, 12),
      evidence: existing ? Array.from(new Set([existing.evidence, evidence])).join('; ') : evidence,
    });
  };

  for (const point of insertionPoints) {
    addParameter(point.name, String(point.type), point.method, routeById.get(point.routeId), point.evidence);
  }
  for (const route of routes) {
    try {
      const url = new URL(routeUrl(route));
      for (const [name, value] of url.searchParams) {
        addParameter(name, 'query', route.method, route, `URL query parameter ${name}=${value}`);
      }
    } catch {
      // Route came from an imported partial map. Insertion-point metadata still covers parameters.
    }
  }

  return Array.from(parameterMap.values()).sort((left, right) => right.routeCount - left.routeCount || left.name.localeCompare(right.name));
}

export function buildTargetContentDiscoveryHandoff(request: TargetSiteMapEngineRequest): TargetContentDiscoveryHandoff {
  const routes = normalizeRoutes(request);
  const filters = normalizeFilters(request.filters);
  const selectedRoutes = filterRoutes(routes, normalizeInsertionPoints(request), request.filters);
  const seedRoutes = selectedRoutes.length ? selectedRoutes : routes;
  const hosts = Array.from(new Set(seedRoutes.map((route) => route.host)));
  const now = request.now ?? new Date().toISOString();
  const candidates: TargetContentDiscoveryCandidate[] = [];
  const pushCandidate = (candidate: TargetContentDiscoveryCandidate) => {
    if (candidates.some((item) => item.host === candidate.host && item.path === candidate.path)) return;
    candidates.push(candidate);
  };

  for (const host of hosts) {
    pushCandidate({
      id: `target-discovery-${host}-backup`.replace(/[^a-z0-9_-]+/gi, '-'),
      host,
      path: '/backup.zip',
      source: 'backup',
      priority: 'medium',
      reason: 'Focused wordlist candidate path for backup and archive exposure.',
    });
    pushCandidate({
      id: `target-discovery-${host}-well-known`.replace(/[^a-z0-9_-]+/gi, '-'),
      host,
      path: '/.well-known/security.txt',
      source: 'wordlist',
      priority: 'info',
      reason: 'Low-noise wordlist candidate path for policy and contact metadata.',
    });
  }
  for (const route of seedRoutes) {
    if (/\.m?js(?:\?|$)/i.test(route.path) || /javascript/i.test(route.mime)) {
      pushCandidate({
        id: `target-discovery-${route.id}-sourcemap`,
        host: route.host,
        path: `${route.path.split('?')[0]}.map`,
        source: 'script',
        priority: 'low',
        reason: 'Script route can hand off to source-map and hidden client route discovery.',
      });
    }
    if (route.path.includes('/api/')) {
      pushCandidate({
        id: `target-discovery-${route.id}-bulk`,
        host: route.host,
        path: `${route.path.replace(/\/$/, '')}/bulk`,
        source: 'api',
        priority: severityForRoute(route),
        reason: 'API route can queue adjacent hidden endpoint discovery with the same session and throttle context.',
      });
    }
    if (route.path.includes('/admin/')) {
      pushCandidate({
        id: `target-discovery-${route.id}-export`,
        host: route.host,
        path: '/admin/export',
        source: 'route',
        priority: 'high',
        reason: 'Admin route suggests role-gated export discovery and access-control review.',
      });
    }
  }

  const candidateCount = candidates.length;
  const scopeSummary = (request.scopeAllowlist ?? ['*.shop.local']).join(', ');
  const packageRefreshProof = buildTargetPackageRefreshProof(now, [
    {
      id: 'target-content-discovery-source-routes',
      kind: 'proxyforge-target-content-discovery-source-routes',
      content: JSON.stringify(seedRoutes.map((route) => ({ id: route.id, method: route.method, host: route.host, path: route.path, source: route.source }))),
      reportReady: seedRoutes.length > 0,
    },
    {
      id: 'target-content-discovery-candidates',
      kind: 'proxyforge-target-content-discovery-candidates',
      content: JSON.stringify(candidates),
      reportReady: candidateCount > 0,
    },
  ], JSON.stringify({ filters, scopeSummary, seedRoutes, candidates }), {
    sourceRouteCount: seedRoutes.length,
    sourceCandidateCount: candidateCount,
  });
  const requirements = {
    packageRefreshCovered: packageRefreshProof.stalePackageIds.length === 0
      && ['proxyforge-target-content-discovery-source-routes', 'proxyforge-target-content-discovery-candidates']
        .every((kind) => packageRefreshProof.linkedPackageKinds.includes(kind)),
    scopeAndThrottleCovered: Boolean(scopeSummary) && (request.throttleMs ?? 150) > 0,
    candidateDiversityCovered: new Set(candidates.map((candidate) => candidate.source)).size >= 2,
    reportPhaseOnlyRedaction: true,
  };
  return {
    id: `target-content-discovery-${Date.parse(now) || Date.now()}`,
    createdAt: now,
    hostCount: hosts.length,
    candidateCount,
    wordlistProfile: filters.url ? `focused:${filters.url}` : 'balanced-app-api-assets',
    throttleMs: request.throttleMs ?? 150,
    scopeSummary,
    candidates: candidates.slice(0, 24),
    packageRefreshProof,
    requirements,
    summary: `Content discovery handoff queued ${candidateCount} candidate path${candidateCount === 1 ? '' : 's'} across ${hosts.length} host${hosts.length === 1 ? '' : 's'} with wordlist, script, route, and hidden API lanes.`,
  };
}

function normalizeRole(value: string) {
  return value.trim().toLowerCase().replace(/[^a-z0-9_-]+/g, '_') || 'role';
}

function accessControlStatusObservation(status?: number): TargetAccessControlObservation {
  if (status === undefined || Number.isNaN(status)) return 'unknown';
  if (status === 401 || status === 403) return 'denied';
  if (status === 404 || status === 410 || status === 0) return 'hidden';
  if (status >= 200 && status < 400) return 'visible';
  if (status >= 400) return 'denied';
  return 'unknown';
}

function accessControlSeverity(route: CrawlRoute, drift: TargetAccessControlDrift): Severity {
  if (drift === 'overexposed') return /admin|support|finance|refund|graphql|\/api\//i.test(route.path) || route.method !== 'GET' ? 'high' : 'medium';
  if (drift === 'underexposed') return 'medium';
  if (drift === 'missing-observation') return /admin|support|finance|refund|graphql|\/api\//i.test(route.path) ? 'medium' : 'info';
  return severityForRoute(route) === 'high' ? 'medium' : 'info';
}

function defaultExpectationForRole(role: string, route: CrawlRoute): TargetAccessControlExpectation {
  const normalizedRole = normalizeRole(role);
  const target = `${route.method} ${route.path} ${route.title}`.toLowerCase();
  if (/anonymous|guest|public/.test(normalizedRole)) return /login|signup|static|assets|security\.txt|\.$/.test(target) ? 'visible' : 'denied';
  if (/customer|viewer|user|low/.test(normalizedRole)) {
    if (/admin|support|finance|impersonate|export|audit|graphql|refund/.test(target)) return 'denied';
    if (route.method !== 'GET' && /\/api\//.test(target)) return 'denied';
  }
  if (/finance/.test(normalizedRole)) return /support|impersonate|audit|admin\/users/.test(target) ? 'denied' : 'visible';
  if (/support|admin|staff|privileged/.test(normalizedRole)) return 'visible';
  return /admin|support|finance/.test(target) ? 'denied' : 'visible';
}

function expectedForRoleMap(
  roleMap: NonNullable<TargetSiteMapEngineRequest['accessControlRoleMaps']>[number] | undefined,
  role: string,
  route: CrawlRoute,
): TargetAccessControlExpectation {
  const routeLabel = `${route.method} ${route.host}${route.path}`;
  if (roleMap?.expectedVisiblePatterns?.some((pattern) => new RegExp(pattern, 'i').test(routeLabel))) return 'visible';
  if (roleMap?.expectedDeniedPatterns?.some((pattern) => new RegExp(pattern, 'i').test(routeLabel))) return 'denied';
  return defaultExpectationForRole(role, route);
}

function observedForRoleMap(
  roleMap: NonNullable<TargetSiteMapEngineRequest['accessControlRoleMaps']>[number] | undefined,
  route: CrawlRoute,
): { observed: TargetAccessControlObservation; status?: number } {
  const ids = new Set(roleMap?.routeIds ?? []);
  const visibleIds = new Set([...(roleMap?.visibleRouteIds ?? []), ...ids]);
  const deniedIds = new Set(roleMap?.deniedRouteIds ?? []);
  const hiddenIds = new Set(roleMap?.hiddenRouteIds ?? []);
  if (visibleIds.has(route.id)) return { observed: 'visible', status: roleMap?.statusByRoute?.[route.id] };
  if (deniedIds.has(route.id)) return { observed: 'denied', status: roleMap?.statusByRoute?.[route.id] ?? 403 };
  if (hiddenIds.has(route.id)) return { observed: 'hidden', status: roleMap?.statusByRoute?.[route.id] ?? 404 };
  const status = roleMap?.statusByRoute?.[route.id];
  return { observed: accessControlStatusObservation(status), status };
}

function accessControlDrift(
  expected: TargetAccessControlExpectation,
  observed: TargetAccessControlObservation,
): TargetAccessControlDrift {
  if (observed === 'unknown') return 'missing-observation';
  if (expected === 'visible' && observed !== 'visible') return 'underexposed';
  if ((expected === 'denied' || expected === 'hidden') && observed === 'visible') return 'overexposed';
  return 'none';
}

export function buildTargetAccessControlReview(request: TargetSiteMapEngineRequest): TargetAccessControlReviewLane[] {
  const routes = normalizeRoutes(request);
  const roleMaps = request.accessControlRoleMaps ?? [];
  const profileSet = new Set([
    ...(request.accessControlProfiles?.length ? request.accessControlProfiles : ['customer', 'support_admin', 'finance_admin']),
    ...roleMaps.map((map) => map.role),
  ]);
  const profiles = Array.from(profileSet);

  return profiles.map((role) => {
    const normalizedRole = normalizeRole(role);
    const roleMap = roleMaps.find((map) => normalizeRole(map.role) === normalizedRole);
    const decisions: TargetAccessControlRouteDecision[] = routes.map((route) => {
      const expected = expectedForRoleMap(roleMap, role, route);
      const { observed, status } = observedForRoleMap(roleMap, route);
      const drift = accessControlDrift(expected, observed);
      return {
        id: `target-access-${normalizedRole}-${route.id}`.replace(/[^a-z0-9_-]+/gi, '-').toLowerCase(),
        role,
        routeId: route.id,
        route: routeKey(route),
        method: route.method,
        host: route.host,
        path: route.path,
        expected,
        observed,
        observedStatus: status,
        drift,
        severity: accessControlSeverity(route, drift),
        evidence: `${role} expected ${expected} and observed ${observed}${status !== undefined ? ` (${status})` : ''} for ${routeKey(route)}.`,
        exchangeIds: roleMap?.exchangeIds ?? [],
      };
    });
    const visibleRouteCount = decisions.filter((decision) => decision.observed === 'visible').length;
    const deniedRouteCount = decisions.filter((decision) => decision.observed === 'denied').length;
    const hiddenRouteCount = decisions.filter((decision) => decision.observed === 'hidden').length;
    const overexposedCount = decisions.filter((decision) => decision.drift === 'overexposed').length;
    const underexposedCount = decisions.filter((decision) => decision.drift === 'underexposed').length;
    const missingObservationCount = decisions.filter((decision) => decision.drift === 'missing-observation').length;
    const driftCount = overexposedCount + underexposedCount;
    const riskyRoutes = decisions
      .filter((decision) => decision.drift !== 'none' || severityRank(decision.severity) >= severityRank('medium'))
      .sort((left, right) => severityRank(right.severity) - severityRank(left.severity) || left.route.localeCompare(right.route))
      .map((decision) => `${decision.route} ${decision.drift}`);
    const severity: Severity = overexposedCount > 0
      ? 'high'
      : underexposedCount > 0 || missingObservationCount > 0
        ? 'medium'
        : 'info';
    const exchangeIds = roleMap?.exchangeIds ?? [];
    const packageRefreshProof = buildTargetPackageRefreshProof(request.now ?? new Date().toISOString(), [
      {
        id: `target-access-${normalizedRole}-role-map`,
        kind: 'proxyforge-target-access-control-role-map',
        content: JSON.stringify(roleMap ?? { role, generatedExpectation: true }),
        reportReady: Boolean(roleMap),
      },
      {
        id: `target-access-${normalizedRole}-decisions`,
        kind: 'proxyforge-target-access-control-decisions',
        content: JSON.stringify(decisions),
        reportReady: decisions.length > 0,
      },
    ], JSON.stringify({ role, roleMap, decisions, exchangeIds }), {
      sourceRouteCount: routes.length,
      sourceRoleCount: 1,
    });
    const requirements = {
      packageRefreshCovered: packageRefreshProof.stalePackageIds.length === 0
        && ['proxyforge-target-access-control-role-map', 'proxyforge-target-access-control-decisions']
          .every((kind) => packageRefreshProof.linkedPackageKinds.includes(kind)),
      roleObservationCovered: decisions.some((decision) => decision.observed !== 'unknown'),
      driftClassificationCovered: decisions.some((decision) => decision.drift !== 'none' || decision.observed === 'visible' || decision.observed === 'denied'),
      rawExchangeLinksCovered: exchangeIds.length > 0,
      reportPhaseOnlyRedaction: true,
    };
    return {
      id: `target-access-${normalizedRole}`.replace(/[^a-z0-9_-]+/gi, '-').toLowerCase(),
      role,
      routeCount: routes.length,
      visibleRouteCount,
      deniedRouteCount,
      hiddenRouteCount,
      driftCount,
      overexposedCount,
      underexposedCount,
      missingObservationCount,
      riskyRoutes: Array.from(new Set(riskyRoutes)).slice(0, 12),
      routeDecisions: decisions.slice(0, 100),
      expectedVisibility: /customer|viewer|user|low|guest/.test(normalizedRole)
        ? 'Privileged admin, support, finance, mutation, refund, and GraphQL routes should be denied or hidden'
        : 'Only assigned operational routes should be visible for this role',
      reviewAction: `Run authorization matrix review for ${role} against captured role map, Repeater matrix, Scanner authz-diff, and Comparer response deltas.`,
      severity,
      evidenceSummary: `Role ${role}: ${visibleRouteCount} visible, ${deniedRouteCount} denied, ${hiddenRouteCount} hidden, ${overexposedCount} overexposed, ${underexposedCount} underexposed, ${missingObservationCount} missing observation.`,
      capturedAt: roleMap?.capturedAt,
      packageRefreshProof,
      requirements,
    };
  });
}

export function buildTargetAnalyzerInventory(request: TargetSiteMapEngineRequest): TargetSiteMapAnalysisPackage {
  const routes = normalizeRoutes(request);
  const insertionPoints = normalizeInsertionPoints(request);
  const technologies = buildTargetTechnologyInventory(request);
  const parameters = buildTargetParameterInventory(request);
  const contentDiscoveryHandoff = buildTargetContentDiscoveryHandoff(request);
  const accessControlReview = buildTargetAccessControlReview(request);
  const overlays = buildTargetRouteFindingOverlays(request);
  const createdAt = request.now ?? new Date().toISOString();
  const hostCount = new Set(routes.map((route) => route.host)).size;
  const inventoryText = JSON.stringify({ technologies, parameters, overlays });
  const accessControlText = JSON.stringify(accessControlReview);
  const packageRefreshProof = buildTargetPackageRefreshProof(createdAt, [
    {
      id: contentDiscoveryHandoff.id,
      kind: 'proxyforge-target-content-discovery-handoff',
      content: JSON.stringify(contentDiscoveryHandoff),
      reportReady: contentDiscoveryHandoff.requirements?.packageRefreshCovered === true,
    },
    {
      id: 'target-access-control-review',
      kind: 'proxyforge-target-access-control-review',
      content: accessControlText,
      reportReady: accessControlReview.some((lane) => lane.requirements?.packageRefreshCovered === true),
    },
    {
      id: 'target-technology-inventory',
      kind: 'proxyforge-target-technology-inventory',
      content: JSON.stringify(technologies),
      reportReady: technologies.length > 0,
    },
    {
      id: 'target-parameter-inventory',
      kind: 'proxyforge-target-parameter-inventory',
      content: JSON.stringify(parameters),
      reportReady: parameters.length > 0,
    },
  ], JSON.stringify({ routes, insertionPoints, inventoryText, accessControlText, contentDiscoveryHandoff }), {
    sourceRouteCount: routes.length,
    sourceInsertionPointCount: insertionPoints.length,
    sourceRoleCount: accessControlReview.length,
    sourceCandidateCount: contentDiscoveryHandoff.candidateCount,
  });
  const requirements = {
    contentDiscoveryPackageRefreshCovered: contentDiscoveryHandoff.requirements?.packageRefreshCovered === true,
    accessControlPackageRefreshCovered: accessControlReview.some((lane) => lane.requirements?.packageRefreshCovered === true)
      && accessControlReview.some((lane) => lane.requirements?.rawExchangeLinksCovered === true),
    inventoryPackageRefreshCovered: packageRefreshProof.stalePackageIds.length === 0
      && ['proxyforge-target-technology-inventory', 'proxyforge-target-parameter-inventory']
        .every((kind) => packageRefreshProof.linkedPackageKinds.includes(kind)),
    reportPhaseOnlyRedaction: true,
  };
  const unsigned = {
    kind: 'proxyforge-target-site-map-analysis',
    createdAt,
    routeCount: routes.length,
    hostCount,
    insertionPointCount: insertionPoints.length,
    technologyInventory: technologies,
    parameterInventory: parameters,
    contentDiscoveryHandoff,
    accessControlReview,
    overlays,
    packageRefreshProof,
    requirements,
    summary: `Target analyzer inventory: ${routes.length} route(s), ${technologies.length} technology signal(s), ${parameters.length} parameter(s), access-control matrix review ready.`,
  };
  const content = JSON.stringify({ ...unsigned, digestPreview: simpleDigest(JSON.stringify(unsigned)) }, null, 2);

  return {
    id: `target-analysis-${Date.parse(createdAt) || Date.now()}`,
    title: 'Target analyzer inventory',
    fileName: `proxyforge-target-site-map-analysis-${Date.parse(createdAt) || Date.now()}.json`,
    path: `target/proxyforge-target-site-map-analysis-${Date.parse(createdAt) || Date.now()}.json`,
    createdAt,
    reportReady: Object.values(requirements).every(Boolean),
    routeCount: routes.length,
    hostCount,
    insertionPointCount: insertionPoints.length,
    technologyInventory: technologies,
    parameterInventory: parameters,
    contentDiscoveryHandoff,
    accessControlReview,
    overlays,
    packageRefreshProof,
    requirements,
    summary: unsigned.summary,
    content,
  };
}

export function analyzeTargetSiteMap(request: TargetSiteMapEngineRequest): TargetSiteMapAnalysisPackage {
  return buildTargetAnalyzerInventory(request);
}

export function buildTargetRouteFindingOverlays(request: TargetSiteMapEngineRequest): TargetRouteFindingOverlay[] {
  const routes = normalizeRoutes(request);
  const routeOverlays: TargetRouteFindingOverlay[] = routes
    .filter((route) => route.status >= 400 || route.status === 0 || route.insertionPoints.length > 0 || route.path.includes('/admin'))
    .map((route) => ({
      id: `target-overlay-${route.id}`,
      title: route.insertionPoints.length ? 'Parameter-bearing route' : route.status >= 400 || route.status === 0 ? 'Stale or failed fetch state' : 'Privileged route review',
      severity: severityForRoute(route),
      host: route.host,
      path: route.path,
      status: route.status ? String(route.status) : 'manual-review',
      source: route.status >= 400 || route.status === 0 ? 'crawler' : 'activity',
    }));
  const issueOverlays = (request.issues ?? []).map((issue) => ({
    id: `target-overlay-issue-${issue.id}`,
    title: issue.title,
    severity: issue.severity,
    host: issue.host,
    path: issue.path,
    status: issue.status,
    source: 'issue' as const,
  }));
  return [...issueOverlays, ...routeOverlays].slice(0, 40);
}

export function buildTargetSiteMapComparisonPackage(request: TargetSiteMapEngineRequest): TargetSiteMapComparisonPackage {
  const routes = normalizeRoutes(request);
  const insertionPoints = normalizeInsertionPoints(request);
  const baselineRoutes = routeSubset(routes, request.baseline).length
    ? routeSubset(routes, request.baseline)
    : routes.filter((route) => route.depth === 0 || route.source === 'seed');
  const candidateRoutes = routeSubset(routes, request.candidate);
  const baselineByKey = new Map(baselineRoutes.map((route) => [routeKey(route).toLowerCase(), route]));
  const candidateByKey = new Map(candidateRoutes.map((route) => [routeKey(route).toLowerCase(), route]));
  const deltas: TargetSiteMapComparisonDelta[] = [];

  for (const [key, route] of candidateByKey) {
    const baseline = baselineByKey.get(key);
    if (!baseline) {
      const parameters = routeParameterNames(route, insertionPoints);
      deltas.push({
        id: `target-delta-added-${route.id}`,
        kind: 'added',
        changeTypes: ['visibility', ...(parameters.length ? ['parameter' as const] : []), ...(routeAuthzSensitive(route) ? ['authz' as const] : [])],
        route: routeKey(route),
        severity: severityForRoute(route),
        detail: `Added candidate route from ${route.source} discovery; include in content discovery, parameter review, and access-control matrix.${parameters.length ? ` Parameters: ${parameters.join(', ')}.` : ''}`,
        candidate: {
          status: route.status,
          mime: route.mime,
          insertionPointCount: parameters.length,
          host: route.host,
          method: route.method,
        },
        affectedParameters: parameters,
        evidence: [`candidate ${route.method} ${route.host}${route.path}`, `authzSensitive=${routeAuthzSensitive(route)}`],
      });
    } else {
      const baselineParameters = routeParameterNames(baseline, insertionPoints);
      const candidateParameters = routeParameterNames(route, insertionPoints);
      const affectedParameters = Array.from(new Set([...baselineParameters, ...candidateParameters]))
        .filter((name) => !baselineParameters.includes(name) || !candidateParameters.includes(name));
      const baselineAuthzSensitive = routeAuthzSensitive(baseline);
      const candidateAuthzSensitive = routeAuthzSensitive(route);
      const structuralChangeTypes = [
        ...(baseline.status !== route.status ? ['status' as const] : []),
        ...(baseline.mime !== route.mime ? ['mime' as const] : []),
        ...(baseline.method !== route.method ? ['method' as const] : []),
        ...(baseline.host !== route.host ? ['host' as const] : []),
        ...(affectedParameters.length || baselineParameters.length !== candidateParameters.length ? ['parameter' as const] : []),
      ];
      const changeTypes = [
        ...structuralChangeTypes,
        ...((baselineAuthzSensitive !== candidateAuthzSensitive || (structuralChangeTypes.length && (baselineAuthzSensitive || candidateAuthzSensitive))) ? ['authz' as const] : []),
      ];
      if (changeTypes.length) {
      deltas.push({
        id: `target-delta-changed-${route.id}`,
        kind: 'changed',
        changeTypes,
        route: routeKey(route),
        severity: comparisonDeltaSeverity(route, changeTypes),
        detail: `Changed route metadata: status ${baseline.status || '-'} -> ${route.status || '-'}, MIME ${baseline.mime} -> ${route.mime}, parameters ${baselineParameters.length} -> ${candidateParameters.length}, change types ${changeTypes.join(', ')}.`,
        baseline: {
          status: baseline.status,
          mime: baseline.mime,
          insertionPointCount: baselineParameters.length,
          host: baseline.host,
          method: baseline.method,
        },
        candidate: {
          status: route.status,
          mime: route.mime,
          insertionPointCount: candidateParameters.length,
          host: route.host,
          method: route.method,
        },
        affectedParameters,
        evidence: [
          `baseline ${baseline.method} ${baseline.host}${baseline.path}`,
          `candidate ${route.method} ${route.host}${route.path}`,
          `authzSensitive=${candidateAuthzSensitive || baselineAuthzSensitive}`,
        ],
      });
      }
    }
  }
  for (const [key, route] of baselineByKey) {
    if (!candidateByKey.has(key)) {
      const parameters = routeParameterNames(route, insertionPoints);
      deltas.push({
        id: `target-delta-removed-${route.id}`,
        kind: 'removed',
        changeTypes: ['visibility', ...(parameters.length ? ['parameter' as const] : []), ...(routeAuthzSensitive(route) ? ['authz' as const] : [])],
        route: routeKey(route),
        severity: 'low',
        detail: `Removed baseline route; verify whether route moved, became role-gated, or was excluded by filters.${parameters.length ? ` Prior parameters: ${parameters.join(', ')}.` : ''}`,
        baseline: {
          status: route.status,
          mime: route.mime,
          insertionPointCount: parameters.length,
          host: route.host,
          method: route.method,
        },
        affectedParameters: parameters,
        evidence: [`baseline ${route.method} ${route.host}${route.path}`, `authzSensitive=${routeAuthzSensitive(route)}`],
      });
    }
  }

  const createdAt = request.now ?? new Date().toISOString();
  const added = deltas.filter((delta) => delta.kind === 'added').length;
  const removed = deltas.filter((delta) => delta.kind === 'removed').length;
  const changed = deltas.filter((delta) => delta.kind === 'changed').length;
  const statusChanged = deltas.filter((delta) => delta.changeTypes?.includes('status')).length;
  const mimeChanged = deltas.filter((delta) => delta.changeTypes?.includes('mime')).length;
  const parameterChanged = deltas.filter((delta) => delta.changeTypes?.includes('parameter')).length;
  const authzSensitiveChanged = deltas.filter((delta) => delta.changeTypes?.includes('authz')).length;
  const highRiskDeltaCount = deltas.filter((delta) => severityRank(delta.severity) >= severityRank('high')).length;
  const hostDeltaCount = new Set(deltas.map((delta) => delta.route.split(/\s+/)[1]?.split('/')[0]).filter(Boolean)).size;
  const normalization = ['method', 'host', 'path', 'status', 'mime', 'parameter-names', 'authz-sensitive-route', 'visibility'];
  const packageRefreshProof = buildTargetPackageRefreshProof(createdAt, [
    {
      id: 'target-comparison-baseline-routes',
      kind: 'proxyforge-target-comparison-baseline-routes',
      content: JSON.stringify(baselineRoutes),
      reportReady: baselineRoutes.length > 0,
    },
    {
      id: 'target-comparison-candidate-routes',
      kind: 'proxyforge-target-comparison-candidate-routes',
      content: JSON.stringify(candidateRoutes),
      reportReady: candidateRoutes.length > 0,
    },
    {
      id: 'target-comparison-deltas',
      kind: 'proxyforge-target-comparison-deltas',
      content: JSON.stringify(deltas),
      reportReady: deltas.length > 0,
    },
  ], JSON.stringify({ baselineRoutes, candidateRoutes, normalization, deltas }), {
    sourceRouteCount: uniqueStrings([...baselineRoutes, ...candidateRoutes].map((route) => route.id)).length,
    sourceInsertionPointCount: insertionPoints.length,
  });
  const requirements = {
    packageRefreshCovered: packageRefreshProof.stalePackageIds.length === 0
      && ['proxyforge-target-comparison-baseline-routes', 'proxyforge-target-comparison-candidate-routes', 'proxyforge-target-comparison-deltas']
        .every((kind) => packageRefreshProof.linkedPackageKinds.includes(kind)),
    baselineCandidateCovered: baselineRoutes.length > 0 && candidateRoutes.length > 0,
    deltaEvidenceCovered: deltas.length > 0 && deltas.every((delta) => (delta.evidence?.length ?? 0) > 0),
    reportPhaseOnlyRedaction: true,
  };
  const unsigned = {
    kind: 'proxyforge-target-site-map-comparison',
    createdAt,
    baseline: {
      name: request.baseline?.name ?? 'Target baseline',
      capturedAt: request.baseline?.capturedAt ?? createdAt,
      routeCount: baselineRoutes.length,
    },
    candidate: {
      name: request.candidate?.name ?? 'Target candidate',
        capturedAt: request.candidate?.capturedAt ?? createdAt,
        routeCount: candidateRoutes.length,
      },
    normalization,
    stats: {
      added,
      removed,
      changed,
      statusChanged,
      mimeChanged,
      parameterChanged,
      authzSensitiveChanged,
      highRiskDeltaCount,
      hostDeltaCount,
    },
    deltas,
    packageRefreshProof,
    requirements,
    summary: `Target site-map comparison package saved: ${added} added, ${removed} removed, ${changed} changed route(s), ${parameterChanged} parameter delta(s), ${statusChanged} status delta(s), and ${authzSensitiveChanged} authz-sensitive delta(s) across baseline and candidate maps.`,
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const content = JSON.stringify({ ...unsigned, digestPreview }, null, 2);

  return {
    id: `target-comparison-${Date.parse(createdAt) || Date.now()}`,
    title: 'Target site-map comparison package',
    fileName: `proxyforge-target-site-map-comparison-${Date.parse(createdAt) || Date.now()}.json`,
    path: `target/proxyforge-target-site-map-comparison-${Date.parse(createdAt) || Date.now()}.json`,
    createdAt,
    reportReady: Object.values(requirements).every(Boolean),
    baselineName: request.baseline?.name ?? 'Target baseline',
    candidateName: request.candidate?.name ?? 'Target candidate',
    baselineRouteCount: baselineRoutes.length,
    candidateRouteCount: candidateRoutes.length,
    added,
    removed,
    changed,
    statusChanged,
    mimeChanged,
    parameterChanged,
    authzSensitiveChanged,
    highRiskDeltaCount,
    hostDeltaCount,
    normalization,
    digestPreview,
    deltas,
    packageRefreshProof,
    requirements,
    summary: unsigned.summary,
    content,
  };
}

export function buildSiteMapComparisonPackage(request: TargetSiteMapEngineRequest): TargetSiteMapComparisonPackage {
  return buildTargetSiteMapComparisonPackage(request);
}

export function buildTargetSiteMapReportAttachment(
  request: TargetSiteMapEngineRequest & {
    analysisPackage?: TargetSiteMapAnalysisPackage;
    comparisonPackage?: TargetSiteMapComparisonPackage;
    issueId?: string;
  },
): TargetSiteMapEvidenceAttachment {
  const analysisPackage = request.analysisPackage ?? buildTargetAnalyzerInventory(request);
  const comparisonPackage = request.comparisonPackage ?? buildTargetSiteMapComparisonPackage(request);
  const createdAt = request.now ?? new Date().toISOString();
  const packageRefreshProof = buildTargetPackageRefreshProof(createdAt, [
    {
      id: analysisPackage.id,
      kind: 'proxyforge-target-site-map-analysis',
      content: analysisPackage.content,
      reportReady: analysisPackage.reportReady && (!analysisPackage.requirements || Object.values(analysisPackage.requirements).every(Boolean)),
    },
    {
      id: comparisonPackage.id,
      kind: 'proxyforge-target-site-map-comparison',
      content: comparisonPackage.content,
      reportReady: comparisonPackage.reportReady && (!comparisonPackage.requirements || Object.values(comparisonPackage.requirements).every(Boolean)),
    },
  ], JSON.stringify({ analysisPackage, comparisonPackage, issueId: request.issueId }), {
    sourceRouteCount: analysisPackage.routeCount,
    sourceInsertionPointCount: analysisPackage.insertionPointCount,
  });
  const requirements = {
    packageRefreshCovered: packageRefreshProof.stalePackageIds.length === 0
      && ['proxyforge-target-site-map-analysis', 'proxyforge-target-site-map-comparison']
        .every((kind) => packageRefreshProof.linkedPackageKinds.includes(kind)),
    analysisPackageLinked: analysisPackage.reportReady,
    comparisonPackageLinked: comparisonPackage.reportReady,
    reportPhaseOnlyRedaction: true,
  };
  const unsigned = {
    kind: 'proxyforge-target-site-map-evidence',
    createdAt,
    reportReady: Object.values(requirements).every(Boolean),
    title: 'Target Site Map Evidence',
    analysisPackage: {
      id: analysisPackage.id,
      routeCount: analysisPackage.routeCount,
      hostCount: analysisPackage.hostCount,
      technologyInventory: analysisPackage.technologyInventory,
      parameterInventory: analysisPackage.parameterInventory,
      accessControlReview: analysisPackage.accessControlReview,
      contentDiscoveryHandoff: analysisPackage.contentDiscoveryHandoff,
    },
    comparisonPackage: {
      id: comparisonPackage.id,
      digestPreview: comparisonPackage.digestPreview,
      added: comparisonPackage.added,
      removed: comparisonPackage.removed,
      changed: comparisonPackage.changed,
      deltas: comparisonPackage.deltas,
    },
    packageRefreshProof,
    requirements,
    summary: `Target Site Map Evidence report-ready attachment: ${analysisPackage.routeCount} route(s), Technology Inventory ${analysisPackage.technologyInventory.length} signal(s), Parameter Inventory ${analysisPackage.parameterInventory.length} parameter(s), Access-Control Review lanes, content discovery handoff, and proxyforge-target-site-map-comparison ${comparisonPackage.digestPreview} comparison package.`,
  };
  const content = JSON.stringify({ ...unsigned, digestPreview: simpleDigest(JSON.stringify(unsigned)) }, null, 2);

  return {
    id: `target-evidence-${Date.parse(createdAt) || Date.now()}`,
    title: 'Target Site Map Evidence',
    fileName: `proxyforge-target-site-map-evidence-${Date.parse(createdAt) || Date.now()}.json`,
    path: `reports/target/proxyforge-target-site-map-evidence-${Date.parse(createdAt) || Date.now()}.json`,
    createdAt,
    reportReady: Object.values(requirements).every(Boolean),
    issueId: request.issueId,
    analysisPackageId: analysisPackage.id,
    comparisonPackageId: comparisonPackage.id,
    packageRefreshProof,
    requirements,
    summary: unsigned.summary,
    content,
  };
}

export function buildTargetReportAttachment(request: TargetSiteMapEngineRequest): TargetSiteMapEvidenceAttachment {
  return buildTargetSiteMapReportAttachment(request);
}

export function buildTargetParityEvidencePackage(request: TargetParityEvidenceRequest): TargetParityEvidencePackage {
  const createdAt = request.now ?? new Date().toISOString();
  const stamp = Date.parse(createdAt) || Date.now();
  const routes = normalizeRoutes(request);
  const insertionPoints = normalizeInsertionPoints(request);
  const viewModel = request.viewModel ?? buildTargetSiteMapViewModel(request);
  const analysisPackage = request.analysisPackage ?? buildTargetAnalyzerInventory(request);
  const comparisonPackage = request.comparisonPackage ?? buildTargetSiteMapComparisonPackage(request);
  const evidenceAttachment = request.evidenceAttachment ?? buildTargetSiteMapReportAttachment({
    ...request,
    analysisPackage,
    comparisonPackage,
  });
  const crawlSummary = request.crawl;
  const sessionEvidence = request.authenticatedSessionEvidence;
  const startHost = crawlSummary?.startUrl ? hostFromUrl(crawlSummary.startUrl) : '';
  const scopedHosts = request.scopeAllowlist ?? [];
  const routesHostScoped = scopedHosts.length === 0
    || routes.every((route) => scopedHosts.some((scope) => hostMatchesScope(route.host, scope)));
  const crawlScoped = Boolean(
    crawlSummary?.startUrl
    && (scopedHosts.length === 0 || scopedHosts.some((scope) => hostMatchesScope(startHost, scope)))
    && crawlSummary.blocked === false
    && routes.length > 0
    && routesHostScoped,
  );
  const technologyText = JSON.stringify(analysisPackage.technologyInventory);
  const parameterText = JSON.stringify(analysisPackage.parameterInventory);
  const rawExecutorMaterial = [
    crawlSummary?.startUrl,
    ...(routes.map((route) => `${route.method} ${route.url} ${route.status} ${route.mime}`).slice(0, 12)),
    analysisPackage.content,
    comparisonPackage.content,
    evidenceAttachment.content,
    JSON.stringify(sessionEvidence ?? {}),
    ...(request.operationalSecretSamples ?? []),
  ].filter(Boolean);
  const rawExecutorMaterialText = rawExecutorMaterial.join('\n');
  const accessControlPackageReady = analysisPackage.accessControlReview
    .some((lane) => lane.requirements?.packageRefreshCovered === true && lane.requirements.rawExchangeLinksCovered === true);
  const packageRefreshProof = buildTargetPackageRefreshProof(createdAt, [
    {
      id: analysisPackage.id,
      kind: 'proxyforge-target-site-map-analysis',
      content: analysisPackage.content,
      reportReady: analysisPackage.reportReady && (!analysisPackage.requirements || Object.values(analysisPackage.requirements).every(Boolean)),
    },
    {
      id: analysisPackage.contentDiscoveryHandoff.id,
      kind: 'proxyforge-target-content-discovery-handoff',
      content: JSON.stringify(analysisPackage.contentDiscoveryHandoff),
      reportReady: analysisPackage.contentDiscoveryHandoff.requirements?.packageRefreshCovered === true,
    },
    {
      id: 'target-access-control-review',
      kind: 'proxyforge-target-access-control-review',
      content: JSON.stringify(analysisPackage.accessControlReview),
      reportReady: accessControlPackageReady,
    },
    {
      id: comparisonPackage.id,
      kind: 'proxyforge-target-site-map-comparison',
      content: comparisonPackage.content,
      reportReady: comparisonPackage.reportReady && (!comparisonPackage.requirements || Object.values(comparisonPackage.requirements).every(Boolean)),
    },
    {
      id: evidenceAttachment.id,
      kind: 'proxyforge-target-site-map-evidence',
      content: evidenceAttachment.content,
      reportReady: evidenceAttachment.reportReady && (!evidenceAttachment.requirements || Object.values(evidenceAttachment.requirements).every(Boolean)),
    },
  ], rawExecutorMaterialText, {
    sourceRouteCount: routes.length,
    sourceInsertionPointCount: insertionPoints.length,
    sourceRoleCount: analysisPackage.accessControlReview.length,
    sourceCandidateCount: analysisPackage.contentDiscoveryHandoff.candidateCount,
  });
  const requiredPackageKinds = [
    'proxyforge-target-site-map-analysis',
    'proxyforge-target-content-discovery-handoff',
    'proxyforge-target-access-control-review',
    'proxyforge-target-site-map-comparison',
    'proxyforge-target-site-map-evidence',
  ];
  const requirements = {
    siteMapUrlTreeCovered: viewModel.hosts.length > 0 && viewModel.hosts.some((host) => host.routes.length > 0),
    crawlPathViewCovered: viewModel.crawlPath.length > 0 && viewModel.crawlPath.some((entry) => entry.parent === 'crawler root' || entry.depth > 0),
    scopedCrawlerCovered: crawlScoped,
    authenticatedSessionReuseCovered: Boolean(
      sessionEvidence?.profileIds.length
      && ((sessionEvidence.reusedExchangeIds?.length ?? 0) > 0 || (sessionEvidence.refreshedCookieNames?.length ?? 0) > 0),
    ),
    technologyInventoryCovered: analysisPackage.technologyInventory.length > 0 && /GraphQL|JSON API|HTML|JavaScript|HTTP/i.test(technologyText),
    parameterInsertionInventoryCovered: analysisPackage.parameterInventory.length > 0 && /query|form|path|cookie|header|body|json|orderId|status/i.test(parameterText),
    contentDiscoveryHandoffCovered: analysisPackage.contentDiscoveryHandoff.candidateCount > 0,
    accessControlReviewCovered: analysisPackage.accessControlReview.some((lane) => (lane.routeDecisions?.length ?? 0) > 0),
    siteMapComparisonCovered: comparisonPackage.reportReady && comparisonPackage.deltas.length > 0,
    reportsHandoffCovered: evidenceAttachment.reportReady && evidenceAttachment.path.startsWith('reports/'),
    packageRefreshCovered: packageRefreshProof.stalePackageIds.length === 0
      && requiredPackageKinds.every((kind) => packageRefreshProof.linkedPackageKinds.includes(kind)),
    rawExecutorMaterialPreserved: rawExecutorMaterial.length >= 6,
    operationalSecretsPreserved: Boolean(request.operationalSecretSamples?.length)
      && (request.operationalSecretSamples ?? []).every((sample) => rawExecutorMaterialText.includes(sample)),
    reportPhaseOnlyRedaction: true,
  };
  const unsigned = {
    kind: 'proxyforge-target-parity-evidence-package',
    createdAt,
    viewModel,
    analysisPackage,
    comparisonPackage,
    evidenceAttachment,
    authenticatedSessionEvidence: sessionEvidence,
    packageRefreshProof,
    operationalSecretSamples: request.operationalSecretSamples ?? [],
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const content = JSON.stringify({ ...unsigned, digestPreview }, null, 2);

  return {
    id: `target-parity-${stamp}`,
    kind: 'proxyforge-target-parity-evidence-package',
    title: 'Target parity evidence package',
    fileName: `proxyforge-target-parity-${stamp}.json`,
    path: `target/proxyforge-target-parity-${stamp}.json`,
    createdAt,
    routeCount: routes.length,
    hostCount: viewModel.hostCount,
    crawlPathCount: viewModel.crawlPath.length,
    insertionPointCount: insertionPoints.length,
    technologyCount: analysisPackage.technologyInventory.length,
    parameterCount: analysisPackage.parameterInventory.length,
    artifactIds: {
      analysisPackageId: analysisPackage.id,
      comparisonPackageId: comparisonPackage.id,
      evidenceAttachmentId: evidenceAttachment.id,
      contentDiscoveryHandoffId: analysisPackage.contentDiscoveryHandoff.id,
    },
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
    digestPreview,
    packageRefreshProof,
    summary: 'Target parity evidence covers URL tree and crawl-path views, scoped crawler output, authenticated session reuse, technology and parameter inventories, content discovery, access-control review, site-map comparison, Reports handoff, and package-refresh proof.',
    content,
  };
}
