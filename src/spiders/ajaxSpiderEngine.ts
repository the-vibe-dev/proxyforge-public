// Cross-cutting reducer: merges Ajax spider routes into the sitemap.
// Deduplicates, normalises, and annotates routes with discovery metadata.

// Keep in sync with electron/spiders/ajaxSpiderDriver.ts:DiscoveredRoute
export interface DiscoveredRoute {
  url: string;
  method: string;
  foundAt: string;
  depth: number;
  via: 'navigation' | 'fetch-intercept' | 'xhr-intercept' | 'form-submit' | 'link-follow';
  framework?: string;
}

export interface SitemapEntry {
  url: string;
  method: string;
  depth: number;
  discoveredAt: string;
  via: DiscoveredRoute['via'];
  framework?: string;
  visited: boolean;
  parameterised: boolean;
}

export interface AjaxSpiderState {
  entries: Map<string, SitemapEntry>;
  startUrl: string;
  framework?: string;
  visitCount: number;
  maxDepth: number;
}

export function createSpiderState(startUrl: string, maxDepth = 3): AjaxSpiderState {
  return {
    entries: new Map(),
    startUrl,
    maxDepth,
    visitCount: 0,
    framework: undefined,
  };
}

export function mergeRoutes(state: AjaxSpiderState, routes: DiscoveredRoute[]): SitemapEntry[] {
  const added: SitemapEntry[] = [];
  const now = new Date().toISOString();

  for (const route of routes) {
    const key = normaliseKey(route.method, route.url);
    if (state.entries.has(key)) continue;

    const entry: SitemapEntry = {
      url: route.url,
      method: route.method,
      depth: route.depth,
      discoveredAt: now,
      via: route.via,
      framework: route.framework,
      visited: false,
      parameterised: isParameterised(route.url),
    };

    state.entries.set(key, entry);
    added.push(entry);
  }

  return added;
}

export function markVisited(state: AjaxSpiderState, url: string, method = 'GET'): void {
  const key = normaliseKey(method, url);
  const entry = state.entries.get(key);
  if (entry) {
    entry.visited = true;
    state.visitCount++;
  }
}

export function getUnvisited(state: AjaxSpiderState): SitemapEntry[] {
  return [...state.entries.values()].filter((e) => !e.visited);
}

export function getSitemapSnapshot(state: AjaxSpiderState): SitemapEntry[] {
  return [...state.entries.values()];
}

export function setFramework(state: AjaxSpiderState, framework: string): void {
  state.framework = framework;
}

export function filterByDepth(state: AjaxSpiderState, maxDepth: number): SitemapEntry[] {
  return [...state.entries.values()].filter((e) => e.depth <= maxDepth);
}

export function filterByOrigin(state: AjaxSpiderState, origin: string): SitemapEntry[] {
  return [...state.entries.values()].filter((e) => {
    try { return new URL(e.url).origin === origin; } catch { return false; }
  });
}

function normaliseKey(method: string, url: string): string {
  try {
    const u = new URL(url);
    // Strip fragment; keep query params as-is for deduplication accuracy
    return `${method.toUpperCase()}:${u.origin}${u.pathname}${u.search}`;
  } catch {
    return `${method.toUpperCase()}:${url}`;
  }
}

function isParameterised(url: string): boolean {
  try {
    const u = new URL(url);
    return u.searchParams.size > 0 || /\/\d+(?:\/|$)/.test(u.pathname);
  } catch {
    return false;
  }
}
