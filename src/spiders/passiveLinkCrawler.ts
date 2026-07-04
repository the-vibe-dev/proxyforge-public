// Passive link crawler — extracts links from captured traffic without driving a browser.
// Refactored out of crawlEngine.ts as a standalone module per §6.6b.

export interface CrawledLink {
  url: string;
  foundIn: string;
  via: 'href' | 'src' | 'action' | 'location-header' | 'meta-refresh' | 'script-literal' | 'css-url' | 'js-fetch';
  depth: number;
  method?: string;
}

export interface PassiveCrawlerConfig {
  startUrls: string[];
  maxDepth?: number;
  includeOrigins?: string[];
  excludePatterns?: string[];
  maxLinksPerPage?: number;
}

export interface PassiveCrawlerState {
  links: Map<string, CrawledLink>;
  queue: Array<{ url: string; depth: number }>;
  visited: Set<string>;
}

const NON_NAV = /^(?:javascript:|mailto:|tel:|data:|#$|blob:)/i;

export function createPassiveCrawler(config: PassiveCrawlerConfig): PassiveCrawlerState {
  const state: PassiveCrawlerState = {
    links: new Map(),
    queue: config.startUrls.map((url) => ({ url, depth: 0 })),
    visited: new Set(),
  };
  return state;
}

export function extractLinksFromHtml(
  html: string,
  baseUrl: string,
  depth: number,
  maxLinks = 500
): CrawledLink[] {
  const links: CrawledLink[] = [];
  const seen = new Set<string>();

  function add(raw: string, via: CrawledLink['via'], method?: string) {
    if (!raw || NON_NAV.test(raw.trim())) return;
    try {
      const resolved = new URL(raw.trim(), baseUrl).href;
      if (seen.has(resolved)) return;
      if (links.length >= maxLinks) return;
      seen.add(resolved);
      links.push({ url: resolved, foundIn: baseUrl, via, depth, method });
    } catch {
      // invalid URL
    }
  }

  // <a href>
  for (const m of html.matchAll(/\bhref=["']([^"']+)["']/gi)) add(m[1], 'href');

  // <form action>
  for (const m of html.matchAll(/\baction=["']([^"']+)["']/gi)) add(m[1], 'action', 'POST');

  // <script src>, <img src>, <iframe src>
  for (const m of html.matchAll(/\bsrc=["']([^"']+)["']/gi)) add(m[1], 'src');

  // <meta http-equiv="refresh" content="0;url=...">
  for (const m of html.matchAll(/content=["'][^"']*url=([^"';]+)/gi)) add(m[1], 'meta-refresh');

  // CSS url()
  for (const m of html.matchAll(/url\(['"]?([^'"\)]+)['"]?\)/gi)) add(m[1], 'css-url');

  // Simple fetch/XMLHttpRequest URL literals in script blocks
  for (const m of html.matchAll(/fetch\(['"]([^'"]+)['"]/gi)) add(m[1], 'js-fetch');
  for (const m of html.matchAll(/\.open\(['"][A-Z]+['"],\s*['"]([^'"]+)['"]/gi)) add(m[1], 'js-fetch', m[0].match(/['"]([A-Z]+)['"]/)?.[1]);

  return links;
}

export function extractLinksFromHeaders(
  headers: Record<string, string>,
  baseUrl: string,
  depth: number
): CrawledLink[] {
  const links: CrawledLink[] = [];

  const location = headers['location'] ?? headers['Location'];
  if (location) {
    try {
      links.push({ url: new URL(location, baseUrl).href, foundIn: baseUrl, via: 'location-header', depth });
    } catch { /* invalid */ }
  }

  return links;
}

export function addLinks(state: PassiveCrawlerState, newLinks: CrawledLink[], maxDepth = 3): void {
  for (const link of newLinks) {
    if (state.links.has(link.url)) continue;
    state.links.set(link.url, link);
    if (link.depth < maxDepth && !state.visited.has(link.url)) {
      state.queue.push({ url: link.url, depth: link.depth + 1 });
    }
  }
}

export function dequeue(state: PassiveCrawlerState): { url: string; depth: number } | undefined {
  while (state.queue.length > 0) {
    const item = state.queue.shift()!;
    if (!state.visited.has(item.url)) {
      state.visited.add(item.url);
      return item;
    }
  }
  return undefined;
}

export function getLinksSummary(state: PassiveCrawlerState): { total: number; visited: number; queued: number } {
  return {
    total: state.links.size,
    visited: state.visited.size,
    queued: state.queue.length,
  };
}

export function filterByOrigin(state: PassiveCrawlerState, origins: string[]): CrawledLink[] {
  if (origins.length === 0) return [...state.links.values()];
  const set = new Set(origins);
  return [...state.links.values()].filter((l) => {
    try { return set.has(new URL(l.url).origin); } catch { return false; }
  });
}
