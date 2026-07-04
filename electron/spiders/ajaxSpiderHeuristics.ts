// Button/link/onclick scoring and SPA-route enumeration heuristics.
// Determines which DOM elements are worth clicking and scores likely navigation events.

export interface ClickCandidate {
  selector: string;
  score: number;
  reason: string;
  navigationLikelihood: 'high' | 'medium' | 'low';
}

export interface RouteSignal {
  url: string;
  confidence: number;
  source: 'href' | 'data-attr' | 'onclick' | 'router-attr' | 'history-snapshot';
}

// High-confidence navigation attributes
const NAV_ATTRS = ['href', 'to', 'routerLink', 'data-href', 'data-url', 'data-route', 'action'];

// Penalized patterns (likely non-navigation)
const PENALTY_PATTERNS = [
  /^javascript:void/i,
  /^javascript:;/i,
  /^mailto:/i,
  /^tel:/i,
  /^#$/,
  /^data:/i,
];

export function scoreClickCandidate(
  tagName: string,
  attributes: Record<string, string>,
  text: string
): ClickCandidate {
  let score = 0;
  let reason = '';
  let navigationLikelihood: 'high' | 'medium' | 'low' = 'low';

  // Anchor tags with href
  if (tagName === 'a' && attributes['href']) {
    const href = attributes['href'];
    if (PENALTY_PATTERNS.some((re) => re.test(href))) {
      score -= 10;
      reason = 'non-navigation href';
    } else if (href.startsWith('/') || href.startsWith('http')) {
      score += 30;
      reason = 'absolute/relative href';
      navigationLikelihood = 'high';
    } else if (href.startsWith('#') && href.length > 1) {
      score += 10;
      reason = 'hash fragment nav';
      navigationLikelihood = 'medium';
    }
  }

  // Router-specific attributes
  for (const attr of NAV_ATTRS) {
    if (attr !== 'href' && attributes[attr]) {
      score += 20;
      reason = `${attr} attribute`;
      navigationLikelihood = 'high';
      break;
    }
  }

  // Role-based navigation
  const role = attributes['role'];
  if (role === 'link') { score += 20; reason = 'role=link'; navigationLikelihood = 'high'; }
  if (role === 'button') { score += 10; reason = 'role=button'; navigationLikelihood = 'medium'; }
  if (role === 'menuitem') { score += 15; reason = 'role=menuitem'; navigationLikelihood = 'medium'; }
  if (role === 'tab') { score += 15; reason = 'role=tab'; navigationLikelihood = 'medium'; }

  // Button elements
  if (tagName === 'button') {
    score += 10;
    reason = 'button element';
    if (!navigationLikelihood || navigationLikelihood === 'low') navigationLikelihood = 'medium';

    const type = (attributes['type'] ?? 'button').toLowerCase();
    if (type === 'submit') { score += 5; reason = 'submit button'; }
  }

  // onclick / data-action hints
  if (attributes['onclick']) { score += 8; reason = 'onclick handler'; }
  if (attributes['data-action']) { score += 12; reason = 'data-action attribute'; }

  // Text-based scoring (navigation words boost)
  const navWords = /\b(go|next|back|prev|continue|submit|login|sign in|sign up|navigate|open|view|details?|more|show)\b/i;
  if (navWords.test(text)) { score += 5; }

  // form elements — low value unless explicit nav attrs
  if (tagName === 'form') {
    score += 5;
    reason = reason || 'form element';
    if (!navigationLikelihood || navigationLikelihood === 'low') navigationLikelihood = 'low';
  }

  return {
    selector: buildSelector(tagName, attributes),
    score: Math.max(0, score),
    reason: reason || 'generic interactable',
    navigationLikelihood,
  };
}

function buildSelector(tagName: string, attributes: Record<string, string>): string {
  if (attributes['id']) return `#${CSS.escape(attributes['id'])}`;
  if (attributes['data-testid']) return `[data-testid="${attributes['data-testid']}"]`;
  if (attributes['aria-label']) return `${tagName}[aria-label="${attributes['aria-label']}"]`;
  if (attributes['href']) return `a[href="${attributes['href']}"]`;
  if (attributes['role']) return `${tagName}[role="${attributes['role']}"]`;
  return tagName;
}

// CSS.escape polyfill for Node context
const CSS = {
  escape: (s: string) => s.replace(/[!"#$%&'()*+,.\/:;<=>?@[\\\]^`{|}~]/g, '\\$&'),
};

export function extractRouteSignalsFromHtml(html: string, baseUrl: string): RouteSignal[] {
  const signals: RouteSignal[] = [];
  const seen = new Set<string>();

  function addSignal(url: string, confidence: number, source: RouteSignal['source']) {
    if (!url || seen.has(url)) return;
    seen.add(url);
    try {
      const resolved = new URL(url, baseUrl).href;
      signals.push({ url: resolved, confidence, source });
    } catch {
      // ignore invalid URLs
    }
  }

  // href attributes
  const hrefRe = /\bhref=["']([^"']+)["']/g;
  let m: RegExpExecArray | null;
  while ((m = hrefRe.exec(html)) !== null) {
    const href = m[1];
    if (!PENALTY_PATTERNS.some((re) => re.test(href))) {
      addSignal(href, 0.9, 'href');
    }
  }

  // Router 'to' attributes
  const toRe = /\bto=["']([^"']+)["']/g;
  while ((m = toRe.exec(html)) !== null) {
    addSignal(m[1], 0.85, 'router-attr');
  }

  // data-href / data-url
  const dataRe = /\bdata-(?:href|url)=["']([^"']+)["']/g;
  while ((m = dataRe.exec(html)) !== null) {
    addSignal(m[1], 0.7, 'data-attr');
  }

  // action attributes on forms
  const actionRe = /\baction=["']([^"']+)["']/g;
  while ((m = actionRe.exec(html)) !== null) {
    addSignal(m[1], 0.8, 'href');
  }

  return signals.sort((a, b) => b.confidence - a.confidence);
}

export function rankCandidates(candidates: ClickCandidate[]): ClickCandidate[] {
  return [...candidates].sort((a, b) => b.score - a.score);
}
