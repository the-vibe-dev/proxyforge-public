import { createRequire } from 'node:module';
import path from 'node:path';
import fs from 'node:fs';

// ---------------------------------------------------------------------------
// Interfaces
// ---------------------------------------------------------------------------

export interface ContentDiscoveryConfig {
  baseUrl: string;
  wordlist?: string[];
  maxPaths?: number;
  throttleMs?: number;
  followRedirects?: boolean;
  expectedNotFoundStatus?: number;
  expectedNotFoundBodyPattern?: string;
}

export interface DiscoveredPath {
  path: string;
  status: number;
  contentType?: string;
  bodySize?: number;
  interesting: boolean;
}

export interface ContentDiscoveryRun {
  id: string;
  baseUrl: string;
  status: 'running' | 'complete' | 'error';
  discovered: DiscoveredPath[];
  probed: number;
  total: number;
  startedAt: string;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export function createDiscoveryRun(config: ContentDiscoveryConfig): ContentDiscoveryRun {
  const wordlist = config.wordlist ?? loadWordlist('common-paths');
  const total = config.maxPaths != null ? Math.min(config.maxPaths, wordlist.length) : wordlist.length;
  return {
    id: `cdisc-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
    baseUrl: config.baseUrl,
    status: 'running',
    discovered: [],
    probed: 0,
    total,
    startedAt: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Result recording
// ---------------------------------------------------------------------------

export function recordDiscoveryResult(
  run: ContentDiscoveryRun,
  path: string,
  status: number,
  contentType?: string,
  bodySize?: number,
): void {
  const notFoundStatus = 404;
  const interesting = isInterestingPath(path, status, notFoundStatus);
  run.discovered.push({ path, status, contentType, bodySize, interesting });
  run.probed += 1;
}

// ---------------------------------------------------------------------------
// Interest classification
// ---------------------------------------------------------------------------

/**
 * Returns true when a probed path is worth flagging:
 * - status differs from the expected-not-found baseline
 * - status is not a 3xx redirect (those are ambiguous noise without follow-through)
 * 403 responses are always interesting because they indicate access control exists.
 */
export function isInterestingPath(path: string, status: number, notFoundStatus: number): boolean {
  if (status === notFoundStatus) return false;
  // Redirect range: 301, 302, 307, 308 – skip unless we specifically care
  if (status >= 300 && status < 400) return false;
  return true;
}

export function getInterestingPaths(run: ContentDiscoveryRun): DiscoveredPath[] {
  return run.discovered.filter((d) => d.interesting);
}

// ---------------------------------------------------------------------------
// Wordlist loader
// ---------------------------------------------------------------------------

export function loadWordlist(name: 'common-paths' | 'common-params' | 'common-headers'): string[] {
  // Support both compiled (dist-electron) and source-tree contexts by resolving
  // relative to this file's location at runtime.
  // In a CommonJS (VM sandbox or compiled) context __dirname is available.
  // In a native ESM context we fall back to process.cwd().
  const fileDir = typeof __dirname !== 'undefined' ? __dirname : process.cwd();

  // Walk up from wherever this module lives to find the project root,
  // then resolve src/data/wordlists/<name>.json
  // The canonical location is src/data/wordlists/ relative to the repo root.
  const candidates = [
    path.resolve(fileDir, '..', 'src', 'data', 'wordlists', `${name}.json`),
    path.resolve(fileDir, 'data', 'wordlists', `${name}.json`),
    path.resolve(fileDir, '..', 'data', 'wordlists', `${name}.json`),
    path.resolve(process.cwd(), 'src', 'data', 'wordlists', `${name}.json`),
  ];

  // Use a createRequire anchored at cwd so JSON files can be required directly.
  const req = createRequire(path.resolve(process.cwd(), 'package.json'));

  for (const candidate of candidates) {
    // First try synchronous fs.readFileSync to avoid require's module cache issues
    // with absolute paths outside the require resolution tree.
    try {
      const raw = fs.readFileSync(candidate, 'utf8');
      const data = JSON.parse(raw);
      if (Array.isArray(data)) return data as string[];
    } catch {
      // try next candidate
    }
  }

  // Last resort: use require with absolute paths
  for (const candidate of candidates) {
    try {
      const data = req(candidate);
      if (Array.isArray(data)) return data as string[];
    } catch {
      // try next candidate
    }
  }

  throw new Error(`loadWordlist: could not locate wordlist "${name}.json" in any of: ${candidates.join(', ')}`);
}
