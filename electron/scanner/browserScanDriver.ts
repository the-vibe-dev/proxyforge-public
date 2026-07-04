// Browser scan driver — CDP/Playwright orchestrator stub for browser-driven scans.
// Provides the interface contract; actual browser driving requires Playwright at runtime.
// Phase 10 stub: if Playwright is not installed, all scans return an error result.

export interface BrowserScanTarget {
  url: string;
  insertionPoints: string[];
  checkIds: string[];
  maxDurationMs?: number;
}

export interface BrowserScanResult {
  targetUrl: string;
  checkId: string;
  finding?: {
    title: string;
    severity: string;
    evidence: string;
  };
  timingMs: number;
  status: 'complete' | 'timeout' | 'error';
  error?: string;
}

export interface BrowserScanConfig {
  headless?: boolean;
  viewport?: { width: number; height: number };
  timeout?: number;
  userAgent?: string;
}

/**
 * Returns true if Playwright (or playwright-chromium) is installed and importable.
 */
export async function isBrowserAvailable(): Promise<boolean> {
  try {
    require('playwright');
    return true;
  } catch {
    // fall through
  }
  try {
    require('playwright-chromium');
    return true;
  } catch {
    // fall through
  }
  return false;
}

/**
 * Runs a browser-driven scan against the given target.
 * If Playwright is not installed, returns an error result for each check.
 * When Playwright is available this stub returns a complete result with no finding —
 * a full implementation would launch a browser context and execute each check.
 */
export async function runBrowserScan(
  target: BrowserScanTarget,
  config?: BrowserScanConfig,
): Promise<BrowserScanResult> {
  const startMs = Date.now();

  const available = await isBrowserAvailable();
  if (!available) {
    return {
      targetUrl: target.url,
      checkId: target.checkIds[0] ?? 'unknown',
      timingMs: Date.now() - startMs,
      status: 'error',
      error: 'Playwright not installed',
    };
  }

  // Stub: browser is available but full CDP orchestration is not yet implemented.
  // A real implementation would iterate target.checkIds and target.insertionPoints,
  // launch a browser context with the given config, inject payloads, and observe signals.
  const timeout = config?.timeout ?? target.maxDurationMs ?? 30_000;
  void timeout; // will be consumed by the real implementation

  return {
    targetUrl: target.url,
    checkId: target.checkIds[0] ?? 'unknown',
    timingMs: Date.now() - startMs,
    status: 'complete',
  };
}
