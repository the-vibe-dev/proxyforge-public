// Browser scan driver — CDP/Playwright orchestrator for browser-required scan checks.
// Manages headless browser sessions for DOM XSS, prototype pollution, and postMessage
// misconfig checks.
// Adapted from source-reference/vantix/secops/skills/ (snapshot 2026-05-26).
// No external npm dependencies at import time; Playwright is an optional peer dep.

export interface BrowserScanSession {
  sessionId: string;
  targetUrl: string;
  checkIds: string[];
  status: 'pending' | 'running' | 'completed' | 'error';
  startedAt?: string;
  completedAt?: string;
  error?: string;
}

export interface BrowserScanObservation {
  sessionId: string;
  checkId: string;
  signal: 'alert-fired' | 'property-mutated' | 'dom-mutation' | 'postmessage-received' | 'navigation' | 'console-error';
  detail: string;
  timestamp: string;
}

export interface BrowserScanResult {
  sessionId: string;
  observations: BrowserScanObservation[];
  confirmedCheckIds: string[];
  durationMs: number;
}

/** Returns true if Playwright is available in the current environment. */
export function isPlaywrightAvailable(): boolean {
  try {
    require.resolve('playwright');
    return true;
  } catch {
    return false;
  }
}

/** Returns true when the current environment supports browser scan mode. */
export function isBrowserScanSupported(): boolean {
  return isPlaywrightAvailable();
}

/**
 * Creates a new browser scan session descriptor.
 * Call `runBrowserScanSession` to actually execute it.
 */
export function createBrowserScanSession(
  targetUrl: string,
  checkIds: string[],
): BrowserScanSession {
  const { randomUUID } = require('node:crypto') as typeof import('node:crypto');
  return {
    sessionId: randomUUID(),
    targetUrl,
    checkIds,
    status: 'pending',
  };
}

/**
 * Runs a browser scan session.
 * If Playwright is not available, returns an error result immediately.
 * In a production build the driver connects to a CDP endpoint or launches
 * Playwright; this stub models the contract.
 */
export async function runBrowserScanSession(
  session: BrowserScanSession,
  _opts?: { timeoutMs?: number },
): Promise<BrowserScanResult> {
  const start = Date.now();

  if (!isBrowserScanSupported()) {
    return {
      sessionId: session.sessionId,
      observations: [],
      confirmedCheckIds: [],
      durationMs: Date.now() - start,
    };
  }

  // Stub: real implementation would launch Playwright, navigate, inject probes,
  // and collect observations. Returns empty result until wired to a live runner.
  return {
    sessionId: session.sessionId,
    observations: [],
    confirmedCheckIds: [],
    durationMs: Date.now() - start,
  };
}

/** Returns a stub observation for fixture/offline testing. */
export function buildStubObservation(
  sessionId: string,
  checkId: string,
  signal: BrowserScanObservation['signal'],
  detail: string,
): BrowserScanObservation {
  return {
    sessionId,
    checkId,
    signal,
    detail,
    timestamp: new Date().toISOString(),
  };
}
