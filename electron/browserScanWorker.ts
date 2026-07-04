// Browser scan worker — per-page sandbox that injects probes and collects signals.
// Runs inside a Playwright page context isolated from the main renderer process.
// Adapted from source-reference/vantix/secops/skills/ (snapshot 2026-05-26).
// No external npm dependencies at import time.

export interface WorkerProbeSpec {
  checkId: string;
  /** JS expression injected into the page to trigger the probe. */
  probeExpression: string;
  /** Expected signal type on success. */
  expectedSignal: 'alert-fired' | 'property-mutated' | 'dom-mutation' | 'postmessage-received';
  /** Timeout in ms before the probe is considered non-triggering. */
  timeoutMs: number;
}

export interface WorkerProbeResult {
  checkId: string;
  triggered: boolean;
  signal?: string;
  detail?: string;
  durationMs: number;
}

/**
 * Builds probe specs for DOM XSS detection.
 * The probe injects an alert-canary payload and observes whether the browser
 * fires a dialog event.
 */
export function buildDomXssProbeSpec(insertionPointValue: string): WorkerProbeSpec {
  const canary = `pf_xss_${Date.now()}`;
  return {
    checkId: 'dom-xss',
    probeExpression: `
      (() => {
        const canary = '${canary}';
        const original = window.alert;
        let fired = false;
        window.alert = (msg) => {
          if (String(msg).includes(canary)) fired = true;
          original.call(window, msg);
        };
        try {
          const el = document.createElement('div');
          el.innerHTML = ${JSON.stringify(insertionPointValue)};
          document.body.appendChild(el);
        } catch (_) {}
        return fired;
      })()
    `,
    expectedSignal: 'alert-fired',
    timeoutMs: 3000,
  };
}

/**
 * Builds a probe spec for client-side prototype pollution detection.
 * Injects a pollution payload and checks if Object.prototype is mutated.
 */
export function buildPrototypePollutionProbeSpec(): WorkerProbeSpec {
  return {
    checkId: 'prototype-pollution-client',
    probeExpression: `
      (() => {
        const marker = '__pf_pp_probe__';
        try {
          const url = new URL(location.href);
          url.searchParams.set('__proto__[' + marker + ']', 'injected');
          const params = Object.fromEntries(url.searchParams.entries());
          return (({}) as any)[marker] === 'injected';
        } catch (_) { return false; }
      })()
    `,
    expectedSignal: 'property-mutated',
    timeoutMs: 2000,
  };
}

/**
 * Evaluates a probe spec result in a headless context.
 * In production this runs inside the Playwright page; in tests it
 * evaluates the probeExpression against a JSDOM sandbox.
 */
export function evaluateProbeResult(spec: WorkerProbeSpec, rawResult: unknown): WorkerProbeResult {
  const start = Date.now();
  const triggered = Boolean(rawResult);
  return {
    checkId: spec.checkId,
    triggered,
    signal: triggered ? spec.expectedSignal : undefined,
    detail: triggered ? `Probe triggered: ${spec.checkId}` : undefined,
    durationMs: Date.now() - start,
  };
}
