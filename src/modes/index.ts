// Global Mode guard — controls whether active probing is allowed.
// A single process-wide mode setting protects against accidental out-of-scope
// active scanning.
// No external dependencies.

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Global operating mode:
 *
 *  safe      — Passive observation only.  No active probes sent, ever.
 *  protected — Active probes allowed only to explicitly in-scope URLs.
 *  standard  — Active probes allowed to in-scope URLs (default behaviour).
 *  attack    — Active probes allowed; out-of-scope URLs may be explicitly
 *              approved via the scopeAllowlist override.
 */
export type GlobalMode = 'safe' | 'protected' | 'standard' | 'attack';

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

let currentMode: GlobalMode = 'standard';

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function setGlobalMode(mode: GlobalMode): void {
  currentMode = mode;
}

export function getGlobalMode(): GlobalMode {
  return currentMode;
}

export function isSafeMode(): boolean {
  return currentMode === 'safe';
}

/**
 * Determines whether an active probe to `url` is permitted given the current
 * global mode and the project's scope allowlist.
 *
 * @param url             The target URL for the probe
 * @param scopeAllowlist  Project scope patterns (same format as contextEngine)
 * @param mode            Override — defaults to the current global mode
 */
export function isActiveProbeAllowed(
  url: string,
  scopeAllowlist: string[],
  mode?: GlobalMode,
): boolean {
  const effective = mode ?? currentMode;

  switch (effective) {
    case 'safe':
      // Safe mode: no active probes, period
      return false;

    case 'protected':
    case 'standard': {
      // Allowed only if the URL matches at least one scope pattern
      if (scopeAllowlist.length === 0) return false;
      return scopeAllowlist.some((pattern) => urlMatchesPattern(url, pattern));
    }

    case 'attack': {
      // Attack mode: in-scope URLs are always allowed.
      // Out-of-scope URLs require explicit scope pattern inclusion — callers
      // must add the URL to scopeAllowlist to approve it.
      return scopeAllowlist.some((pattern) => urlMatchesPattern(url, pattern));
    }

    default:
      return false;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function urlMatchesPattern(url: string, pattern: string): boolean {
  if (pattern.startsWith('^')) {
    try {
      return new RegExp(pattern).test(url);
    } catch {
      return false;
    }
  }
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.');
  try {
    return new RegExp(`^${escaped}`).test(url);
  } catch {
    return false;
  }
}
