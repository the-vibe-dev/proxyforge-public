// Manual session pin — captures a browser/proxy session and replays it.
// Used when automated auth flow is too complex; operator pins a live session.
// No external dependencies.

import { randomBytes } from 'node:crypto';

export interface ManualAuthSession {
  id: string;
  label: string;
  /** Cookie header string, e.g. "sessionId=abc; csrf=xyz" */
  cookies: string;
  /** Additional headers to inject, keyed by header name */
  headers: Record<string, string>;
  pinnedAt: string;
  expiresAt?: string;
  notes: string;
}

// ---------------------------------------------------------------------------
// In-process session store
// ---------------------------------------------------------------------------

const sessionStore = new Map<string, ManualAuthSession>();

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Pins a captured session for later replay.
 * Returns the stored session (with a generated id).
 */
export function pinManualSession(
  options: Omit<ManualAuthSession, 'id' | 'pinnedAt'>,
): ManualAuthSession {
  const session: ManualAuthSession = {
    ...options,
    id: randomBytes(8).toString('hex'),
    pinnedAt: new Date().toISOString(),
  };
  sessionStore.set(session.id, session);
  return session;
}

/**
 * Retrieves a pinned session by id.
 */
export function getManualSession(id: string): ManualAuthSession | undefined {
  return sessionStore.get(id);
}

/**
 * Removes a pinned session.
 */
export function unpinManualSession(id: string): boolean {
  return sessionStore.delete(id);
}

/**
 * Lists all pinned sessions.
 */
export function listManualSessions(): ManualAuthSession[] {
  return Array.from(sessionStore.values());
}

/**
 * Applies a pinned session's cookies and headers to a raw HTTP request string.
 * Merges session headers into existing ones; replaces the Cookie header.
 *
 * @param rawRequest  Raw HTTP/1.1 request string
 * @param session     The pinned session to apply
 * @returns           Modified raw HTTP request string
 */
export function applyManualSession(rawRequest: string, session: ManualAuthSession): string {
  const lines = rawRequest.split('\r\n');
  const requestLine = lines[0];
  const bodyIndex = lines.findIndex((l) => l === '');
  const headerLines = lines.slice(1, bodyIndex < 0 ? undefined : bodyIndex);
  const body = bodyIndex >= 0 ? lines.slice(bodyIndex + 1).join('\r\n') : '';

  // Parse existing headers (case-insensitive)
  const existingHeaders: Array<[string, string]> = headerLines.map((l) => {
    const colon = l.indexOf(':');
    if (colon < 0) return [l, ''] as [string, string];
    return [l.slice(0, colon).trim(), l.slice(colon + 1).trim()] as [string, string];
  });

  // Remove any existing Cookie header
  const filteredHeaders = existingHeaders.filter(([k]) => k.toLowerCase() !== 'cookie');

  // Inject session headers (overwrite matching)
  for (const [name, value] of Object.entries(session.headers)) {
    const idx = filteredHeaders.findIndex(([k]) => k.toLowerCase() === name.toLowerCase());
    if (idx >= 0) {
      filteredHeaders[idx] = [name, value];
    } else {
      filteredHeaders.push([name, value]);
    }
  }

  // Add Cookie header if session has cookies
  if (session.cookies.trim()) {
    filteredHeaders.push(['Cookie', session.cookies]);
  }

  const newHeaders = filteredHeaders.map(([k, v]) => `${k}: ${v}`).join('\r\n');
  const parts = [requestLine, newHeaders, ''];
  if (body) parts.push(body);
  return parts.join('\r\n');
}
