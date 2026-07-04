// AI tool: managed browser drive — Mode + Context gated browser actions.
// Allows the AI agent to drive the in-app managed browser session under
// strict scope and mode controls.
// Adapted from source-reference/vantix/agent_skills/ (snapshot 2026-05-26).
// No external npm dependencies.

export type BrowserAction =
  | { type: 'click'; selector: string }
  | { type: 'type'; selector: string; text: string }
  | { type: 'evaluate'; expression: string }
  | { type: 'screenshot' }
  | { type: 'navigate'; url: string };

export interface BrowserDriveRequest {
  projectId: string;
  sessionId: string;
  action: BrowserAction;
  /** URL context must be in-scope for the action to be allowed. */
  currentUrl: string;
  inScopeUrls: string[];
}

export interface BrowserDriveResult {
  allowed: boolean;
  actionType: string;
  output?: unknown;
  refusalReason?: string;
}

const DANGEROUS_EXPRESSIONS = [
  /process\./,
  /require\(/,
  /import\(/,
  /fs\./,
  /child_process/,
];

/** Returns a refusal reason if the action is blocked, or null if allowed. */
export function validateBrowserAction(
  action: BrowserAction,
  currentUrl: string,
  inScopeUrls: string[],
  mode: string,
): string | null {
  if (mode === 'safe') {
    return 'Browser drive is not available in Safe mode.';
  }

  // Check scope for navigate actions
  if (action.type === 'navigate') {
    const inScope = inScopeUrls.some((pattern) => action.url.startsWith(pattern));
    if (!inScope) {
      return `Navigation to "${action.url}" is out of scope.`;
    }
  }

  // Current page must be in scope
  if (currentUrl) {
    const currentInScope = inScopeUrls.length === 0 || inScopeUrls.some((p) => currentUrl.startsWith(p));
    if (!currentInScope) {
      return `Current page "${currentUrl}" is out of scope. Browser drive refused.`;
    }
  }

  // Block dangerous JS evaluation
  if (action.type === 'evaluate') {
    for (const pattern of DANGEROUS_EXPRESSIONS) {
      if (pattern.test(action.expression)) {
        return `Evaluate expression contains blocked pattern (${pattern}). Access to Node.js APIs from AI agent is not permitted.`;
      }
    }
  }

  return null;
}

/**
 * Executes a browser action on the managed browser session.
 * In production this calls the electron IPC bridge to the running browser
 * worker; in CI/tests this returns a stub result.
 */
export async function executeBrowserAction(
  request: BrowserDriveRequest,
  mode: string,
): Promise<BrowserDriveResult> {
  const refusal = validateBrowserAction(
    request.action,
    request.currentUrl,
    request.inScopeUrls,
    mode,
  );

  if (refusal) {
    return { allowed: false, actionType: request.action.type, refusalReason: refusal };
  }

  // Stub: production implementation calls electron IPC bridge.
  return {
    allowed: true,
    actionType: request.action.type,
    output: null,
  };
}
