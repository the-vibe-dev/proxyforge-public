// Script-based authentication module.
// Runs a user-authored authentication script (for SSO, multi-step login,
// or any flow that cannot be modelled by a static method).
// Scripts receive a typed context and return session data.
// No external npm dependencies.
// Adapted from source-reference/vantix/secops/verify/ (snapshot 2026-05-26).

import type { AuthResult } from './index';

/** Context passed to a user-authored auth script. */
export interface ScriptAuthContext {
  targetUrl: string;
  credentials: Record<string, string>;
  /** Project-scoped key-value store scripts can read/write per invocation. */
  store: Record<string, string>;
}

/** Return type the script must resolve to. */
export interface ScriptAuthResult {
  success: boolean;
  sessionData?: Record<string, string>;
  error?: string;
  /** Updated store values to persist for the next invocation. */
  updatedStore?: Record<string, string>;
}

export interface ScriptAuthConfig {
  /** Inline JS source of the auth script. Must export an async function `run(ctx)`. */
  scriptSource: string;
  targetUrl: string;
}

export interface ScriptAuthCredentials {
  credentials: Record<string, string>;
  store?: Record<string, string>;
}

/**
 * Runs a user-authored auth script in a restricted eval context.
 * The script source must export (or define) an async function named `run`
 * that accepts a `ScriptAuthContext` and returns a `ScriptAuthResult`.
 */
export async function performScriptAuth(
  config: ScriptAuthConfig,
  creds: ScriptAuthCredentials,
): Promise<AuthResult> {
  const ctx: ScriptAuthContext = {
    targetUrl: config.targetUrl,
    credentials: creds.credentials,
    store: { ...(creds.store ?? {}) },
  };

  let run: ((ctx: ScriptAuthContext) => Promise<ScriptAuthResult>) | undefined;

  try {
    // Wrap the source in a module-style IIFE that exposes `run`
    const wrapper = new Function(
      'module', 'exports', 'require',
      `"use strict";\n${config.scriptSource}\nif (typeof run !== 'undefined') module.exports = run;`,
    );
    const mod: { exports: unknown } = { exports: {} };
    wrapper(mod, mod.exports, () => { throw new Error('require() not available in auth scripts.'); });
    if (typeof mod.exports === 'function') {
      run = mod.exports as (ctx: ScriptAuthContext) => Promise<ScriptAuthResult>;
    }
  } catch (err) {
    return { success: false, error: `Script parse error: ${String(err)}` };
  }

  if (!run) {
    return { success: false, error: 'Auth script must define an async function named `run`.' };
  }

  try {
    const result = await run(ctx);
    return {
      success: result.success,
      sessionData: result.sessionData,
      error: result.error,
    };
  } catch (err) {
    return { success: false, error: `Script execution error: ${String(err)}` };
  }
}
