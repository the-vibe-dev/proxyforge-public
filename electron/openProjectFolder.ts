// Opens the active project directory in the OS file manager.
// Uses Electron's shell.openPath with a strict whitelist guard to prevent
// arbitrary path navigation outside the application data directory.
// No external npm dependencies.

import path from 'node:path';
import fs from 'node:fs';

/** Returns the Electron app userData path, or a fallback for non-Electron contexts. */
function getAppDataRoot(): string {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { app } = require('electron') as typeof import('electron');
    return app.getPath('userData');
  } catch {
    return process.env['HOME'] ?? '/tmp';
  }
}

export interface OpenFolderResult {
  allowed: boolean;
  resolvedPath?: string;
  reason?: string;
}

/**
 * Validates that `targetPath` is inside the allowed root and exists.
 * Returns a result with `allowed: false` and a `reason` if the path is
 * outside the allowlist or does not exist.
 */
export function validateProjectFolderPath(
  targetPath: string,
  allowedRoot?: string,
): OpenFolderResult {
  const root = allowedRoot ?? getAppDataRoot();
  const resolved = path.resolve(targetPath);
  const resolvedRoot = path.resolve(root);

  if (!resolved.startsWith(resolvedRoot + path.sep) && resolved !== resolvedRoot) {
    return {
      allowed: false,
      reason: `Path "${resolved}" is outside the allowed application data directory.`,
    };
  }

  if (!fs.existsSync(resolved)) {
    return {
      allowed: false,
      reason: `Path "${resolved}" does not exist.`,
    };
  }

  return { allowed: true, resolvedPath: resolved };
}

/**
 * Opens the project folder in the OS file manager.
 * Validates the path against the app data root before opening.
 */
export async function openProjectFolder(
  projectPath: string,
  allowedRoot?: string,
): Promise<OpenFolderResult> {
  const validation = validateProjectFolderPath(projectPath, allowedRoot);
  if (!validation.allowed) {
    return validation;
  }

  try {
    const { shell } = require('electron') as typeof import('electron');
    const error = await shell.openPath(validation.resolvedPath!);
    if (error) {
      return { allowed: true, resolvedPath: validation.resolvedPath, reason: error };
    }
    return { allowed: true, resolvedPath: validation.resolvedPath };
  } catch {
    // Non-Electron context (e.g., tests)
    return { allowed: true, resolvedPath: validation.resolvedPath };
  }
}
