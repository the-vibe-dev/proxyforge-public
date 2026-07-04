// Project snapshot serialization/deserialization for Phase 8.5 schema tables.
// Provides round-trip JSON serialization and validation against the full table set.

import { MIGRATIONS } from './migrations';

/** All table names derived from the migration registry. */
export const EXPECTED_TABLES: readonly string[] = MIGRATIONS.map((m) => m.id);

export interface ProjectSnapshot {
  version: string;
  projectId: string;
  capturedAt: string;
  tables: Record<string, unknown[]>;
}

/**
 * Creates a ProjectSnapshot for the given project and table data.
 * The `capturedAt` timestamp is set to the current UTC ISO string.
 */
export function serializeSnapshot(
  projectId: string,
  tables: Record<string, unknown[]>,
): ProjectSnapshot {
  return {
    version: '1.0.0',
    projectId,
    capturedAt: new Date().toISOString(),
    tables,
  };
}

/**
 * Parses and returns a ProjectSnapshot from a JSON string.
 * Throws if the JSON is invalid or missing required fields.
 */
export function deserializeSnapshot(json: string): ProjectSnapshot {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch (err) {
    throw new Error(`ProjectSnapshot: invalid JSON — ${(err as Error).message}`);
  }

  if (typeof parsed !== 'object' || parsed === null) {
    throw new Error('ProjectSnapshot: root value must be an object');
  }

  const obj = parsed as Record<string, unknown>;

  if (typeof obj.version !== 'string') {
    throw new Error('ProjectSnapshot: missing or invalid "version" field');
  }
  if (typeof obj.projectId !== 'string') {
    throw new Error('ProjectSnapshot: missing or invalid "projectId" field');
  }
  if (typeof obj.capturedAt !== 'string') {
    throw new Error('ProjectSnapshot: missing or invalid "capturedAt" field');
  }
  if (typeof obj.tables !== 'object' || obj.tables === null || Array.isArray(obj.tables)) {
    throw new Error('ProjectSnapshot: missing or invalid "tables" field');
  }

  return {
    version: obj.version,
    projectId: obj.projectId,
    capturedAt: obj.capturedAt,
    tables: obj.tables as Record<string, unknown[]>,
  };
}

export interface SnapshotValidationResult {
  valid: boolean;
  missingTables: string[];
}

/**
 * Validates that a snapshot contains all expected tables.
 * Returns valid: true only when every EXPECTED_TABLES entry is present.
 */
export function validateSnapshot(snapshot: ProjectSnapshot): SnapshotValidationResult {
  const missingTables = EXPECTED_TABLES.filter(
    (name) => !(name in snapshot.tables),
  );
  return {
    valid: missingTables.length === 0,
    missingTables,
  };
}
