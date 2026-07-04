// Adapted from source-reference/vantix/secops/skills/ design patterns
// (snapshot 2026-05-26). Rewritten in TypeScript with Proxy Forge naming, types,
// and storage model. No runtime dependency on the vendored source.

import type { PayloadFamily } from './types';
import data from '../data/scannerSkilllets.json';

// §8.2 ScannerSkilllet metadata shape
export interface ScannerSkilllet {
  id: string;
  checkIds: string[];
  family: PayloadFamily;
  surfaceTypes: string[];
  triggerFacts: string[];
  summary: string;
  operatorGuidance: string[];
  allowedFollowups: string[];
  forbiddenBranches: string[];
  expectedProof: string[];
  defaultRisk: 'safe' | 'low' | 'medium' | 'high';
}

// Internal JSON shape (checkId-keyed rather than id-keyed)
interface RawSkillletEntry {
  checkId: string;
  family: string;
  surfaceTypes: string[];
  triggerFacts: string[];
  summary: string;
  operatorGuidance: string[];
  allowedFollowups: string[];
  forbiddenBranches: string[];
  expectedProof: string[];
  defaultRisk: string;
}

function normalise(raw: RawSkillletEntry): ScannerSkilllet {
  return {
    id: raw.checkId,
    checkIds: [raw.checkId],
    family: raw.family as PayloadFamily,
    surfaceTypes: raw.surfaceTypes,
    triggerFacts: raw.triggerFacts,
    summary: raw.summary,
    operatorGuidance: raw.operatorGuidance,
    allowedFollowups: raw.allowedFollowups,
    forbiddenBranches: raw.forbiddenBranches,
    expectedProof: raw.expectedProof,
    defaultRisk: raw.defaultRisk as ScannerSkilllet['defaultRisk'],
  };
}

let _cache: ScannerSkilllet[] | null = null;

/**
 * Return all skilllet entries from scannerSkilllets.json.
 */
export function loadSkilllets(): ScannerSkilllet[] {
  if (_cache) return _cache;
  _cache = (data as RawSkillletEntry[]).map(normalise);
  return _cache;
}

/**
 * Look up a single skilllet by its primary check ID.
 * Returns null if not found.
 */
export function getSkilllet(checkId: string): ScannerSkilllet | null {
  return loadSkilllets().find((s) => s.id === checkId || s.checkIds.includes(checkId)) ?? null;
}

/**
 * Return all skilllets belonging to a given payload family.
 */
export function getSkillletsByFamily(family: string): ScannerSkilllet[] {
  return loadSkilllets().filter((s) => s.family === family);
}

/**
 * Return the list of all primary check IDs defined in the metadata file.
 */
export function getAllCheckIds(): string[] {
  return loadSkilllets().map((s) => s.id);
}

const REQUIRED_ARRAY_FIELDS: (keyof ScannerSkilllet)[] = [
  'expectedProof',
  'operatorGuidance',
  'triggerFacts',
  'surfaceTypes',
  'checkIds',
];

const REQUIRED_STRING_FIELDS: (keyof ScannerSkilllet)[] = [
  'id',
  'summary',
  'family',
  'defaultRisk',
];

const VALID_RISK_VALUES = new Set<string>(['safe', 'low', 'medium', 'high']);

/**
 * Validate a skilllet for completeness and return a list of error messages.
 * An empty array means the skilllet is valid.
 */
export function validateSkillletCompleteness(skilllet: ScannerSkilllet): string[] {
  const errors: string[] = [];

  for (const field of REQUIRED_STRING_FIELDS) {
    const val = skilllet[field];
    if (!val || typeof val !== 'string' || (val as string).trim() === '') {
      errors.push(`Missing or empty required string field: ${field}`);
    }
  }

  for (const field of REQUIRED_ARRAY_FIELDS) {
    const val = skilllet[field];
    if (!Array.isArray(val) || (val as unknown[]).length === 0) {
      errors.push(`Missing or empty required array field: ${field}`);
    }
  }

  if (!VALID_RISK_VALUES.has(skilllet.defaultRisk)) {
    errors.push(`Invalid defaultRisk value: "${skilllet.defaultRisk}". Must be one of: safe, low, medium, high`);
  }

  return errors;
}
