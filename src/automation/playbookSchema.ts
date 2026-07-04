// Automation recipe schema — §8.4 of PROXY_FORGE_MASTER_PLAN.md
// Adapted from source-reference/vantix/secops/playbooks/ design patterns
// (snapshot 2026-05-26). No runtime dependency on the vendored source.

export interface AutomationStep {
  id: string;
  type: 'scan' | 'repeater' | 'intruder' | 'oast' | 'export' | 'assert' | 'branch';
  label: string;
  config: Record<string, unknown>;
  onSuccess?: string;
  onFailure?: string;
}

export interface EvidenceGate {
  id: string;
  checkId?: string;
  requiredClass: string;
  minConfidence: number;
  required: boolean;
}

export interface AutomationRecipe {
  id: string;
  name: string;
  summary: string;
  requiredInputs: string[];
  steps: AutomationStep[];
  evidenceGates: EvidenceGate[];
  stopConditions: string[];
  defaultBudgets: {
    maxRequests: number;
    maxRuntimeMs: number;
    maxPayloadsPerInsertionPoint: number;
  };
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

function isNonEmptyString(val: unknown): boolean {
  return typeof val === 'string' && val.trim().length > 0;
}

function isRecord(val: unknown): val is Record<string, unknown> {
  return typeof val === 'object' && val !== null && !Array.isArray(val);
}

const VALID_STEP_TYPES = new Set(['scan', 'repeater', 'intruder', 'oast', 'export', 'assert', 'branch']);

function validateStep(step: unknown, index: number): string[] {
  const errs: string[] = [];
  if (!isRecord(step)) {
    errs.push(`steps[${index}] is not an object`);
    return errs;
  }
  if (!isNonEmptyString(step['id'])) errs.push(`steps[${index}].id is missing or empty`);
  if (!VALID_STEP_TYPES.has(step['type'] as string)) {
    errs.push(`steps[${index}].type "${step['type']}" is not a valid AutomationStep type`);
  }
  if (!isNonEmptyString(step['label'])) errs.push(`steps[${index}].label is missing or empty`);
  if (!isRecord(step['config'])) errs.push(`steps[${index}].config must be an object`);
  return errs;
}

function validateGate(gate: unknown, index: number): string[] {
  const errs: string[] = [];
  if (!isRecord(gate)) {
    errs.push(`evidenceGates[${index}] is not an object`);
    return errs;
  }
  if (!isNonEmptyString(gate['id'])) errs.push(`evidenceGates[${index}].id is missing or empty`);
  if (!isNonEmptyString(gate['requiredClass'])) errs.push(`evidenceGates[${index}].requiredClass is missing or empty`);
  if (typeof gate['minConfidence'] !== 'number') errs.push(`evidenceGates[${index}].minConfidence must be a number`);
  if (typeof gate['required'] !== 'boolean') errs.push(`evidenceGates[${index}].required must be a boolean`);
  return errs;
}

function validateBudgets(budgets: unknown): string[] {
  const errs: string[] = [];
  if (!isRecord(budgets)) {
    errs.push('defaultBudgets must be an object');
    return errs;
  }
  if (typeof budgets['maxRequests'] !== 'number') errs.push('defaultBudgets.maxRequests must be a number');
  if (typeof budgets['maxRuntimeMs'] !== 'number') errs.push('defaultBudgets.maxRuntimeMs must be a number');
  if (typeof budgets['maxPayloadsPerInsertionPoint'] !== 'number') {
    errs.push('defaultBudgets.maxPayloadsPerInsertionPoint must be a number');
  }
  return errs;
}

/**
 * Validate an unknown value as an AutomationRecipe.
 * Returns { valid, errors } — errors is empty when valid.
 */
export function validateRecipe(recipe: unknown): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (!isRecord(recipe)) {
    return { valid: false, errors: ['recipe must be a non-null object'] };
  }

  if (!isNonEmptyString(recipe['id'])) errors.push('id is missing or empty');
  if (!isNonEmptyString(recipe['name'])) errors.push('name is missing or empty');
  if (!isNonEmptyString(recipe['summary'])) errors.push('summary is missing or empty');

  if (!Array.isArray(recipe['requiredInputs'])) {
    errors.push('requiredInputs must be an array');
  }

  if (!Array.isArray(recipe['steps'])) {
    errors.push('steps must be an array');
  } else if ((recipe['steps'] as unknown[]).length === 0) {
    errors.push('steps must not be empty');
  } else {
    (recipe['steps'] as unknown[]).forEach((step, i) => {
      errors.push(...validateStep(step, i));
    });
  }

  if (!Array.isArray(recipe['evidenceGates'])) {
    errors.push('evidenceGates must be an array');
  } else {
    (recipe['evidenceGates'] as unknown[]).forEach((gate, i) => {
      errors.push(...validateGate(gate, i));
    });
  }

  if (!Array.isArray(recipe['stopConditions'])) {
    errors.push('stopConditions must be an array');
  }

  errors.push(...validateBudgets(recipe['defaultBudgets']));

  return { valid: errors.length === 0, errors };
}

/**
 * Parse a JSON string into an AutomationRecipe. Throws on invalid JSON or
 * if the parsed object does not pass validateRecipe.
 */
export function parseRecipeJson(json: string): AutomationRecipe {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch (err) {
    throw new Error(`Invalid JSON: ${(err as Error).message}`);
  }
  const { valid, errors } = validateRecipe(parsed);
  if (!valid) {
    throw new Error(`Invalid AutomationRecipe: ${errors.join('; ')}`);
  }
  return parsed as AutomationRecipe;
}

/**
 * Serialize an AutomationRecipe to a canonical JSON string.
 */
export function serializeRecipe(recipe: AutomationRecipe): string {
  return JSON.stringify(recipe, null, 2);
}
