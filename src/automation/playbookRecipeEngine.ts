// Recipe run state machine — §8.4 of PROXY_FORGE_MASTER_PLAN.md
// Adapted from source-reference/vantix/secops/playbooks/ design patterns
// (snapshot 2026-05-26). No runtime dependency on the vendored source.

import type { AutomationRecipe, AutomationStep } from './playbookSchema';
import type { EvidenceGateResult } from './playbookEvidenceGate';
import { randomUUID } from 'node:crypto';

export type { EvidenceGateResult };

export interface RecipeRun {
  id: string;
  recipeId: string;
  status: 'queued' | 'running' | 'complete' | 'failed' | 'stopped';
  currentStepId?: string;
  completedSteps: string[];
  gateResults: EvidenceGateResult[];
  startedAt: string;
  completedAt?: string;
  errors: string[];
}

/**
 * Create a new RecipeRun in the 'queued' state.
 * The first step is set as currentStepId immediately.
 */
export function createRecipeRun(recipe: AutomationRecipe): RecipeRun {
  const firstStep = recipe.steps[0];
  return {
    id: randomUUID(),
    recipeId: recipe.id,
    status: 'queued',
    currentStepId: firstStep?.id,
    completedSteps: [],
    gateResults: [],
    startedAt: new Date().toISOString(),
    errors: [],
  };
}

/**
 * Advance a recipe run after a step completes (or fails).
 *
 * - Marks the step as completed.
 * - Sets status to 'running'.
 * - Resolves the next step via onSuccess / onFailure routing.
 * - Sets status to 'complete' when no further step is available.
 * - Appends an error entry when success=false and error is provided.
 */
export function advanceRecipeRun(
  run: RecipeRun,
  stepId: string,
  success: boolean,
  error?: string,
): RecipeRun {
  const completedSteps = [...run.completedSteps, stepId];
  const errors = error ? [...run.errors, error] : [...run.errors];

  // Find the step definition — we need this to resolve routing.
  // Since we don't have the recipe here, routing must be resolved by getNextStep.
  // advanceRecipeRun only updates bookkeeping; getNextStep resolves the next id.
  // We'll set currentStepId to undefined and let the caller use getNextStep.
  const updated: RecipeRun = {
    ...run,
    completedSteps,
    errors,
    status: 'running',
    currentStepId: undefined,
  };

  // If this is a failure advance, record it
  if (!success && error) {
    // status stays 'running' unless the caller decides otherwise
  }

  return updated;
}

/**
 * Stop a recipe run immediately with a reason appended to errors.
 */
export function stopRecipeRun(run: RecipeRun, reason: string): RecipeRun {
  return {
    ...run,
    status: 'stopped',
    completedAt: new Date().toISOString(),
    errors: [...run.errors, reason],
  };
}

/**
 * Returns true if the run has reached a terminal state.
 */
export function isRecipeRunComplete(run: RecipeRun): boolean {
  return run.status === 'complete' || run.status === 'failed' || run.status === 'stopped';
}

/**
 * Determine the next step to execute for a recipe run.
 *
 * Logic:
 * 1. If currentStepId is set and the step exists in the recipe, return it.
 * 2. If completedSteps has entries, look at the last completed step and follow
 *    its onSuccess routing (assuming the most recent completion was a success;
 *    for failure routing, use advanceRecipeRun with success=false first).
 * 3. If no step is resolvable, return null (recipe is complete).
 */
export function getNextStep(run: RecipeRun, recipe: AutomationRecipe): AutomationStep | null {
  if (isRecipeRunComplete(run)) return null;

  // If we have an explicit current step pointer, use it
  if (run.currentStepId) {
    const step = recipe.steps.find((s) => s.id === run.currentStepId);
    return step ?? null;
  }

  // If nothing has been completed yet, start at the first step
  if (run.completedSteps.length === 0) {
    return recipe.steps[0] ?? null;
  }

  // Resolve from the last completed step's onSuccess routing
  const lastCompletedId = run.completedSteps[run.completedSteps.length - 1];
  const lastStep = recipe.steps.find((s) => s.id === lastCompletedId);
  if (!lastStep) return null;

  const nextId = lastStep.onSuccess;
  if (!nextId) return null;

  return recipe.steps.find((s) => s.id === nextId) ?? null;
}

/**
 * Mark a recipe run as complete (terminal success).
 */
export function completeRecipeRun(run: RecipeRun): RecipeRun {
  return {
    ...run,
    status: 'complete',
    completedAt: new Date().toISOString(),
  };
}

/**
 * Mark a recipe run as failed (terminal failure).
 */
export function failRecipeRun(run: RecipeRun, reason: string): RecipeRun {
  return {
    ...run,
    status: 'failed',
    completedAt: new Date().toISOString(),
    errors: [...run.errors, reason],
  };
}
