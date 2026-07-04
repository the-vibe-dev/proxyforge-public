// Evidence gate evaluator — §8.4 of PROXY_FORGE_MASTER_PLAN.md
// Adapted from source-reference/vantix/secops/playbooks/ design patterns
// (snapshot 2026-05-26). No runtime dependency on the vendored source.

import type { EvidenceGate } from './playbookSchema';

export type { EvidenceGate };

export interface EvidenceGateResult {
  gateId: string;
  passed: boolean;
  reason: string;
  observedClass?: string;
  observedConfidence?: number;
}

export interface GateObservation {
  responseClass: string;
  confidence: number;
  checkId?: string;
}

/**
 * Evaluate a single evidence gate against a set of observations.
 *
 * The gate passes if at least one observation:
 *   1. Matches the required response class.
 *   2. Meets or exceeds the minimum confidence threshold.
 *   3. (If checkId is specified on the gate) shares the same checkId.
 */
export function evaluateGate(gate: EvidenceGate, observations: GateObservation[]): EvidenceGateResult {
  const candidates = observations.filter((obs) => {
    const classMatch = obs.responseClass === gate.requiredClass;
    const checkMatch = gate.checkId == null || obs.checkId === gate.checkId;
    return classMatch && checkMatch;
  });

  if (candidates.length === 0) {
    return {
      gateId: gate.id,
      passed: false,
      reason: gate.checkId
        ? `No observation matched requiredClass "${gate.requiredClass}" for checkId "${gate.checkId}"`
        : `No observation matched requiredClass "${gate.requiredClass}"`,
    };
  }

  // Pick the highest-confidence matching candidate.
  const best = candidates.reduce((a, b) => (a.confidence >= b.confidence ? a : b));

  if (best.confidence < gate.minConfidence) {
    return {
      gateId: gate.id,
      passed: false,
      reason: `Best confidence ${best.confidence} is below required ${gate.minConfidence} for class "${gate.requiredClass}"`,
      observedClass: best.responseClass,
      observedConfidence: best.confidence,
    };
  }

  return {
    gateId: gate.id,
    passed: true,
    reason: `Observation matched class "${gate.requiredClass}" with confidence ${best.confidence}`,
    observedClass: best.responseClass,
    observedConfidence: best.confidence,
  };
}

/**
 * Evaluate all gates against the observation set and return one result per gate.
 */
export function evaluateAllGates(gates: EvidenceGate[], observations: GateObservation[]): EvidenceGateResult[] {
  return gates.map((gate) => evaluateGate(gate, observations));
}

/**
 * Returns true only if every gate marked as required has passed.
 * Optional gates (required: false) do not block the overall verdict.
 */
export function allRequiredGatesPassed(results: EvidenceGateResult[]): boolean {
  // We need the gate definitions to know which are required.
  // Since we only have results here, EvidenceGateResult.passed covers the outcome.
  // The caller must filter by required gates before passing to this function, or
  // we rely on the convention that only required gates are included in results when
  // this function is used for the final pass/fail check.
  //
  // To keep the signature clean: this function checks ALL results passed.
  // For mixed required/optional sets, use evaluateAllGates + filter externally.
  return results.every((r) => r.passed);
}

/**
 * Evaluate all gates and return whether all required gates passed.
 * This is a convenience wrapper that handles filtering by required flag.
 */
export function checkAllRequiredGates(
  gates: EvidenceGate[],
  observations: GateObservation[],
): boolean {
  const results = evaluateAllGates(gates, observations);
  const requiredResults = gates
    .map((gate, i) => ({ gate, result: results[i] }))
    .filter(({ gate }) => gate.required)
    .map(({ result }) => result);
  return requiredResults.every((r) => r.passed);
}
