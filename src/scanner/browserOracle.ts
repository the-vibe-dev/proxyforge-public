// Browser oracle — scanner ↔ browser worker contract.
// Classifies PageScanObservations against expected signals and formats evidence
// for the finding builder.

export interface BrowserObservation {
  type: string;
  value?: string;
  timestamp?: number;
}

export interface BrowserPayload {
  payload: string;
  family?: string;
  variantId?: string;
}

export interface BrowserOracleResult {
  matched: boolean;
  matchedPayloads: string[];
  evidence: string[];
  canaryMatched: boolean;
}

/**
 * Classifies a list of observations against an array of payloads.
 * Returns null when observations is empty, otherwise an object describing matches.
 */
export function classifyBrowserObservations(
  observations: BrowserObservation[],
  payloads: BrowserPayload[],
): BrowserOracleResult | null {
  if (observations.length === 0) return null;

  const matchedPayloads: string[] = [];
  const evidence: string[] = [];
  let canaryMatched = false;

  for (const obs of observations) {
    const haystack = [obs.type, obs.value ?? ''].join(' ').toLowerCase();
    for (const { payload } of payloads) {
      if (haystack.includes(payload.toLowerCase())) {
        matchedPayloads.push(payload);
        evidence.push(`[${obs.type}] payload="${payload}" value=${JSON.stringify(obs.value ?? '')}`);
        canaryMatched = true;
        break;
      }
    }
  }

  return {
    matched: matchedPayloads.length > 0,
    matchedPayloads,
    evidence,
    canaryMatched,
  };
}

/**
 * Formats browser oracle observations into a human-readable evidence string.
 */
export function buildBrowserFindingEvidence(
  observations: BrowserObservation[],
  canaryPayload: string,
  insertionPoint: string,
): string {
  const lines: string[] = [
    `Browser oracle: canary="${canaryPayload}" insertion="${insertionPoint}"`,
  ];

  for (const obs of observations) {
    const matched = (obs.value ?? '').toLowerCase().includes(canaryPayload.toLowerCase())
      || obs.type.toLowerCase().includes(canaryPayload.toLowerCase());
    lines.push(`  [${obs.type}] value=${JSON.stringify(obs.value ?? '')}${matched ? ' ← canary match' : ''}`);
  }

  if (observations.length === 0) {
    lines.push('  (no observations recorded)');
  }

  return lines.join('\n');
}
