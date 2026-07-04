// Active scan runner — orchestrates insertion-point iteration, probe rendering,
// response classification, and evidence persistence.
// Adapted from source-reference/vantix/secops/skills/scanner_coordinator.py.
// No runtime dependency on the vendored source.

import type { SafetyBudget, ScanProbeMatrix } from '../../src/scanner/types';
import type { InsertionPointSpec } from '../../src/scanner/probePlanner';
import { planProbes } from '../../src/scanner/probePlanner';
import { generatePayloadVariants } from '../../src/scanner/payloadMutationEngine';
import { filterVariantsByBudget, buildBudget } from '../../src/scanner/safetyBudget';
import { renderProbeForInsertionPoint } from '../../src/scanner/probeRenderer';
import {
  buildOracleObservation,
  classifyOracleObservation,
  fingerprintResponse,
  shouldPromoteToFinding,
  highestConfidenceClassification,
} from '../../src/scanner/oracleResponseClassifier';
import { createProbeMatrix, recordClassification, markMatrixStopped } from '../../src/scanner/probeMatrix';
import { concludeMatrix } from '../../src/scanner/evidenceMatrix';
import { buildFinding } from '../../src/scanner/findingBuilder';

export interface ActiveScanRunnerConfig {
  projectId: string;
  exchangeId: string;
  rawRequest: string;
  url: string;
  host: string;
  path: string;
  checkIds: string[];
  insertionPoints: InsertionPointSpec[];
  budget?: Partial<SafetyBudget>;
  oastBaseUrl?: string;
  oastToken?: string;
  onProbeComplete?: (matrix: ScanProbeMatrix) => void;
  onFinding?: (finding: ReturnType<typeof buildFinding>) => void;
  replay: (rawRequest: string, url: string) => Promise<{
    statusCode: number;
    headers: Record<string, string>;
    bodyText: string;
    responseTimeMs: number;
  }>;
}

export interface ActiveScanRunnerResult {
  matrices: ScanProbeMatrix[];
  findingCount: number;
  negativeCount: number;
  totalRequests: number;
}

export async function runActiveScan(config: ActiveScanRunnerConfig): Promise<ActiveScanRunnerResult> {
  const budget = buildBudget(config.budget);
  const plans = planProbes(config.insertionPoints, config.checkIds, budget);

  let totalRequests = 0;
  const matrices: ScanProbeMatrix[] = [];
  let findingCount = 0;
  let negativeCount = 0;

  // Parse base request once
  const baseRequest = {
    method: (config.rawRequest.match(/^([A-Z]+)/)?.[1] ?? 'GET'),
    url: config.url,
    headers: {} as Record<string, string>,
    body: '',
  };

  // Take baseline
  let baseline;
  try {
    const baselineResp = await config.replay(config.rawRequest, config.url);
    baseline = fingerprintResponse(baselineResp);
    totalRequests += 1;
  } catch {
    baseline = undefined;
  }

  for (const plan of plans) {
    if (totalRequests >= budget.maxRequests) break;

    const ip = plan.insertionPoint;
    const rawVariants = generatePayloadVariants({
      family: plan.family,
      baseValue: ip.baseValue,
      insertionPointKind: ip.kind,
      oastBaseUrl: config.oastBaseUrl,
      oastToken: config.oastToken,
      maxVariants: budget.maxVariantsPerInsertionPoint,
    });

    const variants = filterVariantsByBudget(rawVariants, budget);
    if (!variants.length) continue;

    let matrix = createProbeMatrix(
      config.projectId,
      config.exchangeId,
      plan.checkId,
      ip.id,
      variants,
    );

    for (const variant of variants) {
      if (totalRequests >= budget.maxRequests) {
        matrix = markMatrixStopped(matrix, 'stopped');
        break;
      }

      if (budget.throttleMs > 0) {
        await new Promise((resolve) => setTimeout(resolve, budget.throttleMs));
      }

      const probe = renderProbeForInsertionPoint(baseRequest, ip.kind, ip.name, variant);

      try {
        const response = await config.replay(probe.rawRequest, probe.url);
        totalRequests += 1;

        const obs = buildOracleObservation(variant.id, variant.value, response, baseline);
        const classification = classifyOracleObservation(obs, variant, baseline);
        matrix = recordClassification(matrix, classification);

        if (classification.nextAction === 'stop-negative') break;
        if (classification.nextAction === 'promote-finding' || matrix.finalState === 'finding') break;
      } catch {
        totalRequests += 1;
        continue;
      }
    }

    if (matrix.finalState === 'running') {
      const conclusion = concludeMatrix(matrix);
      if (conclusion.state === 'negative') {
        matrix = markMatrixStopped(matrix, 'inconclusive');
        matrix = { ...matrix, finalState: 'negative' };
        negativeCount += 1;
      } else {
        matrix = markMatrixStopped(matrix, 'inconclusive');
      }
    }

    if (matrix.finalState === 'finding') {
      const best = highestConfidenceClassification(
        matrix.classifications.filter((c) => c.responseClass === 'expected-proof'),
      );
      const bestVariant = matrix.variants.find((v) => v.id === best?.payloadVariantId) ?? matrix.variants[0];
      const conclusion = concludeMatrix(matrix);

      if (best && bestVariant) {
        const finding = buildFinding(
          plan.checkId,
          plan.family,
          ip.host,
          ip.path,
          ip.id,
          conclusion,
          best,
          bestVariant,
          config.exchangeId,
        );
        config.onFinding?.(finding);
        findingCount += 1;
      }
    } else if (matrix.finalState === 'negative') {
      negativeCount += 1;
    }

    matrices.push(matrix);
    config.onProbeComplete?.(matrix);
  }

  return { matrices, findingCount, negativeCount, totalRequests };
}
