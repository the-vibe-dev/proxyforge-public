// ---------------------------------------------------------------------------
// Param Miner Engine
// Discovers hidden / undocumented parameters by probing target endpoints
// with candidate names and scoring responses for anomalies.
// ---------------------------------------------------------------------------

export interface ParamMinerConfig {
  targetUrl: string;
  method?: string;
  parameterList?: string[];
  headerList?: string[];
  mode?: 'query' | 'body' | 'headers' | 'all';
  maxParams?: number;
  throttleMs?: number;
  baselineHash?: string;
}

export interface MinedParam {
  name: string;
  location: 'query' | 'body' | 'header';
  reflected: boolean;
  anomalyScore: number;
  evidence: string;
}

export interface ParamMinerRun {
  id: string;
  targetUrl: string;
  status: 'running' | 'complete';
  found: MinedParam[];
  probed: number;
  total: number;
  startedAt: string;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export function createParamMinerRun(config: ParamMinerConfig): ParamMinerRun {
  const paramCount = config.parameterList?.length ?? 0;
  const headerCount = config.headerList?.length ?? 0;
  const mode = config.mode ?? 'all';

  let total = 0;
  if (mode === 'query' || mode === 'body' || mode === 'all') total += paramCount;
  if (mode === 'headers' || mode === 'all') total += headerCount;
  if (config.maxParams != null) total = Math.min(total, config.maxParams);

  return {
    id: `pminer-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
    targetUrl: config.targetUrl,
    status: 'running',
    found: [],
    probed: 0,
    total,
    startedAt: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Result recording
// ---------------------------------------------------------------------------

export function recordParamResult(
  run: ParamMinerRun,
  name: string,
  location: MinedParam['location'],
  reflected: boolean,
  anomalyScore: number,
  evidence: string,
): void {
  run.found.push({ name, location, reflected, anomalyScore, evidence });
  run.probed += 1;
}

// ---------------------------------------------------------------------------
// Analysis helpers
// ---------------------------------------------------------------------------

/**
 * Sort mined params by anomalyScore descending — highest-confidence
 * findings surface first for triage.
 */
export function rankMinedParams(params: MinedParam[]): MinedParam[] {
  return [...params].sort((a, b) => b.anomalyScore - a.anomalyScore);
}

/**
 * Return only params whose anomalyScore meets or exceeds minScore.
 * Default threshold is 0.5 (moderate confidence that the param has an effect).
 */
export function getInterestingParams(run: ParamMinerRun, minScore = 0.5): MinedParam[] {
  return run.found.filter((p) => p.anomalyScore >= minScore);
}
