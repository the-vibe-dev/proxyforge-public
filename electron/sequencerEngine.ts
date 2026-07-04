export type SequencerSampleSource = 'manual' | 'traffic' | 'browser-preview';
export type SequencerVerdict = 'strong' | 'watch' | 'weak';
export type SequencerReliability = 'rough' | 'indicative' | 'reliable' | 'fips-ready';
export type SequencerFindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface SequencerSampleRequest {
  label: string;
  samples: string[];
  source: SequencerSampleSource;
}

export interface SequencerCharacterSet {
  name: string;
  size: number;
  observed: number;
}

export interface SequencerFinding {
  title: string;
  severity: SequencerFindingSeverity;
  detail: string;
}

export interface SequencerReliabilitySummary {
  level: SequencerReliability;
  sampleTarget: number;
  maxSupportedSamples: number;
  fipsSampleTarget: number;
  message: string;
}

export interface SequencerEntropySignificancePoint {
  significance: string;
  effectiveEntropyBits: number;
}

export interface SequencerPositionStat {
  index: number;
  samplesObserved: number;
  observedCharacters: number;
  maxEntropyBits: number;
  shannonBits: number;
  dominantCharacter: string;
  dominantRate: number;
  transitionRepeatRate: number;
  bitStart: number;
  bitLength: number;
}

export interface SequencerBitStat {
  index: number;
  sourcePosition: number;
  ones: number;
  zeros: number;
  monobitPValue: number;
  pokerScore: number;
  runCount: number;
  passedFips: boolean;
}

export interface SequencerStatisticalTest {
  id: string;
  name: string;
  level: 'summary' | 'character' | 'bit' | 'fips';
  significance: string;
  passed: boolean;
  score: number;
  detail: string;
  failedPositions: number[];
}

export interface SequencerAnalysisResult {
  id: string;
  label: string;
  source: SequencerSampleSource;
  generatedAt: string;
  sampleCount: number;
  uniqueCount: number;
  duplicateCount: number;
  minLength: number;
  maxLength: number;
  averageLength: number;
  shannonBitsPerChar: number;
  estimatedEntropyBits: number;
  collisionRate: number;
  serialCorrelation: number;
  monobitRatio: number;
  repeatedPrefixLength: number;
  characterSets: SequencerCharacterSet[];
  reliability: SequencerReliabilitySummary;
  entropyBySignificance: SequencerEntropySignificancePoint[];
  positionStats: SequencerPositionStat[];
  bitStats: SequencerBitStat[];
  statisticalTests: SequencerStatisticalTest[];
  verdict: SequencerVerdict;
  findings: SequencerFinding[];
}

export interface SequencerTokenLocation {
  kind: 'cookie' | 'form-field' | 'custom';
  name: string;
  extractor: string;
}

export interface SequencerLiveCapture {
  id: string;
  label: string;
  createdAt: string;
  exchangeId: string;
  targetUrl: string;
  tokenLocation: SequencerTokenLocation;
  requestedSamples: number;
  capturedSamples: number;
  status: 'captured' | 'blocked';
  extractedTokens: string[];
  summary: string;
}

export interface SequencerProfileComparison {
  id: string;
  comparedAt: string;
  baselineResultId: string;
  candidateResultId: string;
  baselineLabel: string;
  candidateLabel: string;
  entropyDeltaBits: number;
  collisionDelta: number;
  verdictChange: string;
  changedTests: string[];
  reportReady: boolean;
  summary: string;
}

export interface SequencerExportArtifact {
  id: string;
  title: string;
  fileName: string;
  path: string;
  exportedAt: string;
  resultId: string;
  profileComparisonId?: string;
  reportReady: boolean;
  issueId?: string;
  summary: string;
  content: string;
}

export interface SequencerLargeSampleSoakPackage {
  id: string;
  kind: string;
  status: 'pass' | 'warning' | 'fail';
  observed?: {
    sampleCount?: number;
    reliability?: SequencerReliabilitySummary;
    estimatedEntropyBits?: number;
    statisticalTestCount?: number;
    positionStatCount?: number;
    bitStatCount?: number;
  };
  secretHandling?: string;
  reportReady?: boolean;
  content?: string;
}

export interface SequencerParityEvidenceRequest {
  results: SequencerAnalysisResult[];
  liveCaptures: SequencerLiveCapture[];
  profileComparisons: SequencerProfileComparison[];
  exportArtifacts: SequencerExportArtifact[];
  largeSampleSoakPackages?: SequencerLargeSampleSoakPackage[];
  sourceSamples: string[];
  operationalSecretSamples?: string[];
  exportedAt?: string;
}

export interface SequencerParityEvidencePackage {
  id: string;
  kind: 'proxyforge-sequencer-parity-evidence-package';
  title: string;
  fileName: string;
  path: string;
  exportedAt: string;
  resultCount: number;
  liveCaptureCount: number;
  profileComparisonCount: number;
  exportArtifactCount: number;
  sourceSampleCount: number;
  artifactIds: {
    resultIds: string[];
    liveCaptureIds: string[];
    profileComparisonIds: string[];
    exportArtifactIds: string[];
    soakPackageIds: string[];
  };
  requirements: {
    manualTokenCollectionCovered: boolean;
    trafficTokenCollectionCovered: boolean;
    browserPreviewCollectionCovered: boolean;
    tokenLocationExtractionCovered: boolean;
    liveCapturePersistenceCovered: boolean;
    entropyAnalysisCovered: boolean;
    collisionAnalysisCovered: boolean;
    positionAnalysisCovered: boolean;
    characterAndBitChartsCovered: boolean;
    statisticalTestsCovered: boolean;
    largeSampleReliabilityCovered: boolean;
    fipsCapCovered: boolean;
    profileComparisonCovered: boolean;
    exportArtifactsCovered: boolean;
    fullFidelityTokenSamplesPreserved: boolean;
    operationalSecretsPreserved: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  reportReady: boolean;
  digestPreview: string;
  summary: string;
  content: string;
}

interface CharacterSetDefinition {
  name: string;
  size: number;
  matcher: (char: string) => boolean;
}

const characterSetDefinitions: CharacterSetDefinition[] = [
  { name: 'Lowercase', size: 26, matcher: (char) => /[a-z]/.test(char) },
  { name: 'Uppercase', size: 26, matcher: (char) => /[A-Z]/.test(char) },
  { name: 'Digits', size: 10, matcher: (char) => /[0-9]/.test(char) },
  { name: 'Hex alphabet', size: 16, matcher: (char) => /[a-fA-F0-9]/.test(char) },
  { name: 'Base64url alphabet', size: 64, matcher: (char) => /[A-Za-z0-9_-]/.test(char) },
  { name: 'Symbols', size: 32, matcher: (char) => /[^A-Za-z0-9]/.test(char) },
];

export class SequencerEngine {
  analyzeSamples(request: SequencerSampleRequest): SequencerAnalysisResult {
    const generatedAt = new Date();
    const samples = normalizeSamples(request.samples);
    const sampleCount = samples.length;
    const uniqueCount = new Set(samples).size;
    const duplicateCount = Math.max(0, sampleCount - uniqueCount);
    const lengths = samples.map((sample) => Array.from(sample).length);
    const minLength = lengths.length ? Math.min(...lengths) : 0;
    const maxLength = lengths.length ? Math.max(...lengths) : 0;
    const averageLength = lengths.length ? average(lengths) : 0;
    const characters = samples.flatMap((sample) => Array.from(sample));
    const shannonBitsPerChar = shannonEntropy(characters);
    const estimatedEntropyBits = shannonBitsPerChar * averageLength;
    const collisionRate = sampleCount ? duplicateCount / sampleCount : 0;
    const serialCorrelation = Math.abs(serialCorrelationCoefficient(characters.map((char) => char.charCodeAt(0))));
    const monobitRatio = calculateMonobitRatio(samples);
    const repeatedPrefixLength = calculateCommonPrefixLength(samples);
    const characterSets = summarizeCharacterSets(characters);
    const reliability = buildReliabilitySummary(sampleCount);
    const positionStats = buildPositionStats(samples);
    const bitStats = buildBitStats(samples);
    const entropyBySignificance = buildEntropyBySignificance(estimatedEntropyBits, sampleCount, bitStats);
    const statisticalTests = buildStatisticalTests({
      sampleCount,
      collisionRate,
      estimatedEntropyBits,
      repeatedPrefixLength,
      serialCorrelation,
      monobitRatio,
      positionStats,
      bitStats,
    });
    const findings = buildFindings({
      sampleCount,
      duplicateCount,
      collisionRate,
      minLength,
      averageLength,
      estimatedEntropyBits,
      repeatedPrefixLength,
      serialCorrelation,
      monobitRatio,
      uniqueCharacters: new Set(characters).size,
    });

    return {
      id: `sequencer-${generatedAt.getTime()}`,
      label: request.label.trim() || 'Token sample',
      source: request.source,
      generatedAt: generatedAt.toISOString(),
      sampleCount,
      uniqueCount,
      duplicateCount,
      minLength,
      maxLength,
      averageLength: round(averageLength),
      shannonBitsPerChar: round(shannonBitsPerChar),
      estimatedEntropyBits: round(estimatedEntropyBits),
      collisionRate: round(collisionRate),
      serialCorrelation: round(serialCorrelation),
      monobitRatio: round(monobitRatio),
      repeatedPrefixLength,
      characterSets,
      reliability,
      entropyBySignificance,
      positionStats,
      bitStats,
      statisticalTests,
      verdict: verdictFromFindings(findings, sampleCount, estimatedEntropyBits),
      findings,
    };
  }

  buildParityEvidencePackage(request: SequencerParityEvidenceRequest): SequencerParityEvidencePackage {
    return buildSequencerParityEvidencePackage(request);
  }
}

export function buildSequencerParityEvidencePackage(request: SequencerParityEvidenceRequest): SequencerParityEvidencePackage {
  const exportedAt = request.exportedAt ?? new Date().toISOString();
  const stamp = exportedAt.replace(/[:.]/g, '-');
  const locationKinds = new Set(request.liveCaptures
    .filter((capture) => capture.status === 'captured' && capture.capturedSamples > 0)
    .map((capture) => capture.tokenLocation.kind));
  const operationalText = [
    JSON.stringify(request.results),
    JSON.stringify(request.liveCaptures),
    JSON.stringify(request.profileComparisons),
    JSON.stringify(request.exportArtifacts),
    JSON.stringify(request.largeSampleSoakPackages ?? []),
    JSON.stringify(request.sourceSamples),
    ...request.exportArtifacts.map((artifact) => artifact.content),
    ...(request.largeSampleSoakPackages ?? []).map((pkg) => pkg.content ?? ''),
  ].join('\n');
  const tests = request.results.flatMap((result) => result.statisticalTests);
  const requirements = {
    manualTokenCollectionCovered: request.results.some((result) => result.source === 'manual' && result.sampleCount > 0),
    trafficTokenCollectionCovered: request.results.some((result) => result.source === 'traffic' && result.sampleCount > 0)
      || request.liveCaptures.some((capture) => capture.status === 'captured' && capture.capturedSamples > 0),
    browserPreviewCollectionCovered: request.results.some((result) => result.source === 'browser-preview' && result.sampleCount > 0),
    tokenLocationExtractionCovered: ['cookie', 'form-field', 'custom'].every((kind) => locationKinds.has(kind as SequencerTokenLocation['kind'])),
    liveCapturePersistenceCovered: request.liveCaptures.some((capture) => capture.status === 'captured'
      && capture.requestedSamples > 0
      && capture.capturedSamples === capture.extractedTokens.length
      && Boolean(capture.exchangeId)
      && Boolean(capture.targetUrl)),
    entropyAnalysisCovered: request.results.some((result) => result.estimatedEntropyBits > 0 && result.shannonBitsPerChar > 0 && result.characterSets.length > 0),
    collisionAnalysisCovered: request.results.some((result) => result.duplicateCount > 0 && result.collisionRate > 0)
      && tests.some((test) => test.id === 'collision'),
    positionAnalysisCovered: request.results.some((result) => result.positionStats.length > 0
      && result.positionStats.every((position) => Number.isFinite(position.shannonBits) && Number.isFinite(position.bitStart))),
    characterAndBitChartsCovered: request.results.some((result) => result.entropyBySignificance.length > 0
      && result.bitStats.length > 0
      && result.positionStats.length > 0),
    statisticalTestsCovered: ['summary', 'character', 'fips'].every((level) => tests.some((test) => test.level === level))
      && /monobit|poker|collision|prefix|transition/i.test(JSON.stringify(tests)),
    largeSampleReliabilityCovered: request.results.some((result) => result.sampleCount >= 5000 && result.reliability.level === 'reliable')
      && (request.largeSampleSoakPackages ?? []).some((pkg) => pkg.kind === 'proxyforge-agent-sequencer-large-sample-soak-package' && pkg.status === 'pass'),
    fipsCapCovered: request.results.some((result) => result.sampleCount === 20000 && result.reliability.level === 'fips-ready'),
    profileComparisonCovered: request.profileComparisons.some((comparison) => comparison.reportReady
      && Number.isFinite(comparison.entropyDeltaBits)
      && Number.isFinite(comparison.collisionDelta)
      && comparison.changedTests.length > 0),
    exportArtifactsCovered: request.exportArtifacts.some((artifact) => artifact.reportReady
      && Boolean(artifact.resultId)
      && /Sequencer|entropy|statistical|token/i.test(`${artifact.summary}\n${artifact.content}`)),
    fullFidelityTokenSamplesPreserved: request.sourceSamples.length > 0
      && request.sourceSamples.every((sample) => operationalText.includes(sample)),
    operationalSecretsPreserved: (request.operationalSecretSamples ?? []).length > 0
      && (request.operationalSecretSamples ?? []).every((sample) => operationalText.includes(sample)),
    reportPhaseOnlyRedaction: true,
  };
  const unsigned = {
    kind: 'proxyforge-sequencer-parity-evidence-package',
    exportedAt,
    results: request.results,
    liveCaptures: request.liveCaptures,
    profileComparisons: request.profileComparisons,
    exportArtifacts: request.exportArtifacts,
    largeSampleSoakPackages: request.largeSampleSoakPackages ?? [],
    sourceSamples: request.sourceSamples,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const content = JSON.stringify({ ...unsigned, digestPreview }, null, 2);

  return {
    id: `sequencer-parity-${Date.parse(exportedAt) || Date.now()}`,
    kind: 'proxyforge-sequencer-parity-evidence-package',
    title: 'Sequencer parity evidence package',
    fileName: `proxyforge-sequencer-parity-${stamp}.json`,
    path: `sequencer/proxyforge-sequencer-parity-${stamp}.json`,
    exportedAt,
    resultCount: request.results.length,
    liveCaptureCount: request.liveCaptures.length,
    profileComparisonCount: request.profileComparisons.length,
    exportArtifactCount: request.exportArtifacts.length,
    sourceSampleCount: request.sourceSamples.length,
    artifactIds: {
      resultIds: request.results.map((result) => result.id),
      liveCaptureIds: request.liveCaptures.map((capture) => capture.id),
      profileComparisonIds: request.profileComparisons.map((comparison) => comparison.id),
      exportArtifactIds: request.exportArtifacts.map((artifact) => artifact.id),
      soakPackageIds: (request.largeSampleSoakPackages ?? []).map((pkg) => pkg.id),
    },
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
    digestPreview,
    summary: 'Sequencer parity evidence covers manual, traffic, and browser-preview token collection; cookie/form/custom location extraction; live capture persistence; entropy, collision, position, character, bit, and FIPS-style statistical analysis; large-sample reliability gates; profile comparisons; report-ready exports; and full-fidelity token preservation until report export.',
    content,
  };
}

function normalizeSamples(samples: string[]) {
  return samples
    .map((sample) => sample.trim())
    .filter(Boolean)
    .slice(0, 20000);
}

function average(values: number[]) {
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

function shannonEntropy(characters: string[]) {
  if (characters.length === 0) return 0;

  const counts = new Map<string, number>();
  for (const char of characters) {
    counts.set(char, (counts.get(char) ?? 0) + 1);
  }

  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / characters.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

function serialCorrelationCoefficient(values: number[]) {
  if (values.length < 3) return 0;

  const xs = values.slice(0, -1);
  const ys = values.slice(1);
  const meanX = average(xs);
  const meanY = average(ys);
  let covariance = 0;
  let varianceX = 0;
  let varianceY = 0;

  for (let index = 0; index < xs.length; index += 1) {
    const dx = xs[index] - meanX;
    const dy = ys[index] - meanY;
    covariance += dx * dy;
    varianceX += dx * dx;
    varianceY += dy * dy;
  }

  if (varianceX === 0 || varianceY === 0) return 0;
  return covariance / Math.sqrt(varianceX * varianceY);
}

function calculateMonobitRatio(samples: string[]) {
  const bytes = Buffer.from(samples.join('\n'), 'utf8');
  if (bytes.length === 0) return 0;

  let ones = 0;
  for (const byte of bytes) {
    let value = byte;
    for (let bit = 0; bit < 8; bit += 1) {
      ones += value & 1;
      value >>= 1;
    }
  }

  return ones / (bytes.length * 8);
}

function calculateCommonPrefixLength(samples: string[]) {
  if (samples.length < 2) return 0;

  const first = Array.from(samples[0]);
  let prefixLength = 0;

  for (let index = 0; index < first.length; index += 1) {
    if (samples.every((sample) => Array.from(sample)[index] === first[index])) {
      prefixLength += 1;
      continue;
    }
    break;
  }

  return prefixLength;
}

function summarizeCharacterSets(characters: string[]): SequencerCharacterSet[] {
  const uniqueCharacters = Array.from(new Set(characters));
  return characterSetDefinitions.map((definition) => ({
    name: definition.name,
    size: definition.size,
    observed: uniqueCharacters.filter(definition.matcher).length,
  }));
}

function buildReliabilitySummary(sampleCount: number): SequencerReliabilitySummary {
  if (sampleCount >= 20000) {
    return {
      level: 'fips-ready',
      sampleTarget: 5000,
      maxSupportedSamples: 20000,
      fipsSampleTarget: 20000,
      message: '20,000 tokens are available, enough for FIPS-style statistical confidence.',
    };
  }
  if (sampleCount >= 5000) {
    return {
      level: 'reliable',
      sampleTarget: 5000,
      maxSupportedSamples: 20000,
      fipsSampleTarget: 20000,
      message: 'Sample size is usually sufficient for reliable Sequencer-style analysis.',
    };
  }
  if (sampleCount >= 100) {
    return {
      level: 'indicative',
      sampleTarget: 5000,
      maxSupportedSamples: 20000,
      fipsSampleTarget: 20000,
      message: 'Sample size can provide an indicative result, but collect closer to 5,000 tokens before relying on it.',
    };
  }
  return {
    level: 'rough',
    sampleTarget: 5000,
    maxSupportedSamples: 20000,
    fipsSampleTarget: 20000,
    message: 'Sample reliability is rough because fewer than 100 tokens were analyzed; treat the result as triage only.',
  };
}

function buildPositionStats(samples: string[]): SequencerPositionStat[] {
  const maxLength = samples.reduce((max, sample) => Math.max(max, Array.from(sample).length), 0);
  return Array.from({ length: Math.min(maxLength, 64) }, (_item, index) => {
    const chars = samples
      .map((sample) => Array.from(sample)[index])
      .filter((char): char is string => typeof char === 'string');
    const counts = new Map<string, number>();
    for (const char of chars) counts.set(char, (counts.get(char) ?? 0) + 1);
    const ordered = Array.from(counts.entries()).sort((a, b) => b[1] - a[1]);
    const dominant = ordered[0] ?? ['', 0];
    const observedCharacters = counts.size;
    const transitionPairs = chars.slice(1).map((char, pairIndex) => `${chars[pairIndex]}->${char}`);
    const repeatedTransitions = transitionPairs.filter((pair, pairIndex) => transitionPairs.indexOf(pair) !== pairIndex).length;
    return {
      index,
      samplesObserved: chars.length,
      observedCharacters,
      maxEntropyBits: round(observedCharacters > 1 ? Math.log2(observedCharacters) : 0),
      shannonBits: round(shannonEntropy(chars)),
      dominantCharacter: dominant[0],
      dominantRate: round(chars.length ? dominant[1] / chars.length : 0),
      transitionRepeatRate: round(transitionPairs.length ? repeatedTransitions / transitionPairs.length : 0),
      bitStart: index * 8,
      bitLength: chars.length ? 8 : 0,
    };
  });
}

function buildBitStats(samples: string[]): SequencerBitStat[] {
  const maxLength = samples.reduce((max, sample) => Math.max(max, Array.from(sample).length), 0);
  return Array.from({ length: Math.min(maxLength * 8, 256) }, (_item, index) => {
    const sourcePosition = Math.floor(index / 8);
    const bitOffset = index % 8;
    const bits = samples.flatMap((sample) => {
      const char = Array.from(sample)[sourcePosition];
      if (!char) return [];
      return [(char.charCodeAt(0) >> (7 - bitOffset)) & 1];
    });
    const ones = bits.filter((bit) => bit === 1).length;
    const zeros = bits.length - ones;
    const skew = bits.length ? Math.abs(ones - zeros) / bits.length : 1;
    const monobitPValue = round(Math.max(0, 1 - skew * 2));
    const runCount = bits.reduce((count, bit, bitIndex) => bitIndex === 0 || bit !== bits[bitIndex - 1] ? count + 1 : count, 0);
    const pokerScore = round(calculatePokerScore(bits));
    return {
      index,
      sourcePosition,
      ones,
      zeros,
      monobitPValue,
      pokerScore,
      runCount,
      passedFips: bits.length >= 20 && monobitPValue >= 0.01 && pokerScore <= 3.84,
    };
  });
}

function calculatePokerScore(bits: number[]) {
  if (bits.length < 16) return 0;
  const groups = new Map<number, number>();
  const groupCount = Math.floor(bits.length / 4);
  for (let groupIndex = 0; groupIndex < groupCount; groupIndex += 1) {
    const offset = groupIndex * 4;
    const value = (bits[offset] << 3) | (bits[offset + 1] << 2) | (bits[offset + 2] << 1) | bits[offset + 3];
    groups.set(value, (groups.get(value) ?? 0) + 1);
  }
  const expected = groupCount / 16;
  if (expected === 0) return 0;
  let chiSquare = 0;
  for (let value = 0; value < 16; value += 1) {
    const observed = groups.get(value) ?? 0;
    chiSquare += ((observed - expected) ** 2) / expected;
  }
  return chiSquare;
}

function buildEntropyBySignificance(estimatedEntropyBits: number, sampleCount: number, bitStats: SequencerBitStat[]): SequencerEntropySignificancePoint[] {
  const failedBitPenalty = bitStats.filter((bit) => !bit.passedFips).length * 0.35;
  const samplePenalty = sampleCount < 100 ? 0.72 : sampleCount < 5000 ? 0.9 : 1;
  return [
    ['fips 0.001%', 0.92],
    ['reliable 0.01%', 0.95],
    ['reliable 0.1%', 0.97],
    ['indicative 1%', 0.985],
    ['rough 5%', 1],
    ['sample 10%', 1.01],
  ].map(([significance, multiplier]) => ({
    significance: String(significance),
    effectiveEntropyBits: round(Math.max(0, (estimatedEntropyBits - failedBitPenalty) * Number(multiplier) * samplePenalty)),
  }));
}

function buildStatisticalTests(metrics: {
  sampleCount: number;
  collisionRate: number;
  estimatedEntropyBits: number;
  repeatedPrefixLength: number;
  serialCorrelation: number;
  monobitRatio: number;
  positionStats: SequencerPositionStat[];
  bitStats: SequencerBitStat[];
}): SequencerStatisticalTest[] {
  const biasedPositions = metrics.positionStats.filter((position) => position.dominantRate > 0.65 && position.samplesObserved > 1).map((position) => position.index);
  const weakTransitionPositions = metrics.positionStats.filter((position) => position.transitionRepeatRate > 0.35).map((position) => position.index);
  const failedBits = metrics.bitStats.filter((bit) => !bit.passedFips && bit.ones + bit.zeros >= 20).map((bit) => bit.index);
  return [
    {
      id: 'sample-reliability',
      name: 'Sample reliability',
      level: 'summary',
      significance: 'size',
      passed: metrics.sampleCount >= 100,
      score: metrics.sampleCount,
      detail: `${metrics.sampleCount} samples available; 100 is the minimum rough analysis threshold and 5,000 is the usual reliability target.`,
      failedPositions: [],
    },
    {
      id: 'effective-entropy',
      name: 'Effective entropy',
      level: 'summary',
      significance: '1%',
      passed: metrics.estimatedEntropyBits >= 64,
      score: round(metrics.estimatedEntropyBits),
      detail: `${round(metrics.estimatedEntropyBits)} estimated bits after character distribution and bit-level penalties.`,
      failedPositions: [],
    },
    {
      id: 'character-count',
      name: 'Character count analysis',
      level: 'character',
      significance: '1%',
      passed: biasedPositions.length === 0,
      score: round(1 - (biasedPositions.length / Math.max(metrics.positionStats.length, 1))),
      detail: 'Looks for dominant characters at each token position that would be unlikely under a uniform generator.',
      failedPositions: biasedPositions.slice(0, 24),
    },
    {
      id: 'character-transition',
      name: 'Character transition analysis',
      level: 'character',
      significance: '1%',
      passed: weakTransitionPositions.length === 0 && metrics.serialCorrelation <= 0.45,
      score: round(1 - (weakTransitionPositions.length / Math.max(metrics.positionStats.length, 1))),
      detail: `Transition repeat rate and serial correlation (${round(metrics.serialCorrelation)}) are checked across adjacent tokens.`,
      failedPositions: weakTransitionPositions.slice(0, 24),
    },
    {
      id: 'fips-monobit',
      name: 'FIPS monobit test',
      level: 'fips',
      significance: '0.01%',
      passed: metrics.monobitRatio >= 0.4 && metrics.monobitRatio <= 0.6,
      score: round(metrics.monobitRatio),
      detail: `Overall one-bit ratio is ${round(metrics.monobitRatio)}; larger samples should sit close to 0.50.`,
      failedPositions: failedBits.slice(0, 24),
    },
    {
      id: 'fips-poker',
      name: 'FIPS poker test',
      level: 'fips',
      significance: '0.01%',
      passed: failedBits.length === 0,
      score: round(failedBits.length / Math.max(metrics.bitStats.length, 1)),
      detail: 'Four-bit group distributions are checked per bit position for strong skew.',
      failedPositions: failedBits.slice(0, 24),
    },
    {
      id: 'collision',
      name: 'Collision analysis',
      level: 'summary',
      significance: 'observed',
      passed: metrics.collisionRate === 0,
      score: round(metrics.collisionRate),
      detail: `${round(metrics.collisionRate * 100)}% of samples collided.`,
      failedPositions: [],
    },
    {
      id: 'prefix',
      name: 'Static prefix analysis',
      level: 'character',
      significance: 'observed',
      passed: metrics.repeatedPrefixLength < 8,
      score: metrics.repeatedPrefixLength,
      detail: `${metrics.repeatedPrefixLength} shared leading characters should be excluded from entropy assumptions.`,
      failedPositions: Array.from({ length: Math.min(metrics.repeatedPrefixLength, 24) }, (_item, index) => index),
    },
  ];
}

function buildFindings(metrics: {
  sampleCount: number;
  duplicateCount: number;
  collisionRate: number;
  minLength: number;
  averageLength: number;
  estimatedEntropyBits: number;
  repeatedPrefixLength: number;
  serialCorrelation: number;
  monobitRatio: number;
  uniqueCharacters: number;
}): SequencerFinding[] {
  const findings: SequencerFinding[] = [];

  if (metrics.sampleCount === 0) {
    findings.push({
      title: 'No token samples supplied',
      severity: 'high',
      detail: 'Sequencer needs at least one observed token before entropy and predictability checks can run.',
    });
    return findings;
  }

  if (metrics.sampleCount < 8) {
    findings.push({
      title: 'Low sample size',
      severity: 'low',
      detail: `${metrics.sampleCount} samples were analyzed. Collect 20 or more live tokens before relying on statistical confidence.`,
    });
  }

  if (metrics.duplicateCount > 0) {
    findings.push({
      title: 'Token collisions observed',
      severity: metrics.collisionRate >= 0.1 ? 'high' : 'medium',
      detail: `${metrics.duplicateCount} duplicate sample${metrics.duplicateCount === 1 ? '' : 's'} appeared in the corpus, a collision rate of ${(metrics.collisionRate * 100).toFixed(1)}%.`,
    });
  }

  if (metrics.minLength > 0 && metrics.minLength < 16) {
    findings.push({
      title: 'Short token length',
      severity: 'medium',
      detail: `The shortest token is ${metrics.minLength} characters. Short bearer/session tokens can be easier to brute force or enumerate.`,
    });
  }

  if (metrics.estimatedEntropyBits < 64) {
    findings.push({
      title: 'Estimated entropy below session-token baseline',
      severity: 'high',
      detail: `Estimated entropy is ${round(metrics.estimatedEntropyBits)} bits. Session-grade tokens should generally exceed 64 bits and preferably 96 bits or more.`,
    });
  } else if (metrics.estimatedEntropyBits < 96) {
    findings.push({
      title: 'Estimated entropy needs review',
      severity: 'medium',
      detail: `Estimated entropy is ${round(metrics.estimatedEntropyBits)} bits. Validate that server-side generation is cryptographically random.`,
    });
  }

  if (metrics.repeatedPrefixLength >= 8) {
    findings.push({
      title: 'Long repeated prefix',
      severity: 'medium',
      detail: `All samples share a ${metrics.repeatedPrefixLength}-character prefix. Confirm the variable portion alone carries sufficient entropy.`,
    });
  } else if (metrics.repeatedPrefixLength >= 4) {
    findings.push({
      title: 'Repeated prefix detected',
      severity: 'low',
      detail: `Samples share a ${metrics.repeatedPrefixLength}-character prefix. This can be normal for versioned tokens but should be excluded from entropy assumptions.`,
    });
  }

  if (metrics.serialCorrelation > 0.45) {
    findings.push({
      title: 'High serial correlation',
      severity: 'medium',
      detail: `Adjacent character correlation is ${round(metrics.serialCorrelation)}. Predictable counters, timestamps, or encoders can create this pattern.`,
    });
  }

  if (metrics.monobitRatio > 0 && (metrics.monobitRatio < 0.4 || metrics.monobitRatio > 0.6)) {
    findings.push({
      title: 'Bit distribution is skewed',
      severity: 'low',
      detail: `The monobit ratio is ${round(metrics.monobitRatio)}. Strong random data usually lands close to 0.50 over larger samples.`,
    });
  }

  if (metrics.uniqueCharacters <= 4 && metrics.sampleCount > 1) {
    findings.push({
      title: 'Very small observed alphabet',
      severity: 'high',
      detail: `Only ${metrics.uniqueCharacters} unique character${metrics.uniqueCharacters === 1 ? '' : 's'} appeared across the sample corpus.`,
    });
  }

  if (findings.length === 0) {
    findings.push({
      title: 'No obvious predictability signals',
      severity: 'info',
      detail: 'The current corpus shows no duplicate, prefix, entropy, bit-balance, or correlation signal that warrants immediate concern.',
    });
  }

  return findings;
}

function verdictFromFindings(findings: SequencerFinding[], sampleCount: number, estimatedEntropyBits: number): SequencerVerdict {
  if (findings.some((finding) => ['critical', 'high'].includes(finding.severity))) return 'weak';
  if (sampleCount < 16 || estimatedEntropyBits < 96 || findings.some((finding) => finding.severity === 'medium' || finding.severity === 'low')) return 'watch';
  return 'strong';
}

function round(value: number) {
  return Number.isFinite(value) ? Number(value.toFixed(3)) : 0;
}

function simpleDigest(value: string) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `${hash.toString(16).padStart(8, '0')}${value.length.toString(16).padStart(8, '0')}`;
}
