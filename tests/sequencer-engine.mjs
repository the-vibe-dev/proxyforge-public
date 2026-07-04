// run-all: slow  (statistical analysis with large sample sets; needs ~20 s)
import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';

const require = createRequire(import.meta.url);
const { SequencerEngine } = require('../dist-electron/sequencerEngine.js');

const engine = new SequencerEngine();

function assertOptionalAdvancedResultFields(result) {
  const record = result;
  const optionalNumericFields = ['sampleReliability', 'analysisConfidence', 'reliabilityScore'];
  for (const field of optionalNumericFields) {
    if (Object.hasOwn(record, field)) {
      assert.equal(typeof record[field], 'number', `${field} should be numeric when present`);
      assert(Number.isFinite(record[field]), `${field} should be finite when present`);
    }
  }

  if (Object.hasOwn(record, 'reliability')) {
    assert(record.reliability, 'reliability should be populated when present');
    assert(['rough', 'indicative', 'reliable', 'fips-ready'].includes(record.reliability.level));
    assert(Number.isFinite(record.reliability.sampleTarget));
    assert(Number.isFinite(record.reliability.maxSupportedSamples));
    assert(Number.isFinite(record.reliability.fipsSampleTarget));
    assert.match(record.reliability.message, /sample|reliab|fips/i);
  }

  if (Object.hasOwn(record, 'entropyBySignificance')) {
    assert(Array.isArray(record.entropyBySignificance));
    assert(record.entropyBySignificance.length > 0);
    for (const point of record.entropyBySignificance) {
      assert.match(point.significance, /rough|indicative|reliable|fips|sample/i);
      assert(Number.isFinite(point.effectiveEntropyBits));
    }
  }

  if (Object.hasOwn(record, 'positionStats')) {
    assert(Array.isArray(record.positionStats));
    if (record.sampleCount > 0) assert(record.positionStats.length > 0);
    for (const stat of record.positionStats.slice(0, 5)) {
      assert(Number.isFinite(stat.index));
      assert(Number.isFinite(stat.samplesObserved));
      assert(Number.isFinite(stat.shannonBits));
      assert(Number.isFinite(stat.dominantRate));
      assert(Number.isFinite(stat.transitionRepeatRate));
      assert(Number.isFinite(stat.bitStart));
      assert(Number.isFinite(stat.bitLength));
    }
  }

  if (Object.hasOwn(record, 'bitStats')) {
    assert(Array.isArray(record.bitStats));
    if (record.sampleCount > 0) assert(record.bitStats.length > 0);
    for (const stat of record.bitStats.slice(0, 8)) {
      assert(Number.isFinite(stat.index));
      assert(Number.isFinite(stat.sourcePosition));
      assert(Number.isFinite(stat.ones));
      assert(Number.isFinite(stat.zeros));
      assert(Number.isFinite(stat.monobitPValue));
      assert(Number.isFinite(stat.pokerScore));
      assert(Number.isFinite(stat.runCount));
      assert.equal(typeof stat.passedFips, 'boolean');
    }
  }

  if (Object.hasOwn(record, 'statisticalTests')) {
    assert(Array.isArray(record.statisticalTests));
    assert(record.statisticalTests.length > 0);
    assert(/monobit|runs|poker|serial|chi|fips/i.test(JSON.stringify(record.statisticalTests)));
    for (const test of record.statisticalTests) {
      assert.match(test.level, /summary|character|bit|fips/);
      assert.equal(typeof test.passed, 'boolean');
      assert(Number.isFinite(test.score));
      assert(Array.isArray(test.failedPositions));
    }
  }

  const optionalCollections = [
    ['fipsTests', /monobit|runs|poker|serial|long run|fips/],
    ['bitTests', /monobit|runs|poker|serial|bit/],
    ['tokenPositionAnalysis', /position|offset|prefix|variable|entropy/],
    ['positionAnalysis', /position|offset|prefix|variable|entropy/],
    ['characterDistribution', /character|alphabet|frequency|distribution/],
    ['bitDistribution', /bit|zero|one|monobit|distribution/],
    ['characterCharts', /chart|character|histogram|frequency/],
    ['bitCharts', /chart|bit|histogram|distribution/],
    ['profileComparison', /baseline|profile|comparison|drift|regression/],
  ];

  for (const [field, expectedPattern] of optionalCollections) {
    if (Object.hasOwn(record, field)) {
      assert(record[field], `${field} should be populated when present`);
      if (Array.isArray(record[field])) {
        assert(record[field].length > 0, `${field} should contain at least one entry when present`);
      }
      assert(
        expectedPattern.test(JSON.stringify(record[field]).toLowerCase()),
        `${field} should include advanced Sequencer evidence when present`,
      );
    }
  }

  if (Object.hasOwn(record, 'reportReady')) {
    assert.equal(typeof record.reportReady, 'boolean', 'reportReady should be boolean when present');
  }
}

const weak = engine.analyzeSamples({
  label: 'Predictable sequence',
  source: 'manual',
  samples: [
    'token-000001',
    'token-000002',
    'token-000003',
    'token-000004',
    'token-000004',
    'token-000005',
    'token-000006',
    'token-000007',
  ],
});

assert.equal(weak.sampleCount, 8);
assert.equal(weak.uniqueCount, 7);
assert.equal(weak.duplicateCount, 1);
assert.equal(weak.verdict, 'weak');
assert(weak.repeatedPrefixLength >= 8);
assert(weak.findings.some((finding) => finding.title === 'Token collisions observed'));
assert(weak.findings.some((finding) => finding.title === 'Estimated entropy below session-token baseline'));
assertOptionalAdvancedResultFields(weak);

const strong = engine.analyzeSamples({
  label: 'Random-looking bearer tokens',
  source: 'traffic',
  samples: [
    'N7rYq4LxP9mV2cAa8ZwKs5ThQeJ3uBdf',
    'wQ6cTsJ4zNm8RaYp2KxE7uHfVbD5gLhC',
    'Lm2QxV9aPz7TbKc4YhN6eRsJwF8uGdZ3',
    'cU8pJt5WqRy2FnLx9AaZ6mDkVhE4sGbN',
    'Hq5VnRz8KcYw3LpT7UfD2mSaJxE9bGQ4',
    'zB4mYaK8QpN6vLxJ3TsW9hFeUcD2rRgP7',
    'Kx9TaVf3QmY7LsD2hUcP5nWzRbE8JgN4',
    'pL6wRjX3ZcV9TfA2KmQ8sNdYhB5eUgC7',
    'Yt3KqL8VnW5cRpZ2UaJ9mHsFxD6eGbQ4',
    'fQ8xTaC2LmV7WzN5YpR3uKbJsD9hEgP6',
    'Ra7mKxV5CqT2LpY9WnD6uFsJhE3zBgQ8',
    'sJ5WqN8VcT3LmY7PzR2uKbFaX9dEhG6Q',
    'Dq9VtK4LmR8YpN2WcJ7uFaZxE5sBgH3',
    'xM6QaT9WnC3LpV7RsD2uJkYhF8eZgB5',
    'Pb4LxQ8VcY2WnT9RsD6uJmKaF3eZgH7',
    'uR7KqT2LmV9WcN5YsD3pJaXfE8zBgH6',
  ],
});

assert.equal(strong.sampleCount, 16);
assert.equal(strong.duplicateCount, 0);
assert(strong.estimatedEntropyBits > 96);
assert(strong.shannonBitsPerChar > 4);
assert(strong.monobitRatio > 0.4 && strong.monobitRatio < 0.6);
assert.equal(strong.verdict, 'strong');
assert(strong.findings.some((finding) => finding.title === 'No obvious predictability signals'));
assertOptionalAdvancedResultFields(strong);

const large = engine.analyzeSamples({
  label: 'Large live capture corpus',
  source: 'traffic',
  samples: Array.from({ length: 128 }, (_, index) =>
    deterministicToken('proxyforge-sequencer-live', index)),
});

assert.equal(large.sampleCount, 128);
assert.equal(large.uniqueCount, 128);
assert.equal(large.duplicateCount, 0);
assert(large.estimatedEntropyBits > 96);
assert(large.characterSets.some((set) => set.name === 'Base64url alphabet' && set.observed > 20));
assertOptionalAdvancedResultFields(large);

const reliable = engine.analyzeSamples({
  label: 'Reliable 5k live capture corpus',
  source: 'traffic',
  samples: Array.from({ length: 5000 }, (_, index) =>
    deterministicToken('proxyforge-sequencer-reliable', index)),
});

assert.equal(reliable.sampleCount, 5000);
assert.equal(reliable.uniqueCount, 5000);
assert.equal(reliable.duplicateCount, 0);
assert.equal(reliable.reliability.level, 'reliable');
assert.equal(reliable.reliability.sampleTarget, 5000);
assert.equal(reliable.reliability.maxSupportedSamples, 20000);
assert.equal(reliable.statisticalTests.find((test) => test.id === 'sample-reliability')?.passed, true);
assert.equal(reliable.positionStats[0].samplesObserved, 5000);
assert.equal(reliable.bitStats[0].ones + reliable.bitStats[0].zeros, 5000);
assert(reliable.estimatedEntropyBits > 96);
assert(reliable.entropyBySignificance.every((point) => Number.isFinite(point.effectiveEntropyBits)));
assertOptionalAdvancedResultFields(reliable);

const capped = engine.analyzeSamples({
  label: 'FIPS cap boundary corpus',
  source: 'traffic',
  samples: Array.from({ length: 20050 }, (_, index) =>
    deterministicToken('proxyforge-sequencer-fips-cap', index)),
});

assert.equal(capped.sampleCount, 20000);
assert.equal(capped.uniqueCount, 20000);
assert.equal(capped.reliability.level, 'fips-ready');
assert.equal(capped.reliability.fipsSampleTarget, 20000);
assert.equal(capped.statisticalTests.find((test) => test.id === 'sample-reliability')?.passed, true);
assert.equal(capped.positionStats[0].samplesObserved, 20000);
assert.equal(capped.bitStats[0].ones + capped.bitStats[0].zeros, 20000);
assert.match(capped.reliability.message, /20,000 tokens/);
assertOptionalAdvancedResultFields(capped);

const empty = engine.analyzeSamples({
  label: '',
  source: 'manual',
  samples: [' ', ''],
});

assert.equal(empty.sampleCount, 0);
assert.equal(empty.verdict, 'weak');
assert.equal(empty.findings[0].title, 'No token samples supplied');
assertOptionalAdvancedResultFields(empty);

const browserPreview = engine.analyzeSamples({
  label: 'Browser preview token capture',
  source: 'browser-preview',
  samples: Array.from({ length: 128 }, (_, index) =>
    deterministicToken('proxyforge-sequencer-browser-preview', index)),
});

const sourceSamples = [
  'sequencer-secret-token-0000.AUTHZ',
  'sequencer-secret-token-0001.COOKIE',
  'sequencer-secret-token-0002.FORM',
];
const parityPackage = engine.buildParityEvidencePackage({
  results: [weak, strong, reliable, capped, browserPreview],
  liveCaptures: [
    makeLiveCapture('live-cookie', 'cookie', 'session', 'Cookie: session', sourceSamples[1]),
    makeLiveCapture('live-form', 'form-field', 'csrf_token', 'form[name=csrf_token]', sourceSamples[2]),
    makeLiveCapture('live-custom', 'custom', 'Authorization bearer', '/Authorization: Bearer ([^\\s]+)/', sourceSamples[0]),
  ],
  profileComparisons: [
    {
      id: 'sequencer-profile-strong-vs-reliable',
      comparedAt: '2026-05-25T18:00:00.000Z',
      baselineResultId: strong.id,
      candidateResultId: reliable.id,
      baselineLabel: strong.label,
      candidateLabel: reliable.label,
      entropyDeltaBits: Number((reliable.estimatedEntropyBits - strong.estimatedEntropyBits).toFixed(3)),
      collisionDelta: Number((reliable.collisionRate - strong.collisionRate).toFixed(3)),
      verdictChange: `${strong.verdict}->${reliable.verdict}`,
      changedTests: ['sample-reliability', 'fips-monobit'],
      reportReady: true,
      summary: 'Reliable live corpus improved sample reliability while preserving zero collisions.',
    },
  ],
  exportArtifacts: [
    {
      id: 'sequencer-export-reliable',
      title: 'Sequencer reliable corpus evidence',
      fileName: 'sequencer-reliable-evidence.json',
      path: 'sequencer/sequencer-reliable-evidence.json',
      exportedAt: '2026-05-25T18:00:00.000Z',
      resultId: reliable.id,
      profileComparisonId: 'sequencer-profile-strong-vs-reliable',
      reportReady: true,
      issueId: 'issue-token-randomness-review',
      summary: 'Sequencer export preserves entropy, statistical tests, token samples, and profile comparison evidence.',
      content: JSON.stringify({
        kind: 'proxyforge-sequencer-export',
        resultId: reliable.id,
        tokenSamples: sourceSamples,
        entropyBits: reliable.estimatedEntropyBits,
        statisticalTests: reliable.statisticalTests.map((test) => test.id),
      }),
    },
  ],
  largeSampleSoakPackages: [
    {
      id: 'agent-sequencer-soak-reliable',
      kind: 'proxyforge-agent-sequencer-large-sample-soak-package',
      status: 'pass',
      observed: {
        sampleCount: reliable.sampleCount,
        reliability: reliable.reliability,
        estimatedEntropyBits: reliable.estimatedEntropyBits,
        statisticalTestCount: reliable.statisticalTests.length,
        positionStatCount: reliable.positionStats.length,
        bitStatCount: reliable.bitStats.length,
      },
      secretHandling: 'execution-full-fidelity-secrets-preserved',
      reportReady: true,
      content: `proxyforge-agent-sequencer-large-sample-soak sample=${sourceSamples[0]} reliability=${reliable.reliability.level}`,
    },
  ],
  sourceSamples,
  operationalSecretSamples: sourceSamples,
  exportedAt: '2026-05-25T18:00:00.000Z',
});

assert.equal(parityPackage.kind, 'proxyforge-sequencer-parity-evidence-package');
assert.equal(parityPackage.secretHandling, 'execution-full-fidelity-secrets-preserved');
assert.equal(parityPackage.reportRedactionBoundary, 'redact-only-during-report-export');
assert.equal(parityPackage.reportReady, true);
assert(Object.values(parityPackage.requirements).every(Boolean), 'all Sequencer parity requirements should be true');
assert.equal(parityPackage.resultCount, 5);
assert.equal(parityPackage.liveCaptureCount, 3);
assert.equal(parityPackage.profileComparisonCount, 1);
assert.equal(parityPackage.exportArtifactCount, 1);
assert.equal(parityPackage.sourceSampleCount, sourceSamples.length);
assert.match(parityPackage.content, /sequencer-secret-token-0000\.AUTHZ/);
assert.match(parityPackage.content, /proxyforge-agent-sequencer-large-sample-soak-package/);
assert.match(parityPackage.content, /"reportRedactionBoundary": "redact-only-during-report-export"/);

const artifactDir = path.resolve('.gitignored/test-artifacts/sequencer-engine');
await fs.mkdir(artifactDir, { recursive: true });
await fs.writeFile(path.join(artifactDir, 'sequencer-parity-evidence-package.json'), parityPackage.content);

console.log('sequencer-engine: exercised Sequencer parity package, token location extraction, reliability gates, statistical charts, and full-fidelity token preservation');

function deterministicToken(prefix, index) {
  return createHash('sha256').update(`${prefix}-${index}`).digest('base64url').slice(0, 32);
}

function makeLiveCapture(id, kind, name, extractor, token) {
  return {
    id,
    label: `${name} live capture`,
    createdAt: '2026-05-25T18:00:00.000Z',
    exchangeId: 'hx-sequencer-live-source',
    targetUrl: 'https://app.shop.local/session',
    tokenLocation: {
      kind,
      name,
      extractor,
    },
    requestedSamples: 1,
    capturedSamples: 1,
    status: 'captured',
    extractedTokens: [token],
    summary: `Captured ${kind} token ${token} from scoped traffic.`,
  };
}
