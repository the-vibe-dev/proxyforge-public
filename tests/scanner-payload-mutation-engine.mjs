// Phase 1 — Tests for payloadMutationEngine.ts
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { generatePayloadVariants, familiesForInsertionPoint } = require('../dist-electron/src/scanner/payloadMutationEngine.js');

const families = [
  'sql-injection', 'xss-reflected', 'ssti', 'lfi-traversal',
  'command-injection', 'ssrf', 'open-redirect', 'nosql-injection',
];

for (const family of families) {
  const variants = generatePayloadVariants({
    family,
    baseValue: 'test',
    insertionPointKind: 'query',
    maxVariants: 20,
  });

  assert.ok(variants.length >= 6, `${family}: expected ≥6 variants, got ${variants.length}`);

  // Deduplication check
  const values = variants.map((v) => v.value);
  const unique = new Set(values);
  assert.equal(unique.size, values.length, `${family}: variants must not be duplicated`);

  // Every variant must declare intent + expected signals
  for (const v of variants) {
    assert.ok(v.intent, `${family}: variant ${v.id} missing intent`);
    assert.ok(Array.isArray(v.expectedSignals) && v.expectedSignals.length > 0, `${family}: variant ${v.id} missing expectedSignals`);
    assert.ok(v.id, `${family}: variant missing id`);
    assert.ok(v.encoding, `${family}: variant ${v.id} missing encoding`);
    assert.ok(v.destructiveRisk, `${family}: variant ${v.id} missing destructiveRisk`);
  }

  console.log(`  ${family}: ${variants.length} variants OK`);
}

// OAST gating — OAST variants should be excluded when no oastBaseUrl
const ssrfNoOast = generatePayloadVariants({
  family: 'ssrf',
  baseValue: 'http://example.com',
  insertionPointKind: 'query',
});
assert.ok(
  ssrfNoOast.every((v) => !v.requiresOast),
  'SSRF variants without oastBaseUrl must not include OAST-requiring variants',
);

// OAST variants should appear when oastBaseUrl is provided
const ssrfWithOast = generatePayloadVariants({
  family: 'ssrf',
  baseValue: 'http://example.com',
  insertionPointKind: 'query',
  oastBaseUrl: 'https://oast.test',
});
assert.ok(
  ssrfWithOast.some((v) => v.requiresOast),
  'SSRF variants with oastBaseUrl should include at least one OAST-requiring variant',
);

// Max variants respected
const limited = generatePayloadVariants({
  family: 'sql-injection',
  baseValue: 'test',
  insertionPointKind: 'query',
  maxVariants: 3,
});
assert.ok(limited.length <= 3, `Expected ≤3 variants, got ${limited.length}`);

// open-redirect must include javascript: and protocol-relative variants
const redirectVariants = generatePayloadVariants({
  family: 'open-redirect',
  baseValue: '/',
  insertionPointKind: 'query',
  maxVariants: 20,
});
const redirectValues = redirectVariants.map((v) => v.value);
assert.ok(
  redirectValues.some((v) => /javascript:/i.test(v)),
  'open-redirect must include javascript: scheme variant',
);
assert.ok(
  redirectValues.some((v) => v.startsWith('//')),
  'open-redirect must include protocol-relative (//) variant',
);
assert.ok(
  redirectValues.some((v) => /\\\\/i.test(v) || v.includes('\\')),
  'open-redirect must include backslash variant',
);

// familiesForInsertionPoint
const queryFamilies = familiesForInsertionPoint('query');
assert.ok(Array.isArray(queryFamilies), 'familiesForInsertionPoint must return array');
assert.ok(queryFamilies.length >= 4, 'query insertion point must support ≥4 families');
assert.ok(queryFamilies.includes('sql-injection'), 'query must include sql-injection');
assert.ok(queryFamilies.includes('xss-reflected'), 'query must include xss-reflected');

const xmlFamilies = familiesForInsertionPoint('xml');
assert.ok(xmlFamilies.includes('xxe'), 'xml must include xxe');

console.log('PASS scanner-payload-mutation-engine');
