// Tests: payloadMutationEngine.ts — generatePayloadVariants produces ≥6 variants per family,
// no single-payload families, and each variant has required fields.
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

let mod;
try {
  mod = require('../dist-electron/src/scanner/payloadMutationEngine.js');
} catch {
  console.log('SKIP: scanner/payloadMutationEngine not compiled');
  process.exit(0);
}

try {
  const { generatePayloadVariants } = mod;

  // The instruction asks for 'mutatePayload' but the actual export is 'generatePayloadVariants'.
  // Support both names gracefully.
  const mutatePayload = mod.mutatePayload ?? generatePayloadVariants;

  const families = [
    'sql-injection',
    'xss-reflected',
    'ssti',
    'lfi-traversal',
    'command-injection',
    'ssrf',
    'open-redirect',
  ];

  for (const family of families) {
    const variants = mutatePayload({
      family,
      baseValue: 'test',
      insertionPointKind: 'query',
      maxVariants: 20,
    });

    // ── Must return ≥6 variants ─────────────────────────────────────────────
    assert.ok(
      Array.isArray(variants),
      `${family}: generatePayloadVariants must return an array`,
    );
    assert.ok(
      variants.length >= 6,
      `${family}: expected ≥6 variants, got ${variants.length}`,
    );

    // ── Must not be a single-payload family ────────────────────────────────
    assert.ok(
      variants.length > 1,
      `${family}: must not be a single-payload family (got ${variants.length})`,
    );

    // ── Every variant must have required fields ────────────────────────────
    for (const v of variants) {
      assert.ok(v.id,              `${family}: variant missing 'id'`);
      assert.ok(v.value !== undefined, `${family}: variant ${v.id} missing 'value'`);
      assert.ok(v.encoding,        `${family}: variant ${v.id} missing 'encoding'`);
      assert.ok(v.intent,          `${family}: variant ${v.id} missing 'intent'`);
      assert.ok(
        Array.isArray(v.expectedSignals) && v.expectedSignals.length > 0,
        `${family}: variant ${v.id} missing 'expectedSignals'`,
      );
    }

    console.log(`  ${family}: ${variants.length} variants — OK`);
  }

  console.log('PASS scanner-payload-variants-per-family');
} catch (err) {
  console.error('FAIL scanner-payload-variants-per-family:', err.message);
  process.exit(1);
}
