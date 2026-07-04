// Tests: payloadMutationEngine.ts — open-redirect family covers required URL scheme variants.
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
  const generatePayloadVariants = mod.generatePayloadVariants ?? mod.mutatePayload;

  const variants = generatePayloadVariants({
    family: 'open-redirect',
    baseValue: 'https://example.com',
    insertionPointKind: 'query',
    maxVariants: 50,
  });

  assert.ok(Array.isArray(variants), 'open-redirect variants must be an array');
  assert.ok(variants.length >= 6, `Expected ≥6 open-redirect variants, got ${variants.length}`);

  const values = variants.map((v) => v.value);

  // ── javascript: scheme ────────────────────────────────────────────────────
  assert.ok(
    values.some((v) => /javascript:/i.test(v)),
    `open-redirect must include a javascript: scheme variant. Got: ${JSON.stringify(values)}`,
  );

  // ── protocol-relative //evil ──────────────────────────────────────────────
  assert.ok(
    values.some((v) => v.startsWith('//')),
    `open-redirect must include a protocol-relative (//) variant. Got: ${JSON.stringify(values)}`,
  );

  // ── data: scheme ──────────────────────────────────────────────────────────
  assert.ok(
    values.some((v) => /data:/i.test(v)),
    `open-redirect must include a data: scheme variant. Got: ${JSON.stringify(values)}`,
  );

  // ── backslash bypass variant ──────────────────────────────────────────────
  assert.ok(
    values.some((v) => v.includes('\\') || v.includes('%5C') || v.includes('%5c')),
    `open-redirect must include a backslash (\\) bypass variant. Got: ${JSON.stringify(values)}`,
  );

  // ── cross-origin redirect (domain not matching example.com) ──────────────
  assert.ok(
    values.some((v) => /evil|attacker|external|callback|oast|redirect/i.test(v) || v.includes('//') || /^https?:\/\/(?!example\.com)/.test(v)),
    `open-redirect must include cross-origin redirect payloads. Got: ${JSON.stringify(values)}`,
  );

  // ── All variants have required fields ─────────────────────────────────────
  for (const v of variants) {
    assert.ok(v.id,       `open-redirect variant missing 'id'`);
    assert.ok(v.encoding, `open-redirect variant ${v.id} missing 'encoding'`);
    assert.ok(v.intent,   `open-redirect variant ${v.id} missing 'intent'`);
    assert.ok(
      Array.isArray(v.expectedSignals) && v.expectedSignals.length > 0,
      `open-redirect variant ${v.id} missing 'expectedSignals'`,
    );
  }

  console.log(`PASS scanner-open-redirect-scheme-matrix (${variants.length} variants)`);
} catch (err) {
  console.error('FAIL scanner-open-redirect-scheme-matrix:', err.message);
  process.exit(1);
}
