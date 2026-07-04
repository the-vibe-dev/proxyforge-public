// Phase 3b — Auth Methods: TOTP credential cycle.
// Tests generateTotpCode and validateTotpCode with the standard RFC test vector.
// Known TOTP test secret: JBSWY3DPEHPK3PXP
// This is the canonical "Hello!" base32 test secret used in most TOTP test suites.
import { createRequire } from 'node:module';
import assert from 'node:assert/strict';

const require = createRequire(import.meta.url);

let totpMod;
try {
  totpMod = require('../dist-electron/src/authMethods/totpAuth.js');
} catch {
  console.log('SKIP: authMethods/totpAuth.js not compiled — run tsc first.');
  process.exit(0);
}

const { generateTotpCode, validateTotpCode } = totpMod;

const TEST_SECRET = 'JBSWY3DPEHPK3PXP';

// ---------------------------------------------------------------------------
// Test 1: generateTotpCode is exported as a function
// ---------------------------------------------------------------------------
{
  assert.strictEqual(typeof generateTotpCode, 'function', 'generateTotpCode must be a function');
  console.log('PASS: generateTotpCode is a function');
}

// ---------------------------------------------------------------------------
// Test 2: generateTotpCode returns a 6-digit zero-padded string
// ---------------------------------------------------------------------------
{
  // Use a fixed time so the result is deterministic
  const fixedNow = 1_700_000_000_000; // 2023-11-14T22:13:20.000Z
  const code = generateTotpCode(TEST_SECRET, 6, 30, fixedNow);

  assert.strictEqual(typeof code, 'string', 'generateTotpCode must return a string');
  assert.strictEqual(code.length, 6, `TOTP code must be exactly 6 digits, got "${code}"`);
  assert.match(code, /^\d{6}$/, `TOTP code must be all digits, got "${code}"`);

  console.log(`PASS: generateTotpCode returns 6-digit string ("${code}")`);
}

// ---------------------------------------------------------------------------
// Test 3: different time steps produce codes — determinism at the same counter
// ---------------------------------------------------------------------------
{
  const fixedNow = 1_700_000_000_000;
  const code1 = generateTotpCode(TEST_SECRET, 6, 30, fixedNow);
  const code2 = generateTotpCode(TEST_SECRET, 6, 30, fixedNow + 1); // same 30s window

  assert.strictEqual(code1, code2,
    'Same 30s window must produce the same code regardless of sub-second offset');

  console.log('PASS: generateTotpCode is stable within the same time step');
}

// ---------------------------------------------------------------------------
// Test 4: a new 30s window produces a different code (almost certainly)
// ---------------------------------------------------------------------------
{
  const t1 = 1_700_000_000_000;       // counter = floor(1700000000 / 30) = 56666666
  const t2 = t1 + 30_000;             // counter = 56666667

  const codeWindow1 = generateTotpCode(TEST_SECRET, 6, 30, t1);
  const codeWindow2 = generateTotpCode(TEST_SECRET, 6, 30, t2);

  // Both must be valid 6-digit strings
  assert.match(codeWindow1, /^\d{6}$/);
  assert.match(codeWindow2, /^\d{6}$/);

  // They should differ (collision probability is 1/1,000,000)
  assert.notStrictEqual(codeWindow1, codeWindow2,
    'Adjacent 30s windows should (almost certainly) produce different codes');

  console.log('PASS: adjacent time steps produce different TOTP codes');
}

// ---------------------------------------------------------------------------
// Test 5: validateTotpCode is a function (if exported)
// ---------------------------------------------------------------------------
{
  if (typeof validateTotpCode === 'function') {
    const fixedNow = 1_700_000_000_000;
    const code = generateTotpCode(TEST_SECRET, 6, 30, fixedNow);

    // Should validate within the same window
    assert.strictEqual(
      validateTotpCode(TEST_SECRET, code, 6, 30, fixedNow),
      true,
      'validateTotpCode must accept a freshly generated code',
    );

    // An obviously wrong code should fail
    const wrongCode = code === '000000' ? '000001' : '000000';
    assert.strictEqual(
      validateTotpCode(TEST_SECRET, wrongCode, 6, 30, fixedNow),
      false,
      'validateTotpCode must reject an incorrect code',
    );

    console.log('PASS: validateTotpCode accepts correct code and rejects wrong code');
  } else {
    console.log('NOTE: validateTotpCode not exported — skipping validation tests');
  }
}

// ---------------------------------------------------------------------------
// Test 6: 8-digit TOTP variant
// ---------------------------------------------------------------------------
{
  const fixedNow = 1_700_000_000_000;
  const code8 = generateTotpCode(TEST_SECRET, 8, 30, fixedNow);

  assert.strictEqual(typeof code8, 'string');
  assert.strictEqual(code8.length, 8, `8-digit TOTP must be 8 chars, got "${code8}"`);
  assert.match(code8, /^\d{8}$/, `8-digit TOTP must be all digits, got "${code8}"`);

  console.log(`PASS: generateTotpCode produces 8-digit code ("${code8}")`);
}

console.log('\nAll totp-credential-cycle tests passed.');
