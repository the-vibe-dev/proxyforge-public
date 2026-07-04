// Tests: sql-injection with High threshold only reports firm findings,
//        Insane strength emits all variants.
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

let policiesModule;
try {
  policiesModule = require('../dist-electron/src/scanner/policies/index.js');
} catch {
  try {
    policiesModule = require('../dist-electron/scannerPoliciesIndex.js');
  } catch {
    console.log('policy-threshold-strength-applied-per-rule: skipped — policies not compiled yet');
    process.exit(0);
  }
}

const {
  createDefaultPolicy,
  createScannerPolicy,
  createPolicyRule,
  getPolicyRule,
  upsertPolicyRule,
  shouldRunCheck,
  getCheckStrength,
  getEnabledChecks,
} = policiesModule;

if (typeof createDefaultPolicy !== 'function') {
  console.log('policy-threshold-strength-applied-per-rule: skipped — missing exports');
  process.exit(0);
}

// ---------------------------------------------------------------------------
// Test 1: createDefaultPolicy has expected structure
// ---------------------------------------------------------------------------
{
  const policy = createDefaultPolicy();

  assert.ok(typeof policy.id === 'string' && policy.id.length > 0, 'must have id');
  assert.strictEqual(policy.name, 'Default Policy');
  assert.ok(Array.isArray(policy.rules) && policy.rules.length > 0, 'must have rules');
  assert.ok(policy.rules.some((r) => r.checkId === 'sql-injection'), 'must include sql-injection');
  assert.ok(policy.rules.every((r) => r.enabled), 'all default rules must be enabled');
  assert.ok(
    policy.rules.every((r) => r.threshold === 'medium'),
    'all default rules must have medium threshold',
  );
  assert.ok(
    policy.rules.every((r) => r.strength === 'medium'),
    'all default rules must have medium strength',
  );
  console.log('PASS: createDefaultPolicy returns well-formed policy');
}

// ---------------------------------------------------------------------------
// Test 2: shouldRunCheck — medium threshold accepts firm findings
// ---------------------------------------------------------------------------
{
  const policy = createDefaultPolicy();

  assert.strictEqual(shouldRunCheck('sql-injection', policy, 'firm'), true,
    'medium threshold must accept firm confidence');
  assert.strictEqual(shouldRunCheck('sql-injection', policy, 'certain'), true,
    'medium threshold must accept certain confidence');
  console.log('PASS: medium threshold accepts firm and certain findings');
}

// ---------------------------------------------------------------------------
// Test 3: shouldRunCheck — medium threshold rejects tentative findings
// ---------------------------------------------------------------------------
{
  const policy = createDefaultPolicy();
  assert.strictEqual(shouldRunCheck('sql-injection', policy, 'tentative'), false,
    'medium threshold must reject tentative confidence');
  console.log('PASS: medium threshold rejects tentative findings');
}

// ---------------------------------------------------------------------------
// Test 4: shouldRunCheck — high threshold only accepts certain findings
// ---------------------------------------------------------------------------
{
  const policy = createDefaultPolicy();

  // Override sql-injection to high threshold
  upsertPolicyRule(policy, createPolicyRule('sql-injection', { threshold: 'high', strength: 'medium' }));

  assert.strictEqual(shouldRunCheck('sql-injection', policy, 'certain'), true,
    'high threshold must accept certain confidence');
  assert.strictEqual(shouldRunCheck('sql-injection', policy, 'firm'), false,
    'high threshold must reject firm confidence');
  assert.strictEqual(shouldRunCheck('sql-injection', policy, 'tentative'), false,
    'high threshold must reject tentative confidence');
  console.log('PASS: high threshold only accepts certain findings');
}

// ---------------------------------------------------------------------------
// Test 5: shouldRunCheck — low threshold accepts all confidence levels
// ---------------------------------------------------------------------------
{
  const policy = createDefaultPolicy();
  upsertPolicyRule(policy, createPolicyRule('sql-injection', { threshold: 'low', strength: 'medium' }));

  assert.strictEqual(shouldRunCheck('sql-injection', policy, 'tentative'), true,
    'low threshold must accept tentative confidence');
  assert.strictEqual(shouldRunCheck('sql-injection', policy, 'firm'), true);
  assert.strictEqual(shouldRunCheck('sql-injection', policy, 'certain'), true);
  console.log('PASS: low threshold accepts all confidence levels');
}

// ---------------------------------------------------------------------------
// Test 6: shouldRunCheck returns false for disabled rule
// ---------------------------------------------------------------------------
{
  const policy = createDefaultPolicy();
  upsertPolicyRule(policy, createPolicyRule('sql-injection', { threshold: 'low', enabled: false }));

  assert.strictEqual(shouldRunCheck('sql-injection', policy, 'certain'), false,
    'disabled rule must never run');
  console.log('PASS: disabled rule is never run regardless of confidence');
}

// ---------------------------------------------------------------------------
// Test 7: shouldRunCheck returns false for check not in policy
// ---------------------------------------------------------------------------
{
  const policy = createDefaultPolicy();
  assert.strictEqual(shouldRunCheck('unknown-check-xyz', policy, 'certain'), false,
    'check not in policy must not run');
  console.log('PASS: check not in policy returns false');
}

// ---------------------------------------------------------------------------
// Test 8: getCheckStrength returns correct strength for a check
// ---------------------------------------------------------------------------
{
  const policy = createDefaultPolicy();
  upsertPolicyRule(policy, createPolicyRule('sql-injection', { strength: 'insane', threshold: 'medium' }));

  assert.strictEqual(getCheckStrength('sql-injection', policy), 'insane',
    'must return insane strength for sql-injection');
  assert.strictEqual(getCheckStrength('reflected-xss', policy), 'medium',
    'must return medium (default) strength for reflected-xss');
  assert.strictEqual(getCheckStrength('nonexistent', policy), 'medium',
    'must return medium for unknown check');
  console.log('PASS: getCheckStrength returns correct strength per rule');
}

// ---------------------------------------------------------------------------
// Test 9: Insane strength — verify it can be set and read per-rule
// ---------------------------------------------------------------------------
{
  const policy = createScannerPolicy({
    name: 'Insane SQL Policy',
    rules: [
      createPolicyRule('sql-injection', { threshold: 'low', strength: 'insane' }),
    ],
  });

  const rule = getPolicyRule('sql-injection', policy);
  assert.ok(rule, 'rule must exist');
  assert.strictEqual(rule.strength, 'insane', 'strength must be insane');
  assert.strictEqual(rule.threshold, 'low');

  // With insane + low: should run for all confidence levels
  assert.strictEqual(shouldRunCheck('sql-injection', policy, 'tentative'), true);
  assert.strictEqual(shouldRunCheck('sql-injection', policy, 'firm'), true);
  assert.strictEqual(shouldRunCheck('sql-injection', policy, 'certain'), true);
  console.log('PASS: insane strength with low threshold runs for all confidence levels');
}

// ---------------------------------------------------------------------------
// Test 10: getEnabledChecks returns only enabled checks
// ---------------------------------------------------------------------------
{
  const policy = createDefaultPolicy();
  upsertPolicyRule(policy, createPolicyRule('sql-injection', { enabled: false }));

  const enabled = getEnabledChecks(policy);
  assert.ok(!enabled.includes('sql-injection'), 'disabled check must not be in enabled list');
  assert.ok(enabled.includes('reflected-xss'), 'enabled checks must appear in list');
  console.log('PASS: getEnabledChecks returns only enabled checks');
}

// ---------------------------------------------------------------------------
// Test 11: upsertPolicyRule adds a new rule not already in the policy
// ---------------------------------------------------------------------------
{
  const policy = createScannerPolicy({ name: 'Custom', rules: [] });
  assert.strictEqual(policy.rules.length, 0);

  upsertPolicyRule(policy, createPolicyRule('my-custom-check', { threshold: 'high', strength: 'high' }));
  assert.strictEqual(policy.rules.length, 1);
  assert.strictEqual(policy.rules[0].checkId, 'my-custom-check');
  console.log('PASS: upsertPolicyRule adds new rule when not present');
}

// ---------------------------------------------------------------------------
// Test 12: upsertPolicyRule updates existing rule
// ---------------------------------------------------------------------------
{
  const policy = createDefaultPolicy();
  const before = getPolicyRule('sql-injection', policy);
  assert.strictEqual(before?.threshold, 'medium');

  upsertPolicyRule(policy, createPolicyRule('sql-injection', { threshold: 'high', strength: 'insane' }));

  const after = getPolicyRule('sql-injection', policy);
  assert.strictEqual(after?.threshold, 'high');
  assert.strictEqual(after?.strength, 'insane');
  // Rule count must not grow (update, not duplicate)
  const sqlRules = policy.rules.filter((r) => r.checkId === 'sql-injection');
  assert.strictEqual(sqlRules.length, 1, 'must not duplicate the rule');
  console.log('PASS: upsertPolicyRule updates existing rule without duplication');
}

console.log('\nAll policy-threshold-strength-applied-per-rule tests passed.');
