// Phase 12 — Tests for stats/passiveStatsRule.ts
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
let engine, rule;
try {
  engine = require('../dist-electron/src/stats/countersEngine.js');
  rule = require('../dist-electron/src/stats/passiveStatsRule.js');
} catch {
  console.log('SKIP stats-rule-5xx-cluster-finding (module not compiled)');
  process.exit(0);
}

const { increment, resetAll } = engine;
const { evaluateThresholds, DEFAULT_THRESHOLDS, addThreshold } = rule;

resetAll();

// No issues below threshold
increment('proxy.exchange.5xx', 'host:example.com', 5); // below 20 threshold
const noIssues = evaluateThresholds();
const fivexxIssues = noIssues.filter((i) => i.ruleEvent === 'proxy.exchange.5xx');
assert.equal(fivexxIssues.length, 0, 'no 5xx issue below threshold');
console.log('  Below threshold: PASS');

// Trip 5xx threshold
increment('proxy.exchange.5xx', 'host:example.com', 20); // now 25 ≥ 20
const withIssues = evaluateThresholds();
const tripped = withIssues.filter((i) => i.ruleEvent === 'proxy.exchange.5xx');
assert.ok(tripped.length >= 1, 'issue fired above threshold');
assert.equal(tripped[0].bucket, 'host:example.com', 'correct bucket reported');
assert.ok(tripped[0].count >= 20, 'count in issue');
assert.equal(tripped[0].severity, 'medium', 'severity from rule');
console.log('  5xx cluster finding: PASS');

// Trip redirect threshold
increment('proxy.exchange.redirect', 'host:redirect.com', 60); // ≥ 50
const withRedirect = evaluateThresholds();
const redirectIssue = withRedirect.filter((i) => i.ruleEvent === 'proxy.exchange.redirect');
assert.ok(redirectIssue.length >= 1, 'redirect issue fired');
console.log('  Redirect cluster finding: PASS');

// DEFAULT_THRESHOLDS shape
assert.ok(Array.isArray(DEFAULT_THRESHOLDS), 'DEFAULT_THRESHOLDS is array');
assert.ok(DEFAULT_THRESHOLDS.length >= 3, 'at least 3 default thresholds');
assert.ok(DEFAULT_THRESHOLDS.every((t) => t.event && t.threshold > 0 && t.severity), 'all thresholds have required fields');
console.log('  DEFAULT_THRESHOLDS shape: PASS');

// addThreshold
const customThresholds = addThreshold({
  event: 'scanner.custom.event',
  threshold: 5,
  severity: 'info',
  title: 'Custom threshold',
  detail: 'Test threshold',
}, [...DEFAULT_THRESHOLDS]);
assert.ok(customThresholds.some((t) => t.event === 'scanner.custom.event'), 'custom threshold added');
console.log('  addThreshold: PASS');

// Custom threshold fires
resetAll();
increment('scanner.custom.event', 'global', 10); // ≥ 5
const customIssues = evaluateThresholds(customThresholds);
const customFired = customIssues.filter((i) => i.ruleEvent === 'scanner.custom.event');
assert.ok(customFired.length >= 1, 'custom threshold fires');
console.log('  Custom threshold fires: PASS');

console.log('PASS stats-rule-5xx-cluster-finding');
