// Phase 12 — Tests for stats passive rule: redirect chain detection.
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
let engine, rule;
try {
  engine = require('../dist-electron/src/stats/countersEngine.js');
  rule = require('../dist-electron/src/stats/passiveStatsRule.js');
} catch {
  console.log('SKIP stats-rule-redirect-chain-finding (module not compiled)');
  process.exit(0);
}

const { increment, resetAll } = engine;
const { evaluateThresholds, DEFAULT_THRESHOLDS, addThreshold } = rule;

// Start fresh
resetAll();

// Add 60 redirect events to one host bucket → evaluateThresholds returns issue for that host
increment('proxy.exchange.redirect', 'host:redirect-heavy.com', 60);
const issues = evaluateThresholds();
const redirectIssues = issues.filter((i) => i.ruleEvent === 'proxy.exchange.redirect');
assert.ok(redirectIssues.length >= 1, 'redirect issue fired after 60 events (threshold 50)');
const heavyIssue = redirectIssues.find((i) => i.bucket === 'host:redirect-heavy.com');
assert.ok(heavyIssue, 'issue reported for the correct bucket');
console.log('  60 redirects → issue for that host: PASS');

// Different host with only 10 redirects → no issue
increment('proxy.exchange.redirect', 'host:quiet.com', 10);
const issues2 = evaluateThresholds();
const quietIssues = issues2.filter(
  (i) => i.ruleEvent === 'proxy.exchange.redirect' && i.bucket === 'host:quiet.com',
);
assert.equal(quietIssues.length, 0, 'no redirect issue for host with only 10 redirects');
console.log('  10 redirects → no issue: PASS');

// Issue has correct severity and ruleEvent
assert.equal(heavyIssue.severity, 'low', 'redirect issue severity is low');
assert.equal(heavyIssue.ruleEvent, 'proxy.exchange.redirect', 'ruleEvent matches event key');
console.log('  Issue severity and ruleEvent: PASS');

// StatsIssue count field matches accumulated count
assert.ok(heavyIssue.count >= 60, `count field reflects accumulated count (got ${heavyIssue.count})`);
console.log('  StatsIssue count field: PASS');

// addThreshold returns new array without modifying original
const originalLength = DEFAULT_THRESHOLDS.length;
const newThresholds = addThreshold(
  {
    event: 'proxy.exchange.redirect',
    bucket: 'host:custom.com',
    threshold: 5,
    severity: 'info',
    title: 'Low redirect threshold (custom)',
    detail: 'Custom low-threshold redirect rule for testing.',
  },
  [...DEFAULT_THRESHOLDS],
);
assert.equal(DEFAULT_THRESHOLDS.length, originalLength, 'addThreshold does not mutate original array');
assert.equal(newThresholds.length, originalLength + 1, 'returned array has one extra threshold');
assert.ok(
  newThresholds.some((t) => t.event === 'proxy.exchange.redirect' && t.threshold === 5),
  'custom threshold present in returned array',
);
console.log('  addThreshold immutability: PASS');

// Custom threshold with lower limit fires for a bucket that would not trip default
resetAll();
increment('proxy.exchange.redirect', 'host:custom.com', 6); // above custom threshold of 5
const customIssues = evaluateThresholds(newThresholds);
const customFired = customIssues.filter(
  (i) => i.ruleEvent === 'proxy.exchange.redirect' && i.bucket === 'host:custom.com',
);
assert.ok(customFired.length >= 1, 'custom low-threshold fires at 6 events');
console.log('  Custom threshold fires: PASS');

console.log('PASS stats-rule-redirect-chain-finding');
