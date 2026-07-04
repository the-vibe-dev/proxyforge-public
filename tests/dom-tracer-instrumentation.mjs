// Tests for domTracerInstrumentation.ts — buildInstrumentationPayload + buildCanaryInjectionScript
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
let instr;
try {
  instr = require('../dist-electron/domTracerInstrumentation.js');
} catch {
  try {
    instr = require('../dist-electron/electron/domTracerInstrumentation.js');
  } catch {
    console.log('SKIP dom-tracer-instrumentation (module not compiled)');
    process.exit(0);
  }
}

const { buildInstrumentationPayload, buildCanaryInjectionScript } = instr;

// 1. Module exports buildInstrumentationPayload function
assert.equal(typeof buildInstrumentationPayload, 'function', 'buildInstrumentationPayload is a function');
console.log('  [1] exports buildInstrumentationPayload: PASS');

// 2. Module exports buildCanaryInjectionScript function
assert.equal(typeof buildCanaryInjectionScript, 'function', 'buildCanaryInjectionScript is a function');
console.log('  [2] exports buildCanaryInjectionScript: PASS');

// 3. buildInstrumentationPayload returns a non-empty string
const payload = buildInstrumentationPayload({ sessionId: 'sess-test-001' });
assert.equal(typeof payload, 'string', 'payload is a string');
assert.ok(payload.length > 0, 'payload is non-empty');
console.log('  [3] buildInstrumentationPayload returns non-empty string: PASS');

// 4. Returned payload contains '__PF_TRACER__'
assert.ok(payload.includes('__PF_TRACER__'), 'payload contains __PF_TRACER__');
console.log('  [4] payload contains __PF_TRACER__: PASS');

// 5. Returned payload contains 'innerHTML' (sink hook)
assert.ok(payload.includes('innerHTML'), 'payload contains innerHTML sink hook');
console.log('  [5] payload contains innerHTML: PASS');

// 6. Returned payload contains 'eval' when hookEval: true
const payloadWithEval = buildInstrumentationPayload({ sessionId: 'sess-eval-on', hookEval: true });
assert.ok(payloadWithEval.includes('eval'), 'payload with hookEval:true contains eval');
console.log('  [6] payload contains eval when hookEval:true: PASS');

// 7. Returned payload does NOT contain eval hook code when hookEval: false
const payloadNoEval = buildInstrumentationPayload({ sessionId: 'sess-eval-off', hookEval: false });
// When hookEval is false, the eval hook block should be replaced with the disabled comment
assert.ok(!payloadNoEval.includes('window.eval ='), 'payload with hookEval:false does not hook window.eval');
console.log('  [7] payload does not hook eval when hookEval:false: PASS');

// 8. buildCanaryInjectionScript('pf-test123') returns a string containing 'pf-test123'
const canaryScript = buildCanaryInjectionScript('pf-test123');
assert.equal(typeof canaryScript, 'string', 'canary script is a string');
assert.ok(canaryScript.includes('pf-test123'), 'canary script contains the nonce');
console.log('  [8] buildCanaryInjectionScript embeds nonce: PASS');

// 9. buildCanaryInjectionScript with targetSelector includes the selector
const selector = '#output-div';
const canaryScriptWithTarget = buildCanaryInjectionScript('pf-abc999', selector);
assert.ok(canaryScriptWithTarget.includes(selector), 'canary script includes targetSelector');
assert.ok(canaryScriptWithTarget.includes('querySelector'), 'canary script with selector uses querySelector');
console.log('  [9] buildCanaryInjectionScript with targetSelector includes selector: PASS');

// 10. The session ID is embedded in the payload
const sessionId = 'sess-embed-check-007';
const payloadWithSession = buildInstrumentationPayload({ sessionId });
assert.ok(payloadWithSession.includes(sessionId), 'session ID is embedded in the payload');
console.log('  [10] session ID embedded in payload: PASS');

console.log('PASS dom-tracer-instrumentation');
