// Phase 12 — Tests for automation/agentProtocol.ts
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
let protocol;
try {
  protocol = require('../dist-electron/src/automation/agentProtocol.js');
} catch {
  console.log('SKIP agent-protocol-commands (module not compiled)');
  process.exit(0);
}

const {
  parseCommand, serializeResponse, serializeEvent, buildErrorResponse,
  buildSuccessResponse, validateCommand, isValidOpCode,
} = protocol;

// parseCommand
const cmd = parseCommand('{"op":"scanner.run","projectId":"proj-1","exchangeId":"ex-1"}');
assert.equal(cmd.op, 'scanner.run', 'op parsed');
assert.equal(cmd.projectId, 'proj-1', 'projectId parsed');
console.log('  parseCommand: PASS');

// parseCommand throws on missing op
assert.throws(() => parseCommand('{"noOp":true}'), /missing "op"/i, 'throws on missing op');
assert.throws(() => parseCommand('{invalid json'), Error, 'throws on invalid JSON');
console.log('  parseCommand validation: PASS');

// validateCommand — valid
const validResult = validateCommand({ op: 'scanner.run', projectId: 'proj-1', exchangeId: 'ex-1' });
assert.ok(validResult.valid, 'valid command passes');
assert.equal(validResult.errors.length, 0, 'no errors');
console.log('  validateCommand valid: PASS');

// validateCommand — missing fields
const invalidResult = validateCommand({ op: 'scanner.run', projectId: 'proj-1' }); // missing exchangeId
assert.ok(!invalidResult.valid, 'invalid command fails');
assert.ok(invalidResult.errors.some((e) => e.includes('exchangeId')), 'error mentions exchangeId');
console.log('  validateCommand missing field: PASS');

// isValidOpCode
assert.ok(isValidOpCode('scanner.run'), 'scanner.run is valid');
assert.ok(isValidOpCode('project.create'), 'project.create is valid');
assert.ok(!isValidOpCode('unknown.op'), 'unknown op is invalid');
console.log('  isValidOpCode: PASS');

// buildSuccessResponse
const success = buildSuccessResponse('scanner.run', { matrixId: 'm-001' }, 'req-1');
assert.ok(success.ok, 'success.ok is true');
assert.equal(success.op, 'scanner.run', 'op in response');
assert.equal(success.requestId, 'req-1', 'requestId in response');
assert.deepEqual(success.data, { matrixId: 'm-001' }, 'data in response');
console.log('  buildSuccessResponse: PASS');

// buildErrorResponse
const error = buildErrorResponse('scanner.run', 'Budget exceeded', 'req-2');
assert.ok(!error.ok, 'error.ok is false');
assert.equal(error.error, 'Budget exceeded', 'error message');
assert.equal(error.requestId, 'req-2', 'requestId in error');
console.log('  buildErrorResponse: PASS');

// serializeResponse
const serialized = serializeResponse(success);
const reparsed = JSON.parse(serialized);
assert.equal(reparsed.ok, true, 'serialized response round-trips');
assert.equal(reparsed.op, 'scanner.run', 'op in serialized');
console.log('  serializeResponse: PASS');

// serializeEvent
const event = {
  event: 'scanner.finding.created',
  timestamp: new Date().toISOString(),
  findingId: 'finding-001',
};
const eventStr = serializeEvent(event);
const reparsedEvent = JSON.parse(eventStr);
assert.equal(reparsedEvent.event, 'scanner.finding.created', 'event type preserved');
assert.equal(reparsedEvent.findingId, 'finding-001', 'payload preserved');
console.log('  serializeEvent: PASS');

// All required ops are valid
const requiredOps = ['project.create', 'project.open', 'proxy.start', 'proxy.stop', 'browser.launch', 'history.query', 'repeater.send', 'scanner.run', 'oast.payload.create', 'issue.promote', 'report.export'];
for (const op of requiredOps) {
  assert.ok(isValidOpCode(op), `${op} is a valid op code`);
}
console.log('  All required op codes valid: PASS');

console.log('PASS agent-protocol-commands');
