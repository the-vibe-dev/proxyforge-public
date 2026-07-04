import { createRequire } from 'node:module';
import assert from 'node:assert/strict';

const require = createRequire(import.meta.url);

let genMod;
try {
  genMod = require('../dist-electron/src/apiGenerators/pythonGenerator.js');
} catch {
  console.log('SKIP: pythonGenerator not compiled — run tsc first.');
  process.exit(0);
}

const { generatePython } = genMod;

if (typeof generatePython !== 'function') {
  console.log('SKIP: generatePython export not found.');
  process.exit(0);
}

// generatePython returns Array<{ filename, content }>
// The content should contain Python class/def/async def constructs
const schema = { language: 'python', operations: [{ opId: 'proxy_start', method: 'POST', path: '/proxy/start' }] };
const files = generatePython(schema);

assert.ok(Array.isArray(files) && files.length >= 1,
  'generatePython should return an array with at least one file');

const content = files.map((f) => f.content).join('\n');

const hasExpectedKeyword = content.includes('class') || content.includes('def ') || content.includes('async def');
assert.ok(hasExpectedKeyword,
  `generatePython output should contain 'class', 'def', or 'async def'. Got:\n${content.slice(0, 200)}`);

console.log('api-client-python-smoke: all tests passed');
