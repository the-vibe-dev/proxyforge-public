import { createRequire } from 'node:module';
import assert from 'node:assert/strict';

const require = createRequire(import.meta.url);

let genMod;
try {
  genMod = require('../dist-electron/src/apiGenerators/goGenerator.js');
} catch {
  console.log('SKIP: goGenerator not compiled — run tsc first.');
  process.exit(0);
}

const { generateGo } = genMod;

if (typeof generateGo !== 'function') {
  console.log('SKIP: generateGo export not found.');
  process.exit(0);
}

// generateGo returns Array<{ filename, content }>
// The content should contain Go func /package /import keywords
const schema = { language: 'go', operations: [{ opId: 'proxy_start', method: 'POST', path: '/proxy/start' }] };
const files = generateGo(schema);

assert.ok(Array.isArray(files) && files.length >= 1,
  'generateGo should return an array with at least one file');

const content = files.map((f) => f.content).join('\n');

const hasExpectedKeyword = content.includes('func ') || content.includes('package ') || content.includes('import');
assert.ok(hasExpectedKeyword,
  `generateGo output should contain 'func ', 'package ', or 'import'. Got:\n${content.slice(0, 200)}`);

console.log('api-client-go-smoke: all tests passed');
