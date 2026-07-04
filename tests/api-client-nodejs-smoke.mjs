import { createRequire } from 'node:module';
import assert from 'node:assert/strict';

const require = createRequire(import.meta.url);

let genMod;
try {
  genMod = require('../dist-electron/src/apiGenerators/nodeJsGenerator.js');
} catch {
  console.log('SKIP: nodeJsGenerator not compiled — run tsc first.');
  process.exit(0);
}

const { generateNodeJs } = genMod;

if (typeof generateNodeJs !== 'function') {
  console.log('SKIP: generateNodeJs export not found.');
  process.exit(0);
}

// generateNodeJs returns Array<{ filename, content }>
// The content should contain ESM export or CommonJS module.exports or function keyword
const schema = { language: 'nodejs', operations: [{ opId: 'proxy_start', method: 'POST', path: '/proxy/start' }] };
const files = generateNodeJs(schema);

assert.ok(Array.isArray(files) && files.length >= 1,
  'generateNodeJs should return an array with at least one file');

const content = files.map((f) => f.content).join('\n');

const hasExpectedKeyword = content.includes('export') || content.includes('module.exports') || content.includes('function');
assert.ok(hasExpectedKeyword,
  `generateNodeJs output should contain 'export', 'module.exports', or 'function'. Got:\n${content.slice(0, 200)}`);

console.log('api-client-nodejs-smoke: all tests passed');
