import { createRequire } from 'node:module';
import assert from 'node:assert/strict';

const require = createRequire(import.meta.url);

let genMod;
try {
  genMod = require('../dist-electron/src/apiGenerators/rustGenerator.js');
} catch {
  console.log('SKIP: rustGenerator not compiled — run tsc first.');
  process.exit(0);
}

const { generateRust } = genMod;

if (typeof generateRust !== 'function') {
  console.log('SKIP: generateRust export not found.');
  process.exit(0);
}

// generateRust returns Array<{ filename, content }>
// The content should contain Rust fn /pub /use keywords
const schema = { language: 'rust', operations: [{ opId: 'proxy_start', method: 'POST', path: '/proxy/start' }] };
const files = generateRust(schema);

assert.ok(Array.isArray(files) && files.length >= 1,
  'generateRust should return an array with at least one file');

const content = files.map((f) => f.content).join('\n');

const hasExpectedKeyword = content.includes('fn ') || content.includes('pub ') || content.includes('use ');
assert.ok(hasExpectedKeyword,
  `generateRust output should contain 'fn ', 'pub ', or 'use '. Got:\n${content.slice(0, 200)}`);

console.log('api-client-rust-smoke: all tests passed');
