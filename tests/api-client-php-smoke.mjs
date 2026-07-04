import { createRequire } from 'node:module';
import assert from 'node:assert/strict';

const require = createRequire(import.meta.url);

let genMod;
try {
  genMod = require('../dist-electron/src/apiGenerators/phpGenerator.js');
} catch {
  console.log('SKIP: phpGenerator not compiled — run tsc first.');
  process.exit(0);
}

const { generatePhp } = genMod;

if (typeof generatePhp !== 'function') {
  console.log('SKIP: generatePhp export not found.');
  process.exit(0);
}

// generatePhp returns Array<{ filename, content }>
// The content should contain PHP class /function /<?php keywords
const schema = { language: 'php', operations: [{ opId: 'proxy_start', method: 'POST', path: '/proxy/start' }] };
const files = generatePhp(schema);

assert.ok(Array.isArray(files) && files.length >= 1,
  'generatePhp should return an array with at least one file');

const content = files.map((f) => f.content).join('\n');

const hasExpectedKeyword = content.includes('class ') || content.includes('function ') || content.includes('<?php');
assert.ok(hasExpectedKeyword,
  `generatePhp output should contain 'class ', 'function ', or '<?php'. Got:\n${content.slice(0, 200)}`);

console.log('api-client-php-smoke: all tests passed');
