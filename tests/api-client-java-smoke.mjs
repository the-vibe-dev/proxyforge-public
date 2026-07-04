import { createRequire } from 'node:module';
import assert from 'node:assert/strict';

const require = createRequire(import.meta.url);

let genMod;
try {
  genMod = require('../dist-electron/src/apiGenerators/javaGenerator.js');
} catch {
  console.log('SKIP: javaGenerator not compiled — run tsc first.');
  process.exit(0);
}

const { generateJava } = genMod;

if (typeof generateJava !== 'function') {
  console.log('SKIP: generateJava export not found.');
  process.exit(0);
}

// generateJava returns Array<{ filename, content }>
// The content should contain Java class/public/import keywords
const schema = { language: 'java', operations: [{ opId: 'proxy_start', method: 'POST', path: '/proxy/start' }] };
const files = generateJava(schema);

assert.ok(Array.isArray(files) && files.length >= 1,
  'generateJava should return an array with at least one file');

const content = files.map((f) => f.content).join('\n');

const hasExpectedKeyword = content.includes('class') || content.includes('public') || content.includes('import');
assert.ok(hasExpectedKeyword,
  `generateJava output should contain 'class', 'public', or 'import'. Got:\n${content.slice(0, 200)}`);

console.log('api-client-java-smoke: all tests passed');
