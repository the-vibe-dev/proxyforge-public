// Master test runner — discovers all tests/*.mjs files (except itself) and
// runs each with `node <file>`.  Prints a summary and exits with code 1 if
// any file fails.
//
// Per-file markers (first 10 lines of each test file):
//   // run-all: skip          — exclude from default run (CI orchestrators, etc.)
//   // run-all: slow          — allow 120 s instead of 10 s
//   // run-all: args <args>   — pass extra CLI args when spawning

import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SELF = fileURLToPath(import.meta.url);
const TESTS_DIR = path.dirname(SELF);
const DEFAULT_TIMEOUT_MS = 10_000;
const SLOW_TIMEOUT_MS = 120_000;

// ---------------------------------------------------------------------------
// Discover test files
// ---------------------------------------------------------------------------

const entries = await fs.readdir(TESTS_DIR);
const allFiles = entries
  .filter((f) => f.endsWith('.mjs') && path.resolve(TESTS_DIR, f) !== SELF)
  .sort()
  .map((f) => path.resolve(TESTS_DIR, f));

if (allFiles.length === 0) {
  console.log('run-all: no test files found');
  process.exit(0);
}

// ---------------------------------------------------------------------------
// Read per-file markers
// ---------------------------------------------------------------------------

async function readMarkers(filePath) {
  try {
    const content = await fs.readFile(filePath, 'utf8');
    const firstLines = content.split('\n').slice(0, 10).join('\n');
    return {
      skip: /\/\/\s*run-all:\s*skip\b/.test(firstLines),
      slow: /\/\/\s*run-all:\s*slow\b/.test(firstLines),
      extraArgs: (() => {
        const m = firstLines.match(/\/\/\s*run-all:\s*args\s+(.+)/);
        return m ? m[1].trim().split(/\s+/) : [];
      })(),
    };
  } catch {
    return { skip: false, slow: false, extraArgs: [] };
  }
}

const testFiles = [];
let skipped = 0;
for (const f of allFiles) {
  const markers = await readMarkers(f);
  if (markers.skip) {
    skipped++;
  } else {
    testFiles.push({ filePath: f, markers });
  }
}

// ---------------------------------------------------------------------------
// Run a single test file
// ---------------------------------------------------------------------------

function runFile(filePath, markers) {
  const label = path.basename(filePath);
  const timeoutMs = markers.slow ? SLOW_TIMEOUT_MS : DEFAULT_TIMEOUT_MS;
  const extraArgs = markers.extraArgs ?? [];
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [filePath, ...extraArgs], {
      cwd: path.resolve(TESTS_DIR, '..'),
      env: { ...process.env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
    child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });

    const timer = setTimeout(() => {
      child.kill('SIGTERM');
      resolve({ label, passed: false, timedOut: true, timeoutMs, stdout, stderr });
    }, timeoutMs);

    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ label, passed: code === 0, timedOut: false, stdout, stderr, code });
    });
  });
}

// ---------------------------------------------------------------------------
// Run all test files sequentially and collect results
// ---------------------------------------------------------------------------

let passed = 0;
let failed = 0;

for (const { filePath, markers } of testFiles) {
  const label = path.basename(filePath);
  process.stdout.write(`  ${label} ... `);

  const result = await runFile(filePath, markers);

  if (result.passed) {
    passed++;
    process.stdout.write('✓\n');
  } else {
    failed++;
    if (result.timedOut) {
      process.stdout.write(`✗  (timed out after ${result.timeoutMs / 1000}s)\n`);
    } else {
      process.stdout.write(`✗  (exit code ${result.code})\n`);
    }
    // Print captured output for failed tests so the cause is visible
    if (result.stdout.trim()) {
      process.stdout.write(result.stdout.trimEnd().split('\n').map((l) => '    ' + l).join('\n') + '\n');
    }
    if (result.stderr.trim()) {
      process.stderr.write(result.stderr.trimEnd().split('\n').map((l) => '    ' + l).join('\n') + '\n');
    }
  }
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

const total = passed + failed;
console.log('');
if (skipped > 0) {
  console.log(`${passed}/${total} test files passed  (${skipped} skipped)`);
} else {
  console.log(`${passed}/${total} test files passed`);
}

process.exit(failed > 0 ? 1 : 0);
