// Phase 18 — Security regression: body / transcript size caps (runaway memory prevention)
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

function tryLoad(candidates) {
  for (const c of candidates) {
    try { return require(c); } catch { }
  }
  return null;
}

const mod = tryLoad([
  '../dist-electron/traffic/streamingCapture.js',
  '../dist-electron/electron/traffic/streamingCapture.js',
]);
assert.ok(mod, 'streamingCapture module must be loadable');

const { StreamCapture, capBodySize } = mod;
assert.ok(typeof StreamCapture === 'function', 'StreamCapture must be a constructor');
assert.ok(typeof capBodySize === 'function', 'capBodySize must be a function');

// ── Test 1: write() returns false after cap is reached ────────────────────
{
  const cap = new StreamCapture({ maxBodyBytes: 100, maxDurationMs: 60_000 });

  const chunk1 = Buffer.alloc(80, 0x41); // 80 bytes
  const chunk2 = Buffer.alloc(80, 0x42); // 80 bytes — would push total to 160, over cap

  const r1 = cap.write(chunk1);
  assert.ok(r1 === true, 'First write under cap must return true');
  assert.ok(!cap.isCapped(), 'Should not be capped after first write (80 < 100)');

  const r2 = cap.write(chunk2);
  assert.ok(r2 === false, 'Second write that exceeds cap must return false');
  assert.ok(cap.isCapped(), 'StreamCapture must be capped after exceeding maxBodyBytes');

  // bytesReceived must not exceed the cap
  assert.ok(
    cap.getBytesReceived() <= 100,
    `bytesReceived (${cap.getBytesReceived()}) must be <= cap (100)`,
  );

  // getBytes() must not exceed the cap
  const accumulated = cap.getBytes();
  assert.ok(
    accumulated.length <= 100,
    `Accumulated buffer (${accumulated.length}) must be <= cap (100)`,
  );
}

// ── Test 2: Subsequent writes after capping are all rejected ──────────────
{
  const cap = new StreamCapture({ maxBodyBytes: 50, maxDurationMs: 60_000 });
  cap.write(Buffer.alloc(60, 0x43)); // exceeds cap immediately

  assert.ok(cap.isCapped(), 'Should be capped after first oversized write');

  const r = cap.write(Buffer.alloc(10, 0x44));
  assert.ok(r === false, 'Any write after cap must return false');
  assert.ok(
    cap.getBytesReceived() <= 50,
    'bytesReceived must not increase after cap',
  );
}

// ── Test 3: Exact-size write hits cap, marks capped ──────────────────────
{
  const cap = new StreamCapture({ maxBodyBytes: 100, maxDurationMs: 60_000 });
  const r = cap.write(Buffer.alloc(100, 0x45));
  // After writing exactly 100 bytes, the cap is reached
  assert.ok(cap.isCapped(), 'Writing exactly maxBodyBytes must mark capture as capped');
  assert.ok(r === false, 'write() at exact cap boundary must return false');
  assert.equal(cap.getBytesReceived(), 100);
}

// ── Test 4: capBodySize truncates large buffers ────────────────────────────
{
  const TWO_MB = 2 * 1024 * 1024;
  const bigBody = Buffer.alloc(TWO_MB + 512, 0x46);

  const { body, capped, originalSize } = capBodySize(bigBody, TWO_MB);

  assert.ok(capped, 'capBodySize must report capped=true when body exceeds limit');
  assert.equal(body.length, TWO_MB, `Truncated body must be exactly maxBytes (${TWO_MB})`);
  assert.equal(originalSize, TWO_MB + 512, 'originalSize must reflect the full input length');
}

// ── Test 5: capBodySize does not truncate body within limit ───────────────
{
  const smallBody = Buffer.from('hello world');
  const { body, capped, originalSize } = capBodySize(smallBody, 1024);

  assert.ok(!capped, 'capBodySize must report capped=false when body fits within limit');
  assert.equal(body.length, smallBody.length, 'Body within limit must be returned unchanged');
  assert.equal(originalSize, smallBody.length);
}

// ── Test 6: Security-focused — 10 MB response cannot exhaust memory cap ───
{
  const TEN_MB_CAP = 10 * 1024 * 1024;
  const maliciousBody = Buffer.alloc(TEN_MB_CAP + 1, 0x47); // 1 byte over cap
  const { body, capped } = capBodySize(maliciousBody, TEN_MB_CAP);
  assert.ok(capped, 'Body exceeding 10 MB cap must be truncated');
  assert.equal(body.length, TEN_MB_CAP, 'Capped body must be exactly 10 MB');
}

// ── Test 7: Duration cap triggers after elapsed time ─────────────────────
// We fake elapsed time by creating the capture with a 0 ms duration limit
{
  const cap = new StreamCapture({ maxBodyBytes: 10_000, maxDurationMs: 0 });
  // Even a small chunk should be rejected because elapsed >= 0
  const r = cap.write(Buffer.alloc(10, 0x48));
  assert.ok(r === false, 'Duration-capped StreamCapture must reject writes immediately');
  assert.ok(cap.isCapped(), 'Should be capped when duration limit is 0 ms');
}

// ── Test 8: isComplete() only true after end() ────────────────────────────
{
  const cap = new StreamCapture({ maxBodyBytes: 1000, maxDurationMs: 60_000 });
  assert.ok(!cap.isComplete(), 'isComplete() must be false before end()');
  cap.end();
  assert.ok(cap.isComplete(), 'isComplete() must be true after end()');
}

console.log('PASS security-regression-body-caps');
