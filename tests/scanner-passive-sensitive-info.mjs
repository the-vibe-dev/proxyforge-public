// Tests for passive sensitive-info detection rules:
//   clientConfigSecretLike, googleApiKeyLeak, gitHubTokenLeak, creditCardNumberLeak, emailLeak
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

function tryLoad(name) {
  try {
    return require(`../dist-electron/src/scanner/passive/${name}.js`);
  } catch {
    try {
      return require(`../src/scanner/passive/${name}.ts`);
    } catch {
      return null;
    }
  }
}

const mods = {
  clientConfigSecretLike: tryLoad('clientConfigSecretLike'),
  googleApiKeyLeak: tryLoad('googleApiKeyLeak'),
  gitHubTokenLeak: tryLoad('gitHubTokenLeak'),
  creditCardNumberLeak: tryLoad('creditCardNumberLeak'),
  emailLeak: tryLoad('emailLeak'),
};

const missing = Object.entries(mods).filter(([, m]) => !m).map(([n]) => n);
if (missing.length === Object.keys(mods).length) {
  console.error('Could not load any sensitive-info modules. Build first: npm run build:electron');
  process.exit(1);
}
if (missing.length > 0) {
  console.warn(`Warning: could not load modules: ${missing.join(', ')} — skipping those tests`);
}

function makeResponse(body, { status = 200, contentType = 'application/javascript' } = {}) {
  return `HTTP/1.1 ${status} OK\r\nContent-Type: ${contentType}\r\n\r\n${body}`;
}

// ── clientConfigSecretLike ──────────────────────────────────────────────────
if (mods.clientConfigSecretLike) {
  const { check } = mods.clientConfigSecretLike;

  // Should fire: api_key in JS bundle
  {
    const resp = makeResponse(`var config = { api_key: "AbCdEfGhIjKlMnOpQrStUvWx12345" };`);
    const result = check('', resp, 'https://example.com/app.js');
    assert.ok(result !== null, '[clientConfigSecretLike] Should detect api_key pattern in JS');
    assert.equal(result.checkId, 'client-config-secret');
    assert.equal(result.severity, 'high');
  }

  // Should fire: token= pattern
  {
    const resp = makeResponse(`window.__ENV__ = { token: "AAAAABBBBCCCCDDDDEEEEFFFFF1234" };`);
    const result = check('', resp, 'https://example.com/bundle.js');
    assert.ok(result !== null, '[clientConfigSecretLike] Should detect token= pattern');
  }

  // Should NOT fire: value too short
  {
    const resp = makeResponse(`var x = { api_key: "short" };`);
    const result = check('', resp, 'https://example.com/bundle.js');
    assert.equal(result, null, '[clientConfigSecretLike] Should not fire on short value');
  }

  // Should NOT fire: plain HTML response with no secrets
  {
    const resp = makeResponse('<h1>Hello world</h1>', { contentType: 'text/html' });
    const result = check('', resp);
    assert.equal(result, null, '[clientConfigSecretLike] Should not fire on plain HTML');
  }

  console.log('  PASS clientConfigSecretLike (4 assertions)');
}

// ── googleApiKeyLeak ────────────────────────────────────────────────────────
if (mods.googleApiKeyLeak) {
  const { check } = mods.googleApiKeyLeak;

  // Should fire: AIza pattern of correct length (39 chars total)
  {
    const key = 'AIza' + 'A'.repeat(35);
    const resp = makeResponse(`var MAPS_KEY = "${key}";`, { contentType: 'text/html' });
    const result = check('', resp);
    assert.ok(result !== null, '[googleApiKeyLeak] Should detect AIza... key');
    assert.equal(result.checkId, 'google-api-key-leak');
    assert.equal(result.severity, 'high');
  }

  // Should NOT fire: AIza prefix but too short
  {
    const resp = makeResponse(`var x = "AIzaShort";`);
    const result = check('', resp);
    assert.equal(result, null, '[googleApiKeyLeak] Should not fire on short AIza string');
  }

  // Should NOT fire: no key at all
  {
    const resp = makeResponse(`var x = "nothing here";`);
    const result = check('', resp);
    assert.equal(result, null, '[googleApiKeyLeak] Should not fire when no key present');
  }

  console.log('  PASS googleApiKeyLeak (3 assertions)');
}

// ── gitHubTokenLeak ─────────────────────────────────────────────────────────
if (mods.gitHubTokenLeak) {
  const { check } = mods.gitHubTokenLeak;

  // Should fire: ghp_ token (personal access token, 36+ chars after prefix)
  {
    const token = 'ghp_' + 'A'.repeat(36);
    const resp = makeResponse(`GITHUB_TOKEN=${token}`, { contentType: 'text/plain' });
    const result = check('', resp);
    assert.ok(result !== null, '[gitHubTokenLeak] Should detect ghp_ token');
    assert.equal(result.checkId, 'github-token-leak');
    assert.equal(result.severity, 'critical');
    assert.equal(result.confidence, 'certain');
  }

  // Should fire: ghs_ (server-to-server token)
  {
    const token = 'ghs_' + 'B'.repeat(40);
    const resp = makeResponse(`{"token":"${token}"}`, { contentType: 'application/json' });
    const result = check('', resp);
    assert.ok(result !== null, '[gitHubTokenLeak] Should detect ghs_ token');
  }

  // Should NOT fire: too short
  {
    const resp = makeResponse(`ref: ghp_tiny`);
    const result = check('', resp);
    assert.equal(result, null, '[gitHubTokenLeak] Should not fire on short ghp_ value');
  }

  // Should NOT fire: no token
  {
    const resp = makeResponse(`{"status":"ok"}`);
    const result = check('', resp);
    assert.equal(result, null, '[gitHubTokenLeak] Should not fire when no token present');
  }

  console.log('  PASS gitHubTokenLeak (4 assertions)');
}

// ── creditCardNumberLeak ────────────────────────────────────────────────────
if (mods.creditCardNumberLeak) {
  const { check } = mods.creditCardNumberLeak;

  // Luhn-valid Visa test number: 4532015112830366
  {
    const resp = makeResponse(`{"card":"4532015112830366","name":"John"}`, { contentType: 'application/json' });
    const result = check('', resp);
    assert.ok(result !== null, '[creditCardNumberLeak] Should detect Luhn-valid card number');
    assert.equal(result.checkId, 'credit-card-leak');
    assert.equal(result.severity, 'critical');
  }

  // Luhn-valid Mastercard: 5425233430109903
  {
    const resp = makeResponse(`card number: 5425 2334 3010 9903`, { contentType: 'text/plain' });
    const result = check('', resp);
    assert.ok(result !== null, '[creditCardNumberLeak] Should detect spaced card number');
  }

  // Should NOT fire: Luhn-invalid number
  {
    const resp = makeResponse(`{"card":"1234567890123456"}`);
    const result = check('', resp);
    assert.equal(result, null, '[creditCardNumberLeak] Should not fire on Luhn-invalid number');
  }

  console.log('  PASS creditCardNumberLeak (3 assertions)');
}

// ── emailLeak ───────────────────────────────────────────────────────────────
if (mods.emailLeak) {
  const { check } = mods.emailLeak;

  // Should fire: email in response not in request
  {
    const req = 'GET /users HTTP/1.1\r\nHost: example.com\r\n\r\n';
    const resp = makeResponse(`{"email":"admin@example.com","role":"admin"}`, { contentType: 'application/json' });
    const result = check(req, resp);
    assert.ok(result !== null, '[emailLeak] Should detect email in response not in request');
    assert.equal(result.checkId, 'email-leak');
    assert.equal(result.severity, 'low');
  }

  // Should NOT fire: email echoed from request body
  {
    const req = 'POST /login HTTP/1.1\r\nHost: example.com\r\n\r\nemail=user@example.com';
    const resp = makeResponse(`{"email":"user@example.com","token":"abc"}`, { contentType: 'application/json' });
    const result = check(req, resp);
    assert.equal(result, null, '[emailLeak] Should not fire when email was in request');
  }

  // Should NOT fire: no email in response
  {
    const req = 'GET /api/data HTTP/1.1\r\n\r\n';
    const resp = makeResponse(`{"status":"ok","count":42}`);
    const result = check(req, resp);
    assert.equal(result, null, '[emailLeak] Should not fire when no email in response');
  }

  // Should fire: multiple emails leaked
  {
    const req = 'GET /users HTTP/1.1\r\n\r\n';
    const resp = makeResponse(`[{"email":"alice@corp.com"},{"email":"bob@corp.com"}]`, { contentType: 'application/json' });
    const result = check(req, resp);
    assert.ok(result !== null, '[emailLeak] Should fire on multiple leaked emails');
    assert.ok(result.evidence?.includes('alice@corp.com'), '[emailLeak] Evidence should contain email');
  }

  console.log('  PASS emailLeak (4 assertions)');
}

console.log('PASS scanner-passive-sensitive-info');
