// Tests for passive security-header checks:
//   antiClickjackingMissing, xContentTypeOptionsMissing, referrerPolicyMissing,
//   sameSiteCookieMissing, hstsMissing
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
  antiClickjackingMissing: tryLoad('antiClickjackingMissing'),
  xContentTypeOptionsMissing: tryLoad('xContentTypeOptionsMissing'),
  referrerPolicyMissing: tryLoad('referrerPolicyMissing'),
  sameSiteCookieMissing: tryLoad('sameSiteCookieMissing'),
  hstsMissing: tryLoad('hstsMissing'),
};

const missing = Object.entries(mods).filter(([, m]) => !m).map(([n]) => n);
if (missing.length === Object.keys(mods).length) {
  console.error('Could not load any security-header modules. Build first: npm run build:electron');
  process.exit(1);
}
if (missing.length > 0) {
  console.warn(`Warning: could not load modules: ${missing.join(', ')} — skipping those tests`);
}

function htmlResponse(extraHeaders = '', status = 200) {
  return `HTTP/1.1 ${status} OK\r\nContent-Type: text/html; charset=utf-8\r\n${extraHeaders}\r\n<html><body>Hello</body></html>`;
}

// ── antiClickjackingMissing ─────────────────────────────────────────────────
if (mods.antiClickjackingMissing) {
  const { check } = mods.antiClickjackingMissing;

  // Should fire: no X-Frame-Options, no CSP frame-ancestors
  {
    const result = check('', htmlResponse());
    assert.ok(result !== null, '[antiClickjacking] Should fire when XFO and frame-ancestors both absent');
    assert.equal(result.checkId, 'anti-clickjacking-missing');
    assert.equal(result.severity, 'medium');
  }

  // Should NOT fire: X-Frame-Options present
  {
    const result = check('', htmlResponse('X-Frame-Options: DENY\r\n'));
    assert.equal(result, null, '[antiClickjacking] Should not fire when X-Frame-Options is set');
  }

  // Should NOT fire: CSP with frame-ancestors
  {
    const result = check('', htmlResponse("Content-Security-Policy: frame-ancestors 'none'\r\n"));
    assert.equal(result, null, '[antiClickjacking] Should not fire when frame-ancestors CSP present');
  }

  // Should NOT fire: non-HTML response
  {
    const resp = `HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"ok":true}`;
    const result = check('', resp);
    assert.equal(result, null, '[antiClickjacking] Should not fire on JSON responses');
  }

  // Should NOT fire: 4xx response
  {
    const result = check('', htmlResponse('', 404));
    assert.equal(result, null, '[antiClickjacking] Should not fire on 404 response');
  }

  console.log('  PASS antiClickjackingMissing (5 assertions)');
}

// ── xContentTypeOptionsMissing ──────────────────────────────────────────────
if (mods.xContentTypeOptionsMissing) {
  const { check } = mods.xContentTypeOptionsMissing;

  // Should fire: header absent
  {
    const result = check('', htmlResponse());
    assert.ok(result !== null, '[xContentTypeOptions] Should fire when header absent');
    assert.equal(result.checkId, 'x-content-type-options-missing');
    assert.equal(result.severity, 'low');
  }

  // Should NOT fire: nosniff present
  {
    const result = check('', htmlResponse('X-Content-Type-Options: nosniff\r\n'));
    assert.equal(result, null, '[xContentTypeOptions] Should not fire when nosniff set');
  }

  // Should fire: header present but wrong value
  {
    const result = check('', htmlResponse('X-Content-Type-Options: sniff\r\n'));
    assert.ok(result !== null, '[xContentTypeOptions] Should fire when value is not nosniff');
    assert.ok(result.evidence?.includes('sniff'), '[xContentTypeOptions] Evidence should note wrong value');
  }

  // Should NOT fire: 3xx redirect
  {
    const resp = `HTTP/1.1 301 Moved Permanently\r\nLocation: /new\r\n\r\n`;
    const result = check('', resp);
    assert.equal(result, null, '[xContentTypeOptions] Should not fire on redirect');
  }

  console.log('  PASS xContentTypeOptionsMissing (4 assertions)');
}

// ── referrerPolicyMissing ───────────────────────────────────────────────────
if (mods.referrerPolicyMissing) {
  const { check } = mods.referrerPolicyMissing;

  // Should fire: Referrer-Policy absent on HTML 200
  {
    const result = check('', htmlResponse());
    assert.ok(result !== null, '[referrerPolicy] Should fire when header absent on HTML');
    assert.equal(result.checkId, 'referrer-policy-missing');
    assert.equal(result.severity, 'info');
  }

  // Should NOT fire: header present
  {
    const result = check('', htmlResponse('Referrer-Policy: strict-origin-when-cross-origin\r\n'));
    assert.equal(result, null, '[referrerPolicy] Should not fire when Referrer-Policy is set');
  }

  // Should NOT fire: non-HTML content type
  {
    const resp = `HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\nvar x=1;`;
    const result = check('', resp);
    assert.equal(result, null, '[referrerPolicy] Should not fire on JS responses');
  }

  // Should NOT fire: 404 response
  {
    const result = check('', htmlResponse('', 404));
    assert.equal(result, null, '[referrerPolicy] Should not fire on 404');
  }

  console.log('  PASS referrerPolicyMissing (4 assertions)');
}

// ── sameSiteCookieMissing ───────────────────────────────────────────────────
if (mods.sameSiteCookieMissing) {
  const { check } = mods.sameSiteCookieMissing;

  const authReq = 'GET /dashboard HTTP/1.1\r\nCookie: session=abc123\r\n\r\n';

  // Should fire: Set-Cookie without SameSite on authenticated response
  {
    const resp = `HTTP/1.1 200 OK\r\nSet-Cookie: session=newval; HttpOnly; Secure\r\n\r\n`;
    const result = check(authReq, resp);
    assert.ok(result !== null, '[sameSiteCookie] Should fire on cookie without SameSite');
    assert.equal(result.checkId, 'samesite-cookie-missing');
    assert.equal(result.severity, 'medium');
    assert.ok(result.evidence?.includes('session'), '[sameSiteCookie] Evidence should name the cookie');
  }

  // Should NOT fire: SameSite=Strict present
  {
    const resp = `HTTP/1.1 200 OK\r\nSet-Cookie: session=newval; HttpOnly; Secure; SameSite=Strict\r\n\r\n`;
    const result = check(authReq, resp);
    assert.equal(result, null, '[sameSiteCookie] Should not fire when SameSite=Strict is set');
  }

  // Should NOT fire: SameSite=Lax present
  {
    const resp = `HTTP/1.1 200 OK\r\nSet-Cookie: tracker=1; SameSite=Lax\r\n\r\n`;
    const result = check(authReq, resp);
    assert.equal(result, null, '[sameSiteCookie] Should not fire when SameSite=Lax is set');
  }

  // Should NOT fire: no Set-Cookie header
  {
    const resp = `HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html/>`;
    const result = check(authReq, resp);
    assert.equal(result, null, '[sameSiteCookie] Should not fire when no Set-Cookie present');
  }

  // Mixed: one cookie with, one without SameSite — should fire
  {
    const resp = `HTTP/1.1 200 OK\r\nSet-Cookie: good=1; SameSite=Lax\r\nSet-Cookie: bad=2; HttpOnly\r\n\r\n`;
    const result = check(authReq, resp);
    assert.ok(result !== null, '[sameSiteCookie] Should fire when at least one cookie lacks SameSite');
  }

  console.log('  PASS sameSiteCookieMissing (5 assertions)');
}

// ── hstsMissing (existing rule, new test) ───────────────────────────────────
if (mods.hstsMissing) {
  // hstsMissing uses the exchange object pattern (existing convention)
  const { check } = mods.hstsMissing;

  // Should fire: HTTPS response with no HSTS header
  {
    const exchange = {
      url: 'https://example.com/',
      requestRaw: 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n',
      responseRaw: 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html/>',
      status: 200,
      host: 'example.com',
    };
    const result = check(exchange);
    assert.ok(result.fired === true, '[hstsMissing] Should fire on HTTPS response without HSTS');
    assert.ok(result.evidence.length > 0, '[hstsMissing] Should produce evidence');
  }

  // Should NOT fire: HSTS present with sufficient max-age
  {
    const exchange = {
      url: 'https://example.com/',
      requestRaw: 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n',
      responseRaw: 'HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=63072000; includeSubDomains; preload\r\n\r\n',
      status: 200,
      host: 'example.com',
    };
    const result = check(exchange);
    assert.ok(result.fired === false, '[hstsMissing] Should not fire when HSTS is correctly set');
  }

  // Should NOT fire: non-HTTPS URL
  {
    const exchange = {
      url: 'http://example.com/',
      requestRaw: 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n',
      responseRaw: 'HTTP/1.1 200 OK\r\n\r\n',
      status: 200,
      host: 'example.com',
    };
    const result = check(exchange);
    assert.ok(result.fired === false, '[hstsMissing] Should not fire on HTTP (non-HTTPS) exchange');
  }

  // Should fire: HSTS max-age too short
  {
    const exchange = {
      url: 'https://example.com/',
      requestRaw: 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n',
      responseRaw: 'HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=3600\r\n\r\n',
      status: 200,
      host: 'example.com',
    };
    const result = check(exchange);
    assert.ok(result.fired === true, '[hstsMissing] Should fire when max-age is too short');
  }

  console.log('  PASS hstsMissing (4 assertions)');
}

console.log('PASS scanner-passive-security-headers');
