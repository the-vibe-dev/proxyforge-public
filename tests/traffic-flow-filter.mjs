// Tests: flow filter DSL — ~u, ~m, ~c, ~h, & (and), | (or), ! (not)
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { compileFilter, matchesFilter, filterExchanges, parseFlowFilter } =
  require('../dist-electron/traffic/flowFilter.js');

// ─── Fixture exchanges ────────────────────────────────────────────────────────

const getExchange = {
  url: 'https://example.com/api/users?page=2',
  method: 'GET',
  status: 200,
  host: 'example.com',
  path: '/api/users',
  requestRaw: 'GET /api/users?page=2 HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer token123\r\n\r\n',
  responseRaw: 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"users":[]}',
  source: 'proxy',
};

const postExchange = {
  url: 'https://api.example.org/login',
  method: 'POST',
  status: 401,
  host: 'api.example.org',
  path: '/login',
  requestRaw: 'POST /login HTTP/1.1\r\nHost: api.example.org\r\nContent-Type: application/json\r\n\r\n{"user":"alice"}',
  responseRaw: 'HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer\r\n\r\n',
  source: 'proxy',
};

const scanExchange = {
  url: 'https://target.internal/admin',
  method: 'POST',
  status: 500,
  host: 'target.internal',
  path: '/admin',
  requestRaw: 'POST /admin HTTP/1.1\r\nHost: target.internal\r\n\r\npayload',
  responseRaw: 'HTTP/1.1 500 Internal Server Error\r\n\r\nserver error',
  source: 'scanner',
};

try {
  // ── ~u (URL filter) ────────────────────────────────────────────────────────
  {
    const f = compileFilter('~u example.com');
    assert(f(getExchange), '~u example.com should match example.com URL');
    assert(!f(postExchange), '~u example.com should not match api.example.org URL (different TLD)');
    assert(!f(scanExchange), '~u example.com should not match target.internal URL');
  }

  {
    const f = compileFilter('~u /api/');
    assert(f(getExchange), '~u /api/ should match URL with /api/');
    assert(!f(postExchange), '~u /api/ should not match /login');
  }

  // ── ~m (method filter) ────────────────────────────────────────────────────
  {
    const f = compileFilter('~m GET');
    assert(f(getExchange), '~m GET should match GET');
    assert(!f(postExchange), '~m GET should not match POST');
  }

  {
    const f = compileFilter('~m POST');
    assert(f(postExchange), '~m POST should match POST');
    assert(f(scanExchange), '~m POST should match scanner POST');
    assert(!f(getExchange), '~m POST should not match GET');
  }

  // ── ~c (status code filter) ───────────────────────────────────────────────
  {
    const f = compileFilter('~c 200');
    assert(f(getExchange), '~c 200 should match status 200');
    assert(!f(postExchange), '~c 200 should not match status 401');
  }

  {
    const f = compileFilter('~c 400-499');
    assert(f(postExchange), '~c 400-499 range should match 401');
    assert(!f(getExchange), '~c 400-499 should not match 200');
    assert(!f(scanExchange), '~c 400-499 should not match 500');
  }

  {
    const f = compileFilter('~c 500');
    assert(f(scanExchange), '~c 500 should match 500');
  }

  // ── ~h (header filter) ────────────────────────────────────────────────────
  {
    const f = compileFilter('~h Authorization');
    assert(f(getExchange), '~h Authorization should match exchange with Authorization header');
    assert(!f(scanExchange), '~h Authorization should not match exchange without it');
  }

  {
    const f = compileFilter('~h Content-Type');
    assert(f(postExchange), '~h Content-Type should match POST with Content-Type');
  }

  // ── & (AND operator) ──────────────────────────────────────────────────────
  {
    const f = compileFilter('~m GET & ~c 200');
    assert(f(getExchange), 'GET AND 200 should match getExchange');
    assert(!f(postExchange), 'GET AND 200 should not match 401 POST');
    assert(!f(scanExchange), 'GET AND 200 should not match 500 POST');
  }

  {
    const f = compileFilter('~m POST & ~c 400-499');
    assert(f(postExchange), 'POST AND 4xx should match 401 POST');
    assert(!f(scanExchange), 'POST AND 4xx should not match 500 POST');
    assert(!f(getExchange), 'POST AND 4xx should not match 200 GET');
  }

  // ── | (OR operator) ───────────────────────────────────────────────────────
  {
    const f = compileFilter('~c 200 | ~c 401');
    assert(f(getExchange), '200 OR 401 should match 200');
    assert(f(postExchange), '200 OR 401 should match 401');
    assert(!f(scanExchange), '200 OR 401 should not match 500');
  }

  {
    const f = compileFilter('~m GET | ~m POST');
    assert(f(getExchange), 'GET OR POST should match GET');
    assert(f(postExchange), 'GET OR POST should match POST');
  }

  // ── ! (NOT operator) ──────────────────────────────────────────────────────
  {
    const f = compileFilter('! ~m POST');
    assert(f(getExchange), 'NOT POST should match GET');
    assert(!f(postExchange), 'NOT POST should not match POST');
    assert(!f(scanExchange), 'NOT POST should not match scanner POST');
  }

  {
    const f = compileFilter('! ~c 200');
    assert(!f(getExchange), 'NOT 200 should not match 200');
    assert(f(postExchange), 'NOT 200 should match 401');
    assert(f(scanExchange), 'NOT 200 should match 500');
  }

  // ── Compound: NOT with AND ─────────────────────────────────────────────────
  {
    const f = compileFilter('~m POST & ! ~c 500');
    assert(f(postExchange), 'POST AND NOT 500 should match 401 POST');
    assert(!f(scanExchange), 'POST AND NOT 500 should not match 500 POST');
    assert(!f(getExchange), 'POST AND NOT 500 should not match GET');
  }

  // ── Compound: OR with AND (precedence) ────────────────────────────────────
  {
    // ~m GET | (~m POST & ~c 401)
    const f = compileFilter('~m GET | ~m POST & ~c 401');
    assert(f(getExchange), 'GET | (POST & 401) should match GET');
    assert(f(postExchange), 'GET | (POST & 401) should match 401 POST');
    assert(!f(scanExchange), 'GET | (POST & 401) should not match 500 POST');
  }

  // ── Parentheses ───────────────────────────────────────────────────────────
  {
    const f = compileFilter('(~m GET | ~m POST) & ~u example');
    assert(f(getExchange), '(GET|POST) AND example should match GET example.com');
    assert(f(postExchange), '(GET|POST) AND example should match POST api.example.org');
    assert(!f(scanExchange), '(GET|POST) AND example should not match target.internal POST');
  }

  // ── filterExchanges helper ────────────────────────────────────────────────
  {
    const all = [getExchange, postExchange, scanExchange];
    const errors = filterExchanges(all, '~c 500-599');
    assert.equal(errors.length, 1);
    assert.equal(errors[0].status, 500);

    const posts = filterExchanges(all, '~m POST');
    assert.equal(posts.length, 2);

    const empty = filterExchanges(all, '');
    assert.equal(empty.length, 3, 'Empty filter should return all exchanges');
  }

  // ── Bare pattern (URL substring) ─────────────────────────────────────────
  {
    const f = compileFilter('login');
    assert(f(postExchange), 'Bare pattern "login" should match URL containing "login"');
    assert(!f(getExchange), 'Bare pattern "login" should not match unrelated URL');
  }

  // ── parseFlowFilter returns AST ───────────────────────────────────────────
  {
    const node = parseFlowFilter('~m GET & ~c 200');
    assert.equal(node.kind, 'and');
    assert.equal(node.left.kind, 'method');
    assert.equal(node.right.kind, 'code');
    assert.equal(node.right.status, 200);
  }

  {
    const node = parseFlowFilter('');
    assert.equal(node.kind, 'all', 'Empty expression should parse to { kind: "all" }');
  }

  console.log('PASS traffic-flow-filter');
} catch (err) {
  console.error('FAIL traffic-flow-filter:', err.message);
  process.exit(1);
}
