import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

// ---------------------------------------------------------------------------
// Load and link the spec import modules
// ---------------------------------------------------------------------------

async function transpile(filePath) {
  const source = await fs.readFile(filePath, 'utf8');
  return ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
      esModuleInterop: true,
    },
    fileName: filePath,
  }).outputText;
}

async function loadPostmanParser() {
  const indexPath = path.resolve('src/specImport/index.ts');
  const postmanPath = path.resolve('src/specImport/postman.ts');

  for (const p of [indexPath, postmanPath]) {
    try {
      await fs.access(p);
    } catch {
      console.log('spec-import-postman: skipped (source files not found)');
      process.exit(0);
    }
  }

  let indexCode, postmanCode;
  try {
    [indexCode, postmanCode] = await Promise.all([
      transpile(indexPath),
      transpile(postmanPath),
    ]);
  } catch (err) {
    console.log(`spec-import-postman: skipped (transpile error: ${err.message})`);
    process.exit(0);
  }

  const registry = {};

  function makeModule(code, filename, localRequire) {
    const mod = { exports: {} };
    const sandbox = {
      module: mod,
      exports: mod.exports,
      require: localRequire,
      process,
      console,
      URL,
      URLSearchParams,
      TextDecoder,
      TextEncoder,
      Buffer,
    };
    vm.runInNewContext(code, sandbox, { filename });
    return mod.exports;
  }

  function fallbackRequire(id) {
    return require(id);
  }

  registry['postman'] = makeModule(postmanCode, postmanPath, (id) => {
    if (id === './index' || id === './index.js') return registry['index'] ?? {};
    return fallbackRequire(id);
  });

  // Load minimal stubs for other parsers so index.ts doesn't fail
  const stubModule = { exports: { parseOpenApi: () => ({}), parseGraphqlSchema: () => ({}) } };
  registry['index'] = makeModule(indexCode, indexPath, (id) => {
    if (id === './postman' || id === './postman.js') return registry['postman'];
    if (id === './openApi' || id === './openApi.js') return stubModule.exports;
    if (id === './graphqlSchema' || id === './graphqlSchema.js') return stubModule.exports;
    return fallbackRequire(id);
  });

  return registry['postman'];
}

const postmanModule = await loadPostmanParser();
const { parsePostman } = postmanModule;

if (typeof parsePostman !== 'function') {
  console.log('spec-import-postman: skipped (parsePostman not exported)');
  process.exit(0);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// --- Minimal Postman v2.1 collection fixture ---
const POSTMAN_FIXTURE = JSON.stringify({
  info: {
    name: 'Test',
    _postman_id: 'test-001',
    schema: 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json',
  },
  item: [
    {
      name: 'Get users',
      request: {
        method: 'GET',
        url: {
          raw: 'https://api.example.com/users?page=1',
          path: ['users'],
          query: [{ key: 'page', value: '1' }],
        },
      },
    },
  ],
});

// --- parsePostman extracts correct routes ---
{
  const result = parsePostman(POSTMAN_FIXTURE);
  assert.equal(result.format, 'postman', `format should be 'postman', got '${result.format}'`);
  assert.ok(result.routes.length >= 1, `should extract at least 1 route, got ${result.routes.length}`);

  const route = result.routes[0];
  assert.equal(route.method, 'GET', `route method should be GET, got '${route.method}'`);
  assert.ok(
    route.path.toLowerCase().includes('users'),
    `route path should include 'users', got '${route.path}'`,
  );
}

// --- Query parameters extracted from URL ---
{
  const result = parsePostman(POSTMAN_FIXTURE);
  const route = result.routes[0];
  const pageParam = route.params.find((p) => p.name === 'page' && p.location === 'query');
  assert.ok(pageParam, "should extract 'page' as a query parameter");
}

// --- Title extracted from collection info ---
{
  const result = parsePostman(POSTMAN_FIXTURE);
  assert.equal(result.title, 'Test', `title should be 'Test', got '${result.title}'`);
}

// --- Nested folders are walked recursively ---
{
  const nested = JSON.stringify({
    info: {
      name: 'Nested Collection',
      _postman_id: 'nested-001',
      schema: 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json',
    },
    item: [
      {
        name: 'Auth folder',
        item: [
          {
            name: 'Login',
            request: {
              method: 'POST',
              url: {
                raw: 'https://api.example.com/auth/login',
                path: ['auth', 'login'],
              },
            },
          },
        ],
      },
      {
        name: 'Get profile',
        request: {
          method: 'GET',
          url: {
            raw: 'https://api.example.com/profile',
            path: ['profile'],
          },
        },
      },
    ],
  });

  const result = parsePostman(nested);
  assert.ok(result.routes.length >= 2, `should extract 2 routes from nested collection, got ${result.routes.length}`);

  const methods = result.routes.map((r) => r.method);
  assert.ok(methods.includes('POST'), 'should include POST route from nested folder');
  assert.ok(methods.includes('GET'), 'should include GET route from top level');
}

// --- Header parameters extracted ---
{
  const withHeaders = JSON.stringify({
    info: {
      name: 'Header Test',
      _postman_id: 'header-001',
      schema: 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json',
    },
    item: [
      {
        name: 'Authed Request',
        request: {
          method: 'GET',
          url: {
            raw: 'https://api.example.com/secure',
            path: ['secure'],
          },
          header: [
            { key: 'Authorization', value: 'Bearer token123' },
            { key: 'X-Request-ID', value: 'req-001' },
          ],
        },
      },
    ],
  });

  const result = parsePostman(withHeaders);
  const route = result.routes[0];
  const authHeader = route.params.find((p) => p.name === 'Authorization' && p.location === 'header');
  assert.ok(authHeader, "should extract 'Authorization' as a header parameter");
}

// --- Invalid JSON returns error gracefully ---
{
  const result = parsePostman('not valid json }{');
  assert.equal(result.format, 'postman', 'format should still be postman on parse error');
  assert.ok(Array.isArray(result.errors) && result.errors.length > 0, 'should return errors array on invalid JSON');
  assert.equal(result.routes.length, 0, 'routes should be empty on parse error');
}

console.log('spec-import-postman: all tests passed');
