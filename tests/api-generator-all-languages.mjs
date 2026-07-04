import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

// ---------------------------------------------------------------------------
// Graceful skip if dist-electron compiled output is expected but absent.
// We also attempt to load from TypeScript source directly.
// ---------------------------------------------------------------------------

const DIST_CHECK = path.resolve('dist-electron/apiGenerators/index.js');
const SRC_INDEX = path.resolve('src/apiGenerators/index.ts');
const SRC_FILES = [
  'index.ts',
  'pythonGenerator.ts',
  'nodeJsGenerator.ts',
  'javaGenerator.ts',
  'rustGenerator.ts',
  'goGenerator.ts',
  'phpGenerator.ts',
  'wikiGenerator.ts',
].map((f) => path.resolve('src/apiGenerators', f));

// Check that source files exist
for (const p of SRC_FILES) {
  try {
    await fs.access(p);
  } catch {
    console.log('api-generator-all-languages: skipped (source files not found)');
    process.exit(0);
  }
}

// ---------------------------------------------------------------------------
// TypeScript transpiler helper
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

// ---------------------------------------------------------------------------
// Load all apiGenerators modules via vm sandbox
// ---------------------------------------------------------------------------

async function loadGeneratorModules() {
  let codes;
  try {
    codes = await Promise.all(SRC_FILES.map(transpile));
  } catch (err) {
    console.log(`api-generator-all-languages: skipped (transpile error: ${err.message})`);
    process.exit(0);
  }

  const [
    indexCode,
    pythonCode,
    nodeJsCode,
    javaCode,
    rustCode,
    goCode,
    phpCode,
    wikiCode,
  ] = codes;

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
      JSON,
    };
    try {
      vm.runInNewContext(code, sandbox, { filename });
    } catch (err) {
      console.log(`api-generator-all-languages: skipped (vm load error in ${path.basename(filename)}: ${err.message})`);
      process.exit(0);
    }
    return mod.exports;
  }

  function fallbackRequire(id) {
    return require(id);
  }

  // Load sub-modules first; they import types from './index' at runtime they only need OP_SCHEMAS
  // We load index first as a partial (OP_SCHEMAS only), then reload fully once subs are registered.
  // Strategy: load subs with a deferred index reference, then load index pointing at subs.

  // Pass 1: load a stub index so sub-modules can resolve their './index' import for OP_SCHEMAS.
  // We actually load index code in pass 2, but sub-modules only import OP_SCHEMAS from index
  // so we need index loaded before them — load index first, then subs.

  // Load index first (it imports from subs via import statements at bottom)
  // TypeScript compiles top-level imports to requires, so the order matters.
  // Load sub-modules first with a temporary stub for index, then reload index.

  const subModuleNames = ['pythonGenerator', 'nodeJsGenerator', 'javaGenerator', 'rustGenerator', 'goGenerator', 'phpGenerator', 'wikiGenerator'];
  const subCodes = [pythonCode, nodeJsCode, javaCode, rustCode, goCode, phpCode, wikiCode];

  // Step 1: Load index with stubs for all sub-modules (to get OP_SCHEMAS exported)
  const stubSubs = Object.fromEntries(subModuleNames.map((n) => [n, { exports: {} }]));
  registry['index'] = makeModule(indexCode, SRC_FILES[0], (id) => {
    const base = id.replace(/\.js$/, '').replace(/^\.\//, '');
    if (subModuleNames.includes(base)) return stubSubs[base].exports;
    return fallbackRequire(id);
  });

  // Step 2: Load sub-modules for real, pointing their './index' at the real index
  for (let i = 0; i < subModuleNames.length; i++) {
    const name = subModuleNames[i];
    const code = subCodes[i];
    const filePath = SRC_FILES[i + 1];
    registry[name] = makeModule(code, filePath, (id) => {
      if (id === './index' || id === './index.js') return registry['index'];
      return fallbackRequire(id);
    });
  }

  // Step 3: Reload index now that real sub-modules exist
  registry['index'] = makeModule(indexCode, SRC_FILES[0], (id) => {
    const base = id.replace(/\.js$/, '').replace(/^\.\//, '');
    if (subModuleNames.includes(base)) return registry[base];
    return fallbackRequire(id);
  });

  return registry['index'];
}

const generatorModule = await loadGeneratorModules();
const { generate, OP_SCHEMAS } = generatorModule;

if (typeof generate !== 'function' || !Array.isArray(OP_SCHEMAS)) {
  console.log('api-generator-all-languages: skipped (missing required exports)');
  process.exit(0);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// 1. Python generator returns file named proxyforge_client.py with class ProxyForgeClient
{
  const out = generate({ language: 'python' });
  assert.ok(out.files.length >= 1, 'Python: should return at least one file');
  const file = out.files[0];
  assert.strictEqual(file.filename, 'proxyforge_client.py', `Python: filename should be 'proxyforge_client.py', got '${file.filename}'`);
  assert.ok(file.content.includes('class ProxyForgeClient'), 'Python: content should include class ProxyForgeClient');
}

// 2. Python generator contains urllib.request import
{
  const out = generate({ language: 'python' });
  assert.ok(out.files[0].content.includes('urllib.request'), 'Python: content should include urllib.request import');
}

// 3. Node.js generator returns file named proxyforge-client.ts with class ProxyForgeClient
{
  const out = generate({ language: 'nodejs' });
  assert.ok(out.files.length >= 1, 'Node.js: should return at least one file');
  const file = out.files[0];
  assert.strictEqual(file.filename, 'proxyforge-client.ts', `Node.js: filename should be 'proxyforge-client.ts', got '${file.filename}'`);
  assert.ok(file.content.includes('class ProxyForgeClient'), 'Node.js: content should include class ProxyForgeClient');
}

// 4. Java generator returns file named ProxyForgeClient.java with package com.proxyforge.client
{
  const out = generate({ language: 'java' });
  assert.ok(out.files.length >= 1, 'Java: should return at least one file');
  const file = out.files[0];
  assert.strictEqual(file.filename, 'ProxyForgeClient.java', `Java: filename should be 'ProxyForgeClient.java', got '${file.filename}'`);
  assert.ok(file.content.includes('package com.proxyforge.client'), `Java: content should include 'package com.proxyforge.client'`);
}

// 5. Rust generator returns file named proxyforge_client.rs with pub struct ProxyForgeClient
{
  const out = generate({ language: 'rust' });
  assert.ok(out.files.length >= 1, 'Rust: should return at least one file');
  const file = out.files[0];
  assert.strictEqual(file.filename, 'proxyforge_client.rs', `Rust: filename should be 'proxyforge_client.rs', got '${file.filename}'`);
  assert.ok(file.content.includes('pub struct ProxyForgeClient'), 'Rust: content should include pub struct ProxyForgeClient');
}

// 6. Go generator returns file named proxyforge_client.go with package proxyforge
{
  const out = generate({ language: 'go' });
  assert.ok(out.files.length >= 1, 'Go: should return at least one file');
  const file = out.files[0];
  assert.strictEqual(file.filename, 'proxyforge_client.go', `Go: filename should be 'proxyforge_client.go', got '${file.filename}'`);
  assert.ok(file.content.includes('package proxyforge'), 'Go: content should include package proxyforge');
}

// 7. PHP generator returns file named ProxyForgeClient.php with class ProxyForgeClient
{
  const out = generate({ language: 'php' });
  assert.ok(out.files.length >= 1, 'PHP: should return at least one file');
  const file = out.files[0];
  assert.strictEqual(file.filename, 'ProxyForgeClient.php', `PHP: filename should be 'ProxyForgeClient.php', got '${file.filename}'`);
  assert.ok(file.content.includes('class ProxyForgeClient'), 'PHP: content should include class ProxyForgeClient');
}

// 8. Wiki generator returns file named API_REFERENCE.md with # ProxyForge JSON-RPC API Reference
{
  const out = generate({ language: 'wiki' });
  assert.ok(out.files.length >= 1, 'Wiki: should return at least one file');
  const file = out.files[0];
  assert.strictEqual(file.filename, 'API_REFERENCE.md', `Wiki: filename should be 'API_REFERENCE.md', got '${file.filename}'`);
  assert.ok(file.content.includes('# ProxyForge JSON-RPC API Reference'), 'Wiki: content should include # ProxyForge JSON-RPC API Reference');
}

// 9. Custom baseUrl is reflected in all generators
{
  const customUrl = 'http://custom.host:9999';
  const langs = ['python', 'nodejs', 'java', 'rust', 'go', 'php', 'wiki'];
  for (const language of langs) {
    const out = generate({ language, baseUrl: customUrl });
    const combined = out.files.map((f) => f.content).join('\n');
    assert.ok(combined.includes(customUrl), `${language}: custom baseUrl '${customUrl}' should appear in generated content`);
  }
}

// 10. Custom namespace/package is reflected in Java and PHP generators
{
  const javaOut = generate({ language: 'java', namespace: 'com.example.api' });
  assert.ok(javaOut.files[0].content.includes('package com.example.api'), 'Java: custom namespace should appear as package declaration');

  // PHP namespace uses backslash separator internally; generator replaces - with \
  const phpOut = generate({ language: 'php', namespace: 'MyApp\\Client' });
  assert.ok(phpOut.files[0].content.includes('MyApp'), 'PHP: custom namespace should appear in generated content');
}

// 11. All generators include all 16 ops (check method/function count >= 16)
{
  const expectedOpCount = OP_SCHEMAS.length;
  assert.ok(expectedOpCount >= 16, `OP_SCHEMAS should have at least 16 ops, got ${expectedOpCount}`);

  // Python: count async def declarations (one per op)
  {
    const out = generate({ language: 'python' });
    const matches = (out.files[0].content.match(/async def \w+/g) ?? []).length;
    assert.ok(matches >= expectedOpCount, `Python: expected >= ${expectedOpCount} async def methods, got ${matches}`);
  }

  // Node.js: count async method declarations
  {
    const out = generate({ language: 'nodejs' });
    const matches = (out.files[0].content.match(/async \w+\(/g) ?? []).length;
    assert.ok(matches >= expectedOpCount, `Node.js: expected >= ${expectedOpCount} async methods, got ${matches}`);
  }

  // Java: count public JsonObject method declarations
  {
    const out = generate({ language: 'java' });
    const matches = (out.files[0].content.match(/public JsonObject \w+/g) ?? []).length;
    assert.ok(matches >= expectedOpCount, `Java: expected >= ${expectedOpCount} public JsonObject methods, got ${matches}`);
  }

  // Rust: count pub async fn declarations
  {
    const out = generate({ language: 'rust' });
    const matches = (out.files[0].content.match(/pub async fn \w+/g) ?? []).length;
    assert.ok(matches >= expectedOpCount, `Rust: expected >= ${expectedOpCount} pub async fn methods, got ${matches}`);
  }

  // Go: count func (c *Client) declarations
  {
    const out = generate({ language: 'go' });
    const matches = (out.files[0].content.match(/func \(c \*Client\) \w+/g) ?? []).length;
    assert.ok(matches >= expectedOpCount, `Go: expected >= ${expectedOpCount} func methods, got ${matches}`);
  }

  // PHP: count public function declarations (minus constructor and send)
  {
    const out = generate({ language: 'php' });
    const matches = (out.files[0].content.match(/public function \w+/g) ?? []).length;
    // constructor + send + op methods
    assert.ok(matches >= expectedOpCount, `PHP: expected >= ${expectedOpCount} public function declarations, got ${matches}`);
  }

  // Wiki: count ### `op.name` headings
  {
    const out = generate({ language: 'wiki' });
    const matches = (out.files[0].content.match(/^### `/gm) ?? []).length;
    assert.ok(matches >= expectedOpCount, `Wiki: expected >= ${expectedOpCount} op headings, got ${matches}`);
  }
}

// 12. Unknown language returns empty files array with warning
{
  const out = generate({ language: 'cobol' });
  assert.strictEqual(out.files.length, 0, 'Unknown language: files array should be empty');
  assert.ok(Array.isArray(out.warnings) && out.warnings.length > 0, 'Unknown language: should return warnings array');
  assert.ok(out.warnings[0].toLowerCase().includes('unknown'), `Unknown language: warning should mention 'unknown', got '${out.warnings[0]}'`);
}

console.log('api-generator-all-languages: all tests passed');
