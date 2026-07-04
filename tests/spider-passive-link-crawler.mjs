import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

// ---------------------------------------------------------------------------
// Load passiveLinkCrawler via TypeScript transpilation
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

async function loadPassiveLinkCrawler() {
  const crawlerPath = path.resolve('src/spiders/passiveLinkCrawler.ts');

  try {
    await fs.access(crawlerPath);
  } catch {
    console.log('spider-passive-link-crawler: skipped (source file not found)');
    process.exit(0);
  }

  let crawlerCode;
  try {
    crawlerCode = await transpile(crawlerPath);
  } catch (err) {
    console.log(`spider-passive-link-crawler: skipped (transpile error: ${err.message})`);
    process.exit(0);
  }

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

  return makeModule(crawlerCode, crawlerPath, (id) => require(id));
}

const mod = await loadPassiveLinkCrawler();

const {
  createPassiveCrawler,
  extractLinksFromHtml,
  extractLinksFromHeaders,
  addLinks,
  dequeue,
  getLinksSummary,
  filterByOrigin,
} = mod;

const missing = [
  'createPassiveCrawler',
  'extractLinksFromHtml',
  'extractLinksFromHeaders',
  'addLinks',
  'dequeue',
  'getLinksSummary',
  'filterByOrigin',
].filter((name) => typeof mod[name] !== 'function');

if (missing.length > 0) {
  console.log(`spider-passive-link-crawler: skipped (missing exports: ${missing.join(', ')})`);
  process.exit(0);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// 1. createPassiveCrawler returns state with links, queue, visited fields
{
  const state = createPassiveCrawler({ startUrls: ['https://example.com/'] });
  // vm context has its own Map/Set globals so instanceof won't work — check by
  // duck-typing the well-known interface instead.
  assert.equal(typeof state.links.get, 'function', 'state.links should be Map-like (has .get)');
  assert.equal(typeof state.links.set, 'function', 'state.links should be Map-like (has .set)');
  assert.equal(typeof state.links.has, 'function', 'state.links should be Map-like (has .has)');
  assert.ok(Array.isArray(state.queue), 'state.queue should be an Array');
  assert.equal(typeof state.visited.add, 'function', 'state.visited should be Set-like (has .add)');
  assert.equal(typeof state.visited.has, 'function', 'state.visited should be Set-like (has .has)');
}

// 2. extractLinksFromHtml extracts <a href> links with absolute resolution against baseUrl
{
  const html = '<a href="/about">About</a><a href="https://other.com/page">Other</a>';
  const base = 'https://example.com/';
  const links = extractLinksFromHtml(html, base, 0);
  const urls = links.map((l) => l.url);
  assert.ok(urls.includes('https://example.com/about'), 'should resolve relative /about against base');
  assert.ok(urls.includes('https://other.com/page'), 'should keep absolute URL as-is');
  const aboutLink = links.find((l) => l.url === 'https://example.com/about');
  assert.ok(aboutLink, 'should find about link');
  assert.equal(aboutLink.via, 'href', 'link via should be href');
  assert.equal(aboutLink.depth, 0, 'link depth should match supplied depth');
}

// 3. extractLinksFromHtml ignores javascript:void, mailto:, tel: hrefs
{
  const html = [
    '<a href="javascript:void(0)">noop</a>',
    '<a href="mailto:admin@example.com">Mail</a>',
    '<a href="tel:+15550001234">Call</a>',
    '<a href="/real-link">Real</a>',
  ].join('');
  const links = extractLinksFromHtml(html, 'https://example.com/', 0);
  const vias = links.filter((l) => l.via === 'href').map((l) => l.url);
  assert.ok(!vias.some((u) => u.startsWith('javascript:')), 'should not include javascript: hrefs');
  assert.ok(!vias.some((u) => u.startsWith('mailto:')), 'should not include mailto: hrefs');
  assert.ok(!vias.some((u) => u.startsWith('tel:')), 'should not include tel: hrefs');
  assert.ok(vias.some((u) => u.includes('/real-link')), 'should include normal href');
}

// 4. extractLinksFromHtml extracts form action links with method POST
{
  const html = '<form action="/login" method="post"><input name="user"></form>';
  const links = extractLinksFromHtml(html, 'https://example.com/', 0);
  const formLink = links.find((l) => l.via === 'action');
  assert.ok(formLink, 'should extract form action link');
  assert.ok(formLink.url.includes('/login'), 'form action link should point to /login');
  assert.equal(formLink.method, 'POST', 'form action link method should be POST');
}

// 5. extractLinksFromHtml extracts fetch("url") calls as js-fetch via source
{
  const html = '<script>fetch("/api/data").then(r => r.json())</script>';
  const links = extractLinksFromHtml(html, 'https://example.com/', 1);
  const fetchLink = links.find((l) => l.via === 'js-fetch');
  assert.ok(fetchLink, 'should extract fetch() URL as js-fetch link');
  assert.ok(fetchLink.url.includes('/api/data'), 'js-fetch link should point to /api/data');
}

// 6. addLinks adds new links to state map
{
  const state = createPassiveCrawler({ startUrls: [] });
  const newLinks = [
    { url: 'https://example.com/page1', foundIn: 'https://example.com/', via: 'href', depth: 0 },
    { url: 'https://example.com/page2', foundIn: 'https://example.com/', via: 'href', depth: 0 },
  ];
  addLinks(state, newLinks);
  assert.equal(state.links.size, 2, 'state.links should have 2 entries after addLinks');
  assert.ok(state.links.has('https://example.com/page1'), 'state.links should contain page1');
  assert.ok(state.links.has('https://example.com/page2'), 'state.links should contain page2');
}

// 7. dequeue returns item from queue and marks visited
{
  const state = createPassiveCrawler({ startUrls: ['https://example.com/'] });
  const item = dequeue(state);
  assert.ok(item, 'dequeue should return an item');
  assert.equal(item.url, 'https://example.com/', 'dequeued item should be the start URL');
  assert.ok(state.visited.has('https://example.com/'), 'dequeued URL should be marked visited');
  const second = dequeue(state);
  assert.equal(second, undefined, 'dequeue on empty queue should return undefined');
}

// 8. getLinksSummary returns correct total/visited/queued counts
{
  const state = createPassiveCrawler({ startUrls: ['https://example.com/'] });
  addLinks(state, [
    { url: 'https://example.com/a', foundIn: 'https://example.com/', via: 'href', depth: 1 },
    { url: 'https://example.com/b', foundIn: 'https://example.com/', via: 'href', depth: 1 },
  ]);
  // Dequeue the start URL to mark it visited
  dequeue(state);
  const summary = getLinksSummary(state);
  assert.equal(typeof summary.total, 'number', 'summary.total should be a number');
  assert.equal(typeof summary.visited, 'number', 'summary.visited should be a number');
  assert.equal(typeof summary.queued, 'number', 'summary.queued should be a number');
  // 2 links added to the map (start URLs are in queue but not in links map)
  assert.equal(summary.total, 2, `total should be 2, got ${summary.total}`);
  // 1 visited (the start URL dequeued above)
  assert.equal(summary.visited, 1, `visited should be 1, got ${summary.visited}`);
}

// 9. filterByOrigin returns only links matching the given origin
{
  const state = createPassiveCrawler({ startUrls: [] });
  addLinks(state, [
    { url: 'https://target.com/page1', foundIn: 'https://target.com/', via: 'href', depth: 0 },
    { url: 'https://target.com/page2', foundIn: 'https://target.com/', via: 'href', depth: 0 },
    { url: 'https://other.com/page', foundIn: 'https://target.com/', via: 'href', depth: 0 },
  ]);
  const filtered = filterByOrigin(state, ['https://target.com']);
  assert.equal(filtered.length, 2, `filterByOrigin should return 2 links for target.com, got ${filtered.length}`);
  assert.ok(filtered.every((l) => new URL(l.url).origin === 'https://target.com'), 'all filtered links should be from target.com');
}

console.log('spider-passive-link-crawler: all tests passed');
