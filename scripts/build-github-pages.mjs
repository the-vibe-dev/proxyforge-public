#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const outDir = path.join(root, '.gitignored', 'github-pages');
const packageJson = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));

const docs = [
  { title: 'README', source: 'README.md', slug: 'index' },
  { title: 'Release Notes', source: 'docs/RELEASE_NOTES_v0.1.0-alpha.1.md', slug: 'release-notes' },
  { title: 'Release Checklist', source: 'docs/RELEASE_CHECKLIST.md', slug: 'release-checklist' },
  { title: 'Install Linux and Windows', source: 'docs/INSTALL_LINUX_WINDOWS.md', slug: 'install-linux-windows' },
  { title: 'Operator Guide', source: 'docs/OPERATOR_GUIDE.md', slug: 'operator-guide' },
  { title: 'Feature Matrix', source: 'docs/FEATURE_MATRIX.md', slug: 'feature-matrix' },
  { title: 'Release Evidence', source: 'docs/RELEASE_EVIDENCE.md', slug: 'release-evidence' },
  { title: 'Agentic Interface', source: 'docs/AGENTIC_INTERFACE.md', slug: 'agentic-interface' },
  { title: 'Security Policy', source: 'SECURITY.md', slug: 'security' }
];

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function inlineMarkdown(value) {
  let html = escapeHtml(value);
  html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
  html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  html = html.replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_match, text, href) => {
    const safeHref = String(href).startsWith('http') || String(href).startsWith('#') ? href : `https://github.com/the-vibe-dev/proxyforge-public/blob/main/${href}`;
    return `<a href="${escapeHtml(safeHref)}">${text}</a>`;
  });
  return html;
}

function renderTable(rows) {
  const parsed = rows.map((row) => row.trim().replace(/^\||\|$/g, '').split('|').map((cell) => cell.trim()));
  if (parsed.length < 2) {
    return `<p>${inlineMarkdown(rows.join(' '))}</p>`;
  }
  const header = parsed[0];
  const body = parsed.slice(2);
  return [
    '<div class="table-wrap"><table>',
    '<thead><tr>',
    ...header.map((cell) => `<th>${inlineMarkdown(cell)}</th>`),
    '</tr></thead>',
    '<tbody>',
    ...body.flatMap((row) => [
      '<tr>',
      ...row.map((cell) => `<td>${inlineMarkdown(cell)}</td>`),
      '</tr>'
    ]),
    '</tbody></table></div>'
  ].join('');
}

function renderMarkdown(markdown) {
  const lines = markdown.replace(/\r\n/g, '\n').split('\n');
  const html = [];
  let paragraph = [];
  let list = [];
  let table = [];
  let inCode = false;
  let code = [];

  const flushParagraph = () => {
    if (paragraph.length) {
      html.push(`<p>${inlineMarkdown(paragraph.join(' '))}</p>`);
      paragraph = [];
    }
  };
  const flushList = () => {
    if (list.length) {
      html.push(`<ul>${list.map((item) => `<li>${inlineMarkdown(item)}</li>`).join('')}</ul>`);
      list = [];
    }
  };
  const flushTable = () => {
    if (table.length) {
      html.push(renderTable(table));
      table = [];
    }
  };
  const flushBlocks = () => {
    flushParagraph();
    flushList();
    flushTable();
  };

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith('```')) {
      if (inCode) {
        html.push(`<pre><code>${escapeHtml(code.join('\n'))}</code></pre>`);
        code = [];
        inCode = false;
      } else {
        flushBlocks();
        inCode = true;
      }
      continue;
    }

    if (inCode) {
      code.push(line);
      continue;
    }

    if (!trimmed) {
      flushBlocks();
      continue;
    }

    const heading = /^(#{1,4})\s+(.+)$/.exec(trimmed);
    if (heading) {
      flushBlocks();
      const level = Math.min(heading[1].length, 4);
      const text = heading[2].replace(/\s+#$/, '');
      const id = text.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
      html.push(`<h${level} id="${id}">${inlineMarkdown(text)}</h${level}>`);
      continue;
    }

    if (/^\|.+\|$/.test(trimmed)) {
      flushParagraph();
      flushList();
      table.push(trimmed);
      continue;
    }

    const bullet = /^[-*]\s+(.+)$/.exec(trimmed);
    if (bullet) {
      flushParagraph();
      flushTable();
      list.push(bullet[1]);
      continue;
    }

    flushList();
    flushTable();
    paragraph.push(trimmed);
  }

  flushBlocks();
  if (inCode) {
    html.push(`<pre><code>${escapeHtml(code.join('\n'))}</code></pre>`);
  }
  return html.join('\n');
}

function pageShell({ title, content, source }) {
  const nav = docs.map((doc) => {
    const href = doc.slug === 'index' ? './' : `${doc.slug}.html`;
    const current = doc.title === title ? ' aria-current="page"' : '';
    return `<a${current} href="${href}">${escapeHtml(doc.title)}</a>`;
  }).join('');

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)} - ProxyForge Docs</title>
  <meta name="description" content="ProxyForge ${escapeHtml(packageJson.version)} public alpha documentation.">
  <link rel="stylesheet" href="./styles.css">
</head>
<body>
  <header class="topbar">
    <a class="brand" href="./">ProxyForge <span>${escapeHtml(packageJson.version)}</span></a>
    <a class="repo" href="https://github.com/the-vibe-dev/proxyforge-public">GitHub</a>
  </header>
  <main class="layout">
    <nav class="sidebar" aria-label="Documentation">${nav}</nav>
    <article class="doc">
      <p class="source"><a href="https://github.com/the-vibe-dev/proxyforge-public/blob/main/${escapeHtml(source)}">${escapeHtml(source)}</a></p>
      ${content}
    </article>
  </main>
</body>
</html>`;
}

const stylesheet = `:root {
  color-scheme: light;
  --bg: #f7f8fb;
  --panel: #ffffff;
  --ink: #151922;
  --muted: #596274;
  --line: #dce2ec;
  --accent: #12685f;
  --accent-2: #9a4b14;
  --code: #eef2f7;
}

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  background: var(--bg);
  color: var(--ink);
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  line-height: 1.65;
}

a {
  color: var(--accent);
  text-decoration-thickness: 1px;
  text-underline-offset: 3px;
}

.topbar {
  align-items: center;
  background: var(--panel);
  border-bottom: 1px solid var(--line);
  display: flex;
  gap: 16px;
  justify-content: space-between;
  min-height: 64px;
  padding: 0 24px;
  position: sticky;
  top: 0;
  z-index: 10;
}

.brand {
  color: var(--ink);
  font-size: 18px;
  font-weight: 800;
  text-decoration: none;
}

.brand span {
  color: var(--accent-2);
  font-size: 13px;
  font-weight: 700;
  margin-left: 8px;
}

.repo {
  font-weight: 700;
}

.layout {
  display: grid;
  gap: 32px;
  grid-template-columns: minmax(190px, 260px) minmax(0, 1fr);
  margin: 0 auto;
  max-width: 1280px;
  padding: 32px 24px 56px;
}

.sidebar {
  align-self: start;
  display: grid;
  gap: 4px;
  position: sticky;
  top: 88px;
}

.sidebar a {
  border-radius: 6px;
  color: var(--muted);
  padding: 8px 10px;
  text-decoration: none;
}

.sidebar a[aria-current="page"],
.sidebar a:hover {
  background: #e7f3f1;
  color: var(--accent);
}

.doc {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 8px;
  box-shadow: 0 16px 48px rgba(21, 25, 34, 0.06);
  min-width: 0;
  padding: 40px;
}

.source {
  color: var(--muted);
  font-size: 13px;
  margin-top: 0;
}

h1,
h2,
h3,
h4 {
  line-height: 1.25;
  margin: 1.8em 0 0.55em;
}

h1 {
  font-size: clamp(32px, 4vw, 52px);
  margin-top: 0;
}

h2 {
  border-top: 1px solid var(--line);
  font-size: 28px;
  padding-top: 28px;
}

h3 {
  font-size: 21px;
}

p,
ul {
  margin: 0 0 1rem;
}

li + li {
  margin-top: 0.35rem;
}

code {
  background: var(--code);
  border-radius: 5px;
  color: #242a36;
  font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
  font-size: 0.92em;
  padding: 0.12em 0.32em;
}

pre {
  background: #111827;
  border-radius: 8px;
  color: #f8fafc;
  overflow-x: auto;
  padding: 18px;
}

pre code {
  background: transparent;
  color: inherit;
  padding: 0;
}

.table-wrap {
  overflow-x: auto;
}

table {
  border-collapse: collapse;
  margin: 18px 0;
  min-width: 680px;
  width: 100%;
}

th,
td {
  border: 1px solid var(--line);
  padding: 8px 10px;
  text-align: left;
  vertical-align: top;
}

th {
  background: #edf3f6;
}

@media (max-width: 820px) {
  .topbar {
    padding: 0 16px;
  }

  .layout {
    display: block;
    padding: 18px 14px 40px;
  }

  .sidebar {
    background: var(--bg);
    display: flex;
    gap: 8px;
    margin-bottom: 18px;
    overflow-x: auto;
    padding-bottom: 4px;
    position: static;
  }

  .sidebar a {
    flex: 0 0 auto;
  }

  .doc {
    padding: 24px 18px;
  }
}
`;

fs.rmSync(outDir, { recursive: true, force: true });
fs.mkdirSync(outDir, { recursive: true });

for (const doc of docs) {
  const sourcePath = path.join(root, doc.source);
  if (!fs.existsSync(sourcePath)) {
    throw new Error(`Missing documentation source: ${doc.source}`);
  }
  const markdown = fs.readFileSync(sourcePath, 'utf8');
  const html = pageShell({
    title: doc.title,
    content: renderMarkdown(markdown),
    source: doc.source
  });
  const filename = doc.slug === 'index' ? 'index.html' : `${doc.slug}.html`;
  fs.writeFileSync(path.join(outDir, filename), html);
}

fs.writeFileSync(path.join(outDir, 'styles.css'), stylesheet);
fs.writeFileSync(path.join(outDir, '.nojekyll'), '');
fs.writeFileSync(path.join(outDir, '404.html'), pageShell({
  title: 'Not Found',
  content: '<h1>Not Found</h1><p>The requested ProxyForge documentation page does not exist.</p><p><a href="./">Return to docs index.</a></p>',
  source: 'README.md'
}));

const urls = docs.map((doc) => `https://the-vibe-dev.github.io/proxyforge-public/${doc.slug === 'index' ? '' : `${doc.slug}.html`}`);
fs.writeFileSync(path.join(outDir, 'sitemap.xml'), `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.map((url) => `  <url><loc>${url}</loc></url>`).join('\n')}
</urlset>
`);

console.log(`Built GitHub Pages docs for ${packageJson.name} ${packageJson.version} at ${path.relative(root, outDir)}`);
