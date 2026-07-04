#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const outDir = path.join(root, '.gitignored', 'github-pages');
const packageJson = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const repoUrl = 'https://github.com/the-vibe-dev/proxyforge-public';
const siteUrl = 'https://the-vibe-dev.github.io/proxyforge-public/';

const sections = [
  {
    title: 'Home',
    docs: [
      { title: 'Home', source: 'README.md', slug: 'index' }
    ]
  },
  {
    title: 'Release',
    docs: [
      { title: 'Release Notes', source: 'docs/RELEASE_NOTES_v0.1.0-alpha.1.md', slug: 'release-notes' },
      { title: 'Install Linux and Windows', source: 'docs/INSTALL_LINUX_WINDOWS.md', slug: 'install-linux-windows' },
      { title: 'Release Checklist', source: 'docs/RELEASE_CHECKLIST.md', slug: 'release-checklist' },
      { title: 'Release Evidence', source: 'docs/RELEASE_EVIDENCE.md', slug: 'release-evidence' }
    ]
  },
  {
    title: 'Operations',
    docs: [
      { title: 'Operator Guide', source: 'docs/OPERATOR_GUIDE.md', slug: 'operator-guide' },
      { title: 'Feature Matrix', source: 'docs/FEATURE_MATRIX.md', slug: 'feature-matrix' },
      { title: 'Agentic Interface', source: 'docs/AGENTIC_INTERFACE.md', slug: 'agentic-interface' },
      { title: 'Automation API', source: 'docs/AUTOMATION_API.md', slug: 'automation-api' }
    ]
  },
  {
    title: 'Advanced Modes',
    docs: [
      { title: 'HTTP/3 Mode', source: 'docs/MODES_HTTP3.md', slug: 'modes-http3' },
      { title: 'Transparent Mode', source: 'docs/MODES_TRANSPARENT.md', slug: 'modes-transparent' },
      { title: 'WireGuard Mode', source: 'docs/MODES_WIREGUARD.md', slug: 'modes-wireguard' },
      { title: 'OAST Provider Guide', source: 'docs/OAST_PROVIDER_GUIDE.md', slug: 'oast-provider-guide' }
    ]
  },
  {
    title: 'Agents',
    docs: [
      { title: 'Codex Agent', source: 'docs/agents/CODEX.md', slug: 'agent-codex' },
      { title: 'Claude Agent', source: 'docs/agents/CLAUDE.md', slug: 'agent-claude' },
      { title: 'Vantix Agent', source: 'docs/agents/VANTIX.md', slug: 'agent-vantix' },
      { title: 'Agent Schemas', source: 'docs/agents/SCHEMAS.md', slug: 'agent-schemas' }
    ]
  },
  {
    title: 'Trust',
    docs: [
      { title: 'Security Policy', source: 'SECURITY.md', slug: 'security' },
      { title: 'Project SBOM Guide', source: 'docs/PROJECT_SBOM_GUIDE.md', slug: 'project-sbom-guide' },
      { title: 'Roadmap', source: 'docs/PROXY_FORGE_ROADMAP.md', slug: 'roadmap' }
    ]
  }
];

const docs = sections.flatMap((section) => section.docs.map((doc) => ({ ...doc, section: section.title })));
const docsBySource = new Map(docs.map((doc) => [doc.source, doc]));

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function decodeAttribute(value) {
  return String(value)
    .replaceAll('&amp;', '&')
    .replaceAll('&quot;', '"')
    .replaceAll('&#39;', "'")
    .replaceAll('&lt;', '<')
    .replaceAll('&gt;', '>');
}

function pageHref(doc) {
  return doc.slug === 'index' ? './' : `${doc.slug}.html`;
}

function splitHash(href) {
  const index = href.indexOf('#');
  if (index === -1) {
    return [href, ''];
  }
  return [href.slice(0, index), href.slice(index)];
}

function resolveHref(href) {
  const rawHref = decodeAttribute(href).trim();
  if (/^(https?:|mailto:|tel:)/i.test(rawHref) || rawHref.startsWith('#')) {
    return rawHref;
  }

  const [withoutHash, hash] = splitHash(rawHref.replace(/^\.\//, ''));
  if (!withoutHash) {
    return hash || './';
  }

  const doc = docsBySource.get(withoutHash);
  if (doc) {
    return `${pageHref(doc)}${hash}`;
  }

  if (withoutHash.startsWith('assets/')) {
    return `./${withoutHash}${hash}`;
  }

  return `${repoUrl}/blob/main/${withoutHash}${hash}`;
}

function inlineMarkdown(value) {
  let html = escapeHtml(value);

  html = html.replace(/!\[([^\]]*)\]\(([^)]+)\)/g, (_match, alt, href) => {
    return `<img class="content-image" src="${escapeHtml(resolveHref(href))}" alt="${escapeHtml(decodeAttribute(alt))}">`;
  });
  html = html.replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_match, text, href) => {
    return `<a href="${escapeHtml(resolveHref(href))}">${text}</a>`;
  });
  html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
  html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  html = html.replace(/\*([^*\n]+)\*/g, '<em>$1</em>');
  return html;
}

function slugify(value) {
  return String(value)
    .toLowerCase()
    .replace(/<[^>]*>/g, '')
    .replace(/&[a-z0-9#]+;/gi, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '') || 'section';
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

function renderCodeBlock(lines, language = '') {
  const lang = language ? ` data-lang="${escapeHtml(language)}"` : '';
  return `<div class="highlight"><pre class="code-block"${lang}><code>${escapeHtml(lines.join('\n'))}</code></pre></div>`;
}

function stripReadmeChrome(markdown) {
  const lines = markdown.replace(/\r\n/g, '\n').split('\n');
  const firstContent = lines.findIndex((line) => /^##\s+What is ProxyForge\?/i.test(line.trim()));
  if (firstContent !== -1) {
    return lines.slice(firstContent).join('\n');
  }

  return lines
    .filter((line) => !/^<\/?(p|h1)\b/i.test(line.trim()))
    .filter((line) => !/^\s*<img\b/i.test(line.trim()))
    .join('\n');
}

function renderMarkdown(markdown) {
  const lines = markdown.replace(/\r\n/g, '\n').split('\n');
  const html = [];
  const headings = [];
  let paragraph = [];
  let unordered = [];
  let ordered = [];
  let table = [];
  let inCode = false;
  let codeLanguage = '';
  let code = [];
  let indentedCode = [];

  const flushParagraph = () => {
    if (paragraph.length) {
      html.push(`<p>${inlineMarkdown(paragraph.join(' '))}</p>`);
      paragraph = [];
    }
  };
  const flushUnordered = () => {
    if (unordered.length) {
      html.push(`<ul>${unordered.map((item) => `<li>${inlineMarkdown(item)}</li>`).join('')}</ul>`);
      unordered = [];
    }
  };
  const flushOrdered = () => {
    if (ordered.length) {
      html.push(`<ol>${ordered.map((item) => `<li>${inlineMarkdown(item)}</li>`).join('')}</ol>`);
      ordered = [];
    }
  };
  const flushTable = () => {
    if (table.length) {
      html.push(renderTable(table));
      table = [];
    }
  };
  const flushIndentedCode = () => {
    if (indentedCode.length) {
      html.push(renderCodeBlock(indentedCode));
      indentedCode = [];
    }
  };
  const flushBlocks = () => {
    flushParagraph();
    flushUnordered();
    flushOrdered();
    flushTable();
    flushIndentedCode();
  };

  for (const line of lines) {
    const trimmed = line.trim();
    const fence = /^```([A-Za-z0-9_-]+)?\s*$/.exec(trimmed);
    if (fence) {
      if (inCode) {
        html.push(renderCodeBlock(code, codeLanguage));
        code = [];
        codeLanguage = '';
        inCode = false;
      } else {
        flushBlocks();
        inCode = true;
        codeLanguage = fence[1] || '';
      }
      continue;
    }

    if (inCode) {
      code.push(line);
      continue;
    }

    if (/^(    |\t)/.test(line) && trimmed) {
      flushParagraph();
      flushUnordered();
      flushOrdered();
      flushTable();
      indentedCode.push(line.replace(/^(    |\t)/, ''));
      continue;
    }

    if (indentedCode.length) {
      flushIndentedCode();
    }

    if (!trimmed) {
      flushBlocks();
      continue;
    }

    if (/^---+$/.test(trimmed)) {
      flushBlocks();
      html.push('<hr>');
      continue;
    }

    const heading = /^(#{1,4})\s+(.+)$/.exec(trimmed);
    if (heading) {
      flushBlocks();
      const level = Math.min(heading[1].length, 4);
      const text = heading[2].replace(/\s+#$/, '');
      const id = slugify(text);
      headings.push({ level, text, id });
      html.push(`<h${level} id="${id}">${inlineMarkdown(text)}<a class="anchor" href="#${id}" aria-label="Permanent link to ${escapeHtml(text)}">#</a></h${level}>`);
      continue;
    }

    if (/^\|.+\|$/.test(trimmed)) {
      flushParagraph();
      flushUnordered();
      flushOrdered();
      table.push(trimmed);
      continue;
    }

    const bullet = /^[-*]\s+(.+)$/.exec(trimmed);
    if (bullet) {
      flushParagraph();
      flushOrdered();
      flushTable();
      unordered.push(bullet[1]);
      continue;
    }

    const numbered = /^\d+\.\s+(.+)$/.exec(trimmed);
    if (numbered) {
      flushParagraph();
      flushUnordered();
      flushTable();
      ordered.push(numbered[1]);
      continue;
    }

    const quote = /^>\s+(.+)$/.exec(trimmed);
    if (quote) {
      flushBlocks();
      html.push(`<blockquote>${inlineMarkdown(quote[1])}</blockquote>`);
      continue;
    }

    flushUnordered();
    flushOrdered();
    flushTable();
    paragraph.push(trimmed);
  }

  flushBlocks();
  if (inCode) {
    html.push(renderCodeBlock(code, codeLanguage));
  }
  return { html: html.join('\n'), headings };
}

function renderTabs(currentSection) {
  return sections.map((section) => {
    const firstDoc = section.docs[0];
    const current = section.title === currentSection ? ' aria-current="page"' : '';
    return `<a${current} href="${pageHref(firstDoc)}">${escapeHtml(section.title)}</a>`;
  }).join('');
}

function renderPrimaryNav(currentSource) {
  return sections.map((section) => {
    const links = section.docs.map((doc) => {
      const current = doc.source === currentSource ? ' aria-current="page"' : '';
      return `<a${current} href="${pageHref(doc)}">${escapeHtml(doc.title)}</a>`;
    }).join('');
    return `<div class="nav-section"><p>${escapeHtml(section.title)}</p>${links}</div>`;
  }).join('');
}

function renderToc(headings) {
  const items = headings.filter((heading) => heading.level >= 2 && heading.level <= 3).slice(0, 24);
  if (!items.length) {
    return '<p class="toc-empty">No sections</p>';
  }
  return `<ol>${items.map((heading) => `<li class="toc-level-${heading.level}"><a href="#${heading.id}">${inlineMarkdown(heading.text)}</a></li>`).join('')}</ol>`;
}

function renderBadges() {
  const badgeNames = [
    'version.svg',
    'license.svg',
    'workbenches.svg',
    'feature-lanes.svg',
    'agent-flows.svg',
    'AI-providers.svg',
    'exports.svg',
    'test-gates.svg'
  ];
  return badgeNames.map((name) => `<img src="./assets/badges/${name}" alt="">`).join('');
}

function renderHomeHero() {
  return `<section class="pf-hero" aria-labelledby="proxyforge-title">
  <img class="pf-hero-logo" src="./assets/proxyforge-github-hero.png" alt="ProxyForge - Where requests become findings">
  <h1 id="proxyforge-title">ProxyForge ${escapeHtml(packageJson.version)}</h1>
  <p class="pf-tagline">Cross-platform interception and mutation workbench for authorized web security testing.</p>
  <p class="pf-actions">
    <a class="button button-primary" href="${escapeHtml(`${repoUrl}/releases/tag/v${packageJson.version}`)}">Download alpha</a>
    <a class="button" href="./install-linux-windows.html">Install guide</a>
    <a class="button" href="./release-notes.html">Release notes</a>
    <a class="button" href="./security.html">Safety policy</a>
  </p>
  <div class="pf-badges" aria-label="Project status badges">${renderBadges()}</div>
</section>
<section class="pf-cards" aria-label="ProxyForge highlights">
  <article class="pf-card">
    <h3>Intercept</h3>
    <p>Capture HTTP, HTTPS, WebSocket, browser-routed, and callback traffic with project CA isolation.</p>
  </article>
  <article class="pf-card">
    <h3>Mutate</h3>
    <p>Replay, fuzz, compare, decode, scan, and package evidence through analyst workbenches and headless CI.</p>
  </article>
  <article class="pf-card">
    <h3>Report</h3>
    <p>Keep operational captures full-fidelity, then apply report/export redaction for deliverables.</p>
  </article>
</section>`;
}

function renderDocHeader(doc) {
  return `<header class="doc-header">
  <p class="source"><a href="${escapeHtml(`${repoUrl}/blob/main/${doc.source}`)}">${escapeHtml(doc.source)}</a></p>
  <h1>${escapeHtml(doc.title)}</h1>
</header>`;
}

function pageShell({ doc, content, headings, previousDoc, nextDoc }) {
  const isHome = doc.slug === 'index';
  const title = isHome ? 'ProxyForge Docs' : `${doc.title} - ProxyForge Docs`;
  const nav = renderPrimaryNav(doc.source);
  const tabs = renderTabs(doc.section);
  const toc = renderToc(headings);
  const previous = previousDoc ? `<a class="pager-link" href="${pageHref(previousDoc)}"><span>Previous</span>${escapeHtml(previousDoc.title)}</a>` : '<span></span>';
  const next = nextDoc ? `<a class="pager-link pager-next" href="${pageHref(nextDoc)}"><span>Next</span>${escapeHtml(nextDoc.title)}</a>` : '<span></span>';
  const pageIntro = isHome ? renderHomeHero() : renderDocHeader(doc);

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)}</title>
  <meta name="description" content="ProxyForge ${escapeHtml(packageJson.version)} public alpha documentation.">
  <meta name="theme-color" content="#1a1d21">
  <meta property="og:type" content="website">
  <meta property="og:title" content="${escapeHtml(title)}">
  <meta property="og:description" content="ProxyForge public alpha documentation and release evidence.">
  <meta property="og:image" content="${siteUrl}assets/proxyforge-social-square.png">
  <meta property="og:url" content="${siteUrl}${doc.slug === 'index' ? '' : `${doc.slug}.html`}">
  <link rel="icon" href="./assets/favicon-32.png">
  <link rel="apple-touch-icon" href="./assets/favicon-256.png">
  <link rel="stylesheet" href="./styles.css">
</head>
<body>
  <a class="skip-link" href="#content">Skip to content</a>
  <header class="topbar">
    <nav class="topbar-inner" aria-label="Header">
      <a class="brand" href="./" aria-label="ProxyForge home">
        <img src="./assets/favicon-64.png" alt="">
        <span>ProxyForge</span>
      </a>
      <label class="search-label" for="doc-search">
        <span>Search</span>
        <input id="doc-search" type="search" placeholder="Filter docs" autocomplete="off">
      </label>
      <a class="repo" href="${repoUrl}">the-vibe-dev/proxyforge-public</a>
    </nav>
    <nav class="tabs" aria-label="Documentation sections">${tabs}</nav>
  </header>
  <main class="layout">
    <aside class="sidebar" aria-label="Documentation navigation">
      <div class="sidebar-title">
        <img src="./assets/proxyforge-logo-lockup.png" alt="ProxyForge">
      </div>
      <nav id="doc-nav">${nav}</nav>
    </aside>
    <article class="doc" id="content">
      ${pageIntro}
      ${content}
      <nav class="pager" aria-label="Previous and next pages">${previous}${next}</nav>
    </article>
    <aside class="toc" aria-label="Table of contents">
      <p>Table of contents</p>
      ${toc}
    </aside>
  </main>
  <footer class="footer">
    <span>ProxyForge ${escapeHtml(packageJson.version)} public alpha</span>
    <a href="${repoUrl}/blob/main/LICENSE">MIT licensed</a>
    <a href="${repoUrl}/security/advisories/new">Report a vulnerability</a>
  </footer>
  <script>
    const search = document.querySelector('#doc-search');
    const navLinks = [...document.querySelectorAll('#doc-nav a')];
    search?.addEventListener('input', () => {
      const query = search.value.trim().toLowerCase();
      navLinks.forEach((link) => {
        link.hidden = query && !link.textContent.toLowerCase().includes(query);
      });
    });
  </script>
</body>
</html>`;
}

const stylesheet = `@import url("https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap");

:root {
  color-scheme: light;
  --pf-bg: #f5f7fb;
  --pf-panel: #ffffff;
  --pf-ink: #171a20;
  --pf-muted: #5c6678;
  --pf-line: #dce3ec;
  --pf-soft: #eef2f7;
  --pf-charcoal: #1a1d21;
  --pf-charcoal-2: #2e3338;
  --pf-orange: #ff6a00;
  --pf-amber: #ff9e1a;
  --pf-teal: #12685f;
  --pf-blue: #315f86;
  --pf-code: #111827;
  --pf-radius: 8px;
  --pf-shadow: 0 18px 48px rgba(22, 29, 40, 0.08);
}

* {
  box-sizing: border-box;
}

[hidden] {
  display: none !important;
}

html {
  scroll-behavior: smooth;
}

body {
  margin: 0;
  background: var(--pf-bg);
  color: var(--pf-ink);
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  font-size: 16px;
  line-height: 1.68;
}

a {
  color: var(--pf-teal);
  text-decoration-thickness: 1px;
  text-underline-offset: 3px;
}

a:hover {
  color: #0d4f49;
}

.skip-link {
  background: var(--pf-orange);
  color: #121417;
  font-weight: 800;
  left: 12px;
  padding: 8px 12px;
  position: fixed;
  top: -48px;
  z-index: 20;
}

.skip-link:focus {
  top: 12px;
}

.topbar {
  background: var(--pf-charcoal);
  box-shadow: 0 1px 0 rgba(255, 255, 255, 0.08);
  color: #ffffff;
  position: sticky;
  top: 0;
  z-index: 10;
}

.topbar-inner {
  align-items: center;
  display: grid;
  gap: 18px;
  grid-template-columns: auto minmax(160px, 360px) auto;
  margin: 0 auto;
  max-width: 1440px;
  min-height: 56px;
  padding: 0 24px;
}

.brand {
  align-items: center;
  color: #ffffff;
  display: inline-flex;
  font-weight: 800;
  gap: 10px;
  letter-spacing: 0;
  text-decoration: none;
}

.brand img {
  border-radius: 6px;
  height: 28px;
  width: 28px;
}

.search-label {
  align-items: center;
  background: rgba(255, 255, 255, 0.08);
  border: 1px solid rgba(255, 255, 255, 0.12);
  border-radius: var(--pf-radius);
  color: #cdd5df;
  display: flex;
  font-size: 12px;
  gap: 10px;
  min-width: 0;
  padding: 6px 10px;
}

.search-label input {
  background: transparent;
  border: 0;
  color: #ffffff;
  flex: 1;
  font: inherit;
  min-width: 0;
  outline: 0;
}

.search-label input::placeholder {
  color: #9aa6b8;
}

.repo {
  color: #f6f8fb;
  font-size: 13px;
  font-weight: 700;
  justify-self: end;
  text-decoration: none;
}

.tabs {
  display: flex;
  gap: 2px;
  margin: 0 auto;
  max-width: 1440px;
  overflow-x: auto;
  padding: 0 20px;
}

.tabs a {
  border-bottom: 3px solid transparent;
  color: #dce4ef;
  flex: 0 0 auto;
  font-size: 14px;
  font-weight: 700;
  padding: 12px 14px 10px;
  text-decoration: none;
}

.tabs a[aria-current="page"],
.tabs a:hover {
  border-color: var(--pf-orange);
  color: #ffffff;
}

.layout {
  display: grid;
  gap: 28px;
  grid-template-columns: minmax(210px, 260px) minmax(0, 1fr) minmax(180px, 240px);
  margin: 0 auto;
  max-width: 1440px;
  padding: 28px 24px 48px;
}

.sidebar,
.toc {
  align-self: start;
  position: sticky;
  top: 112px;
}

.sidebar {
  color: var(--pf-muted);
  max-height: calc(100vh - 132px);
  overflow-y: auto;
  padding-right: 4px;
}

.sidebar-title {
  background: var(--pf-panel);
  border: 1px solid var(--pf-line);
  border-radius: var(--pf-radius);
  margin-bottom: 16px;
  padding: 14px;
}

.sidebar-title img {
  display: block;
  height: auto;
  width: 100%;
}

.nav-section {
  border-left: 2px solid var(--pf-line);
  margin-bottom: 16px;
  padding-left: 12px;
}

.nav-section p,
.toc p {
  color: var(--pf-charcoal);
  font-size: 12px;
  font-weight: 800;
  margin: 0 0 6px;
  text-transform: uppercase;
}

.nav-section a {
  border-radius: 6px;
  color: var(--pf-muted);
  display: block;
  font-size: 14px;
  font-weight: 600;
  line-height: 1.3;
  padding: 7px 9px;
  text-decoration: none;
}

.nav-section a[aria-current="page"],
.nav-section a:hover {
  background: #fff3e8;
  color: #a44806;
}

.doc {
  background: var(--pf-panel);
  border: 1px solid var(--pf-line);
  border-radius: var(--pf-radius);
  box-shadow: var(--pf-shadow);
  min-width: 0;
  padding: 36px min(5vw, 56px) 44px;
}

.doc-header {
  border-bottom: 1px solid var(--pf-line);
  margin: -4px 0 28px;
  padding-bottom: 22px;
}

.source {
  color: var(--pf-muted);
  font-size: 13px;
  font-weight: 700;
  margin: 0 0 8px;
}

.pf-hero {
  border-bottom: 1px solid var(--pf-line);
  margin: -8px 0 30px;
  padding: 0 0 28px;
  text-align: center;
}

.pf-hero-logo {
  border-radius: var(--pf-radius);
  box-shadow: 0 16px 40px rgba(16, 20, 28, 0.12);
  display: block;
  height: auto;
  margin: 0 auto 22px;
  max-width: min(920px, 100%);
}

.pf-hero h1 {
  margin-top: 0;
}

.pf-tagline {
  color: var(--pf-muted);
  font-size: 1.15rem;
  margin: 0 auto 18px;
  max-width: 660px;
}

.pf-actions {
  align-items: center;
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  justify-content: center;
  margin: 0 0 16px;
}

.button {
  border: 1px solid var(--pf-line);
  border-radius: var(--pf-radius);
  color: var(--pf-charcoal);
  display: inline-flex;
  font-size: 14px;
  font-weight: 800;
  line-height: 1;
  padding: 11px 14px;
  text-decoration: none;
}

.button:hover {
  border-color: var(--pf-orange);
  color: var(--pf-charcoal);
}

.button-primary {
  background: var(--pf-orange);
  border-color: var(--pf-orange);
  color: #121417;
}

.pf-badges {
  align-items: center;
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  justify-content: center;
  margin: 0 auto;
  max-width: 920px;
}

.pf-badges img {
  display: block;
  height: 28px;
  max-width: 100%;
}

.pf-cards {
  display: grid;
  gap: 14px;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  margin: 0 0 30px;
}

.pf-card {
  background: linear-gradient(180deg, #ffffff 0%, #f7f9fc 100%);
  border: 1px solid var(--pf-line);
  border-radius: var(--pf-radius);
  padding: 16px;
}

.pf-card h3 {
  color: #a44806;
  font-size: 1rem;
  margin: 0 0 6px;
}

.pf-card p {
  color: var(--pf-muted);
  font-size: 0.9rem;
  margin: 0;
}

h1,
h2,
h3,
h4 {
  color: var(--pf-charcoal);
  font-weight: 800;
  letter-spacing: 0;
  line-height: 1.22;
}

h1 {
  font-size: clamp(2rem, 4vw, 3.1rem);
  margin: 0 0 0.7em;
}

h2 {
  border-top: 1px solid var(--pf-line);
  font-size: 1.55rem;
  margin: 2.1em 0 0.65em;
  padding-top: 1.25em;
}

h2:first-child,
.pf-hero + h2,
.pf-cards + h2 {
  border-top: 0;
  margin-top: 0;
  padding-top: 0;
}

h3 {
  font-size: 1.1rem;
  margin: 1.45em 0 0.5em;
}

h4 {
  font-size: 1rem;
  margin: 1.2em 0 0.4em;
}

.anchor {
  color: #aeb7c6;
  font-size: 0.72em;
  margin-left: 8px;
  opacity: 0;
  text-decoration: none;
}

h1:hover .anchor,
h2:hover .anchor,
h3:hover .anchor,
h4:hover .anchor {
  opacity: 1;
}

p,
ul,
ol,
blockquote {
  margin: 0 0 1rem;
}

ul,
ol {
  padding-left: 1.35rem;
}

li + li {
  margin-top: 0.35rem;
}

blockquote {
  background: #f2f7f7;
  border-left: 4px solid var(--pf-teal);
  border-radius: 0 var(--pf-radius) var(--pf-radius) 0;
  color: var(--pf-charcoal);
  padding: 12px 14px;
}

hr {
  border: 0;
  border-top: 1px solid var(--pf-line);
  margin: 2rem 0;
}

code {
  background: var(--pf-soft);
  border-radius: 5px;
  color: #202633;
  font-family: "JetBrains Mono", "SFMono-Regular", Consolas, "Liberation Mono", monospace;
  font-size: 0.88em;
  padding: 0.12em 0.32em;
}

.highlight {
  margin: 1rem 0 1.15rem;
}

.code-block {
  background: var(--pf-code);
  border: 1px solid #243044;
  border-radius: var(--pf-radius);
  color: #eef4ff;
  font-family: "JetBrains Mono", "SFMono-Regular", Consolas, "Liberation Mono", monospace;
  font-size: 0.86rem;
  line-height: 1.7;
  margin: 0;
  overflow-x: auto;
  padding: 18px;
  position: relative;
}

.code-block[data-lang] {
  padding-top: 34px;
}

.code-block[data-lang]::before {
  color: #ffbd70;
  content: attr(data-lang);
  font-size: 11px;
  font-weight: 800;
  left: 18px;
  position: absolute;
  text-transform: uppercase;
  top: 10px;
}

.code-block code {
  background: transparent;
  color: inherit;
  padding: 0;
}

.content-image {
  border-radius: var(--pf-radius);
  display: block;
  height: auto;
  margin: 1rem auto;
  max-width: 100%;
}

.table-wrap {
  margin: 1rem 0 1.25rem;
  overflow-x: auto;
}

table {
  border-collapse: collapse;
  min-width: 680px;
  width: 100%;
}

th,
td {
  border: 1px solid var(--pf-line);
  padding: 9px 11px;
  text-align: left;
  vertical-align: top;
}

th {
  background: #eef3f8;
  color: var(--pf-charcoal);
  font-size: 13px;
  font-weight: 800;
}

tr:nth-child(even) td {
  background: #fbfcfe;
}

.toc {
  border-left: 1px solid var(--pf-line);
  max-height: calc(100vh - 132px);
  overflow-y: auto;
  padding-left: 16px;
}

.toc ol {
  list-style: none;
  margin: 0;
  padding: 0;
}

.toc li {
  margin: 0;
}

.toc a {
  color: var(--pf-muted);
  display: block;
  font-size: 13px;
  line-height: 1.35;
  padding: 5px 0;
  text-decoration: none;
}

.toc a:hover {
  color: var(--pf-teal);
}

.toc-level-3 {
  padding-left: 12px;
}

.toc-empty {
  color: var(--pf-muted);
  font-size: 13px;
}

.pager {
  border-top: 1px solid var(--pf-line);
  display: grid;
  gap: 16px;
  grid-template-columns: 1fr 1fr;
  margin-top: 36px;
  padding-top: 20px;
}

.pager-link {
  border: 1px solid var(--pf-line);
  border-radius: var(--pf-radius);
  color: var(--pf-charcoal);
  display: block;
  font-weight: 800;
  line-height: 1.3;
  padding: 13px 14px;
  text-decoration: none;
}

.pager-link span {
  color: var(--pf-muted);
  display: block;
  font-size: 12px;
  font-weight: 700;
  margin-bottom: 2px;
}

.pager-next {
  text-align: right;
}

.footer {
  align-items: center;
  background: #ffffff;
  border-top: 1px solid var(--pf-line);
  color: var(--pf-muted);
  display: flex;
  flex-wrap: wrap;
  font-size: 13px;
  gap: 14px;
  justify-content: center;
  padding: 18px 24px;
}

@media (max-width: 1120px) {
  .layout {
    grid-template-columns: minmax(180px, 240px) minmax(0, 1fr);
  }

  .toc {
    display: none;
  }
}

@media (max-width: 820px) {
  .topbar-inner {
    grid-template-columns: 1fr;
    gap: 10px;
    padding: 12px 16px;
  }

  .repo {
    justify-self: start;
  }

  .tabs {
    padding: 0 10px;
  }

  .layout {
    display: block;
    padding: 16px 12px 36px;
  }

  .sidebar {
    max-height: none;
    overflow: visible;
    position: static;
  }

  .sidebar-title {
    display: none;
  }

  #doc-nav {
    display: flex;
    gap: 10px;
    margin-bottom: 16px;
    overflow-x: auto;
    padding-bottom: 4px;
  }

  .nav-section {
    border: 0;
    flex: 0 0 210px;
    padding: 0;
  }

  .doc {
    padding: 24px 16px 32px;
  }

  .pf-cards,
  .pager {
    grid-template-columns: 1fr;
  }

  table {
    min-width: 620px;
  }
}
`;

function copyFile(source, target) {
  const sourcePath = path.join(root, source);
  const targetPath = path.join(outDir, target);
  if (!fs.existsSync(sourcePath)) {
    throw new Error(`Missing site asset: ${source}`);
  }
  fs.mkdirSync(path.dirname(targetPath), { recursive: true });
  fs.copyFileSync(sourcePath, targetPath);
}

function copySiteAssets() {
  const assets = [
    'assets/favicon-32.png',
    'assets/favicon-64.png',
    'assets/favicon-256.png',
    'assets/proxyforge-github-hero.png',
    'assets/proxyforge-logo-lockup.png',
    'assets/proxyforge-feature-hero.png',
    'assets/proxyforge-social-square.png'
  ];

  for (const asset of assets) {
    copyFile(asset, asset);
  }

  const badgeDir = path.join(root, 'assets', 'badges');
  for (const filename of fs.readdirSync(badgeDir).filter((name) => name.endsWith('.svg'))) {
    copyFile(path.join('assets', 'badges', filename), path.join('assets', 'badges', filename));
  }
}

fs.rmSync(outDir, { recursive: true, force: true });
fs.mkdirSync(outDir, { recursive: true });
copySiteAssets();

for (const [index, doc] of docs.entries()) {
  const sourcePath = path.join(root, doc.source);
  if (!fs.existsSync(sourcePath)) {
    throw new Error(`Missing documentation source: ${doc.source}`);
  }
  const markdown = fs.readFileSync(sourcePath, 'utf8');
  const preparedMarkdown = doc.source === 'README.md' ? stripReadmeChrome(markdown) : markdown;
  const rendered = renderMarkdown(preparedMarkdown);
  const html = pageShell({
    doc,
    content: rendered.html,
    headings: rendered.headings,
    previousDoc: docs[index - 1],
    nextDoc: docs[index + 1]
  });
  const filename = doc.slug === 'index' ? 'index.html' : `${doc.slug}.html`;
  fs.writeFileSync(path.join(outDir, filename), html);
}

fs.writeFileSync(path.join(outDir, 'styles.css'), stylesheet);
fs.writeFileSync(path.join(outDir, '.nojekyll'), '');
fs.writeFileSync(path.join(outDir, '404.html'), pageShell({
  doc: { title: 'Not Found', source: 'README.md', slug: '404', section: 'Home' },
  content: '<header class="doc-header"><h1>Not Found</h1></header><p>The requested ProxyForge documentation page does not exist.</p><p><a href="./">Return to docs index.</a></p>',
  headings: [],
  previousDoc: undefined,
  nextDoc: docs[0]
}));

const urls = docs.map((doc) => `${siteUrl}${doc.slug === 'index' ? '' : `${doc.slug}.html`}`);
fs.writeFileSync(path.join(outDir, 'sitemap.xml'), `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.map((url) => `  <url><loc>${url}</loc></url>`).join('\n')}
</urlset>
`);

console.log(`Built GitHub Pages docs for ${packageJson.name} ${packageJson.version} at ${path.relative(root, outDir)}`);
