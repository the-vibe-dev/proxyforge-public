import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';

const require = createRequire(import.meta.url);
const { runHeadlessScan } = require('../dist-electron/headlessRunner.js');

const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'proxyforge-headless-'));
const observedAuth = {
  programmaticCrawler: false,
  programmaticActiveScan: false,
  programmaticCrawlAudit: false,
  cliActiveScan: false,
};
const target = http.createServer((request, response) => {
  const authorization = String(request.headers.authorization ?? '');
  const cookie = String(request.headers.cookie ?? '');
  const apiKey = String(request.headers['x-api-key'] ?? '');
  const hasProgrammaticSession = authorization === 'Bearer headless-token'
    && cookie.includes('session=headless-session')
    && apiKey === 'headless-api-key';
  const hasCliSession = authorization === 'Bearer cli-token'
    && cookie.includes('session=cli-session');

  if (hasProgrammaticSession) {
    if (request.headers['x-proxyforge-insertion-point']) observedAuth.programmaticCrawlAudit = true;
    else if (request.headers['x-proxyforge-active-scan']) observedAuth.programmaticActiveScan = true;
    else observedAuth.programmaticCrawler = true;
  }
  if (hasCliSession && request.headers['x-proxyforge-active-scan']) {
    observedAuth.cliActiveScan = true;
  }

  if (request.method === 'OPTIONS') {
    response.writeHead(204, {
      allow: 'GET, POST, DELETE',
      'access-control-allow-methods': 'GET, POST, DELETE',
    });
    response.end();
    return;
  }

  if (request.url === '/') {
    response.writeHead(200, { 'content-type': 'text/html' });
    response.end([
      '<html><title>Headless Seed</title>',
      '<a href="/orders?status=open">Orders</a>',
      '<form method="post" action="/api/refunds">',
      '<input name="orderId"><input name="amount">',
      '</form></html>',
    ].join(''));
    return;
  }

  const bodyParts = [`path=${request.url}`];
  if (hasProgrammaticSession || hasCliSession) bodyParts.push('authenticated-session');
  if (request.headers.origin) bodyParts.push('cors-origin');
  if (request.headers['x-forwarded-host']) bodyParts.push(String(request.headers['x-forwarded-host']));
  if (request.headers['x-proxyforge-auth-state']) bodyParts.push('role=support_admin scope=refunds.write');
  if (request.headers['x-proxyforge-token-audit']) bodyParts.push('token=eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic3VwcG9ydF9hZG1pbiJ9.signature');
  if (request.headers['x-proxyforge-active-scan'] === 'graphql-introspection') bodyParts.push('__schema queryType mutationType');

  const headers = {
    'content-type': request.headers.origin ? 'application/json' : 'text/html',
    ...(request.headers.origin ? {
      'access-control-allow-origin': request.headers.origin,
      'access-control-allow-credentials': 'true',
    } : {}),
  };
  response.writeHead(200, headers);
  response.end(`<html>${bodyParts.join(' ')}</html>`);
});

try {
  const port = await listen(target);
  const targetUrl = `http://127.0.0.1:${port}/`;
  const outDir = path.join(tempDir, 'artifacts');
  const summary = await runHeadlessScan({
    projectName: 'Headless CI Assessment',
    targetUrl,
    scopeAllowlist: ['127.0.0.1'],
    outDir,
    failOnSeverity: 'medium',
    crawl: {
      maxDepth: 1,
      maxPages: 4,
      throttleMs: 0,
      includeForms: true,
    },
    session: {
      headers: {
        Authorization: 'Bearer headless-token',
        'X-API-Key': 'headless-api-key',
      },
      cookies: {
        session: 'headless-session',
      },
    },
    activeScan: {
      checks: ['security-headers', 'cors-origin', 'cache-key', 'method-options', 'authz-diff', 'jwt-claims', 'graphql-introspection'],
      throttleMs: 0,
      maxRequests: 7,
    },
    crawlAudit: {
      enabled: true,
      checks: ['security-headers', 'method-options'],
      throttleMs: 0,
      maxInsertionPoints: 2,
    },
    report: {
      formats: ['json', 'markdown', 'bundle'],
      sections: ['executive', 'technical', 'evidence'],
      signingSecret: 'headless-signing-secret',
      signEvidenceBundle: true,
    },
    ci: {
      outputs: ['sarif', 'junit'],
    },
  });

  assert.equal(summary.blocked, false);
  assert.equal(summary.exitCode, 2);
  assert.equal(summary.sessionHeaderCount, 3);
  assert.equal(summary.sessionCookieCount, 1);
  assert(['medium', 'high', 'critical'].includes(summary.highestSeverity));
  assert(summary.routeCount >= 2);
  assert(summary.insertionPointCount >= 2);
  assert(summary.totalRequests >= 10);
  assert(summary.findingCount >= 4);
  assert(summary.scannerTuning.length >= 2);
  assert(summary.scannerTuning.some((tuning) => tuning.falsePositiveControls.includes('suppress-error-page-security-header-noise')));
  assert.equal(summary.suppressedFindingCount, summary.suppressedFindings.length);
  assert(summary.findings.some((finding) => finding.title === 'HTML response missing Content-Security-Policy'));
  assert(summary.findings.some((finding) => finding.title === 'OPTIONS response advertises state-changing methods'));
  assert.equal(summary.reports.length, 3);
  assert(summary.reports.some((artifact) => artifact.format === 'bundle'));
  assert.equal(summary.ciArtifacts.length, 2);
  assert(summary.ciArtifacts.some((artifact) => artifact.format === 'sarif'));
  assert(summary.ciArtifacts.some((artifact) => artifact.format === 'junit'));
  assert.equal(observedAuth.programmaticCrawler, true);
  assert.equal(observedAuth.programmaticActiveScan, true);
  assert.equal(observedAuth.programmaticCrawlAudit, true);

  const summaryFile = JSON.parse(await fs.readFile(summary.summaryPath, 'utf8'));
  assert.equal(summaryFile.projectName, 'Headless CI Assessment');
  assert.equal(summaryFile.reportCount, 3);
  assert.equal(summaryFile.ciArtifactCount, 2);
  assert.equal(summaryFile.suppressedFindingCount, summary.suppressedFindingCount);
  assert(summaryFile.scannerTuning.length >= 2);
  assert(!JSON.stringify(summaryFile).includes('headless-signing-secret'));
  assert(!JSON.stringify(summaryFile).includes('headless-token'));
  assert(!JSON.stringify(summaryFile).includes('headless-session'));
  assert(!JSON.stringify(summaryFile).includes('headless-api-key'));

  const sarifArtifact = summary.ciArtifacts.find((artifact) => artifact.format === 'sarif');
  assert(sarifArtifact);
  const parsedSarif = JSON.parse(await fs.readFile(sarifArtifact.path, 'utf8'));
  assert.equal(parsedSarif.version, '2.1.0');
  assert.equal(parsedSarif.runs[0].tool.driver.name, 'ProxyForge');
  assert(parsedSarif.runs[0].results.length >= summary.findingCount);
  assert(parsedSarif.runs[0].results.some((result) => result.ruleId.startsWith('PF-html-response-missing-content-security-policy')));

  const junitArtifact = summary.ciArtifacts.find((artifact) => artifact.format === 'junit');
  assert(junitArtifact);
  const junitXml = await fs.readFile(junitArtifact.path, 'utf8');
  assert.match(junitXml, /<testsuites name="ProxyForge Headless"/);
  assert.match(junitXml, /<failure type="medium"/);

  const jsonReport = summary.reports.find((artifact) => artifact.format === 'json');
  assert(jsonReport);
  const parsedJsonReport = JSON.parse(await fs.readFile(jsonReport.path, 'utf8'));
  assert.equal(parsedJsonReport.projectName, 'Headless CI Assessment');
  assert(parsedJsonReport.summary.totalIssues >= 4);
  assert(!JSON.stringify(parsedJsonReport).includes('headless-token'));
  assert(!JSON.stringify(parsedJsonReport).includes('headless-session'));
  assert(!JSON.stringify(parsedJsonReport).includes('headless-api-key'));
  assert(JSON.stringify(parsedJsonReport).includes('Authorization: [redacted]'));
  assert(JSON.stringify(parsedJsonReport).includes('Cookie: [redacted]'));
  assert(JSON.stringify(parsedJsonReport).includes('X-API-Key: [redacted]'));

  const bundleReport = summary.reports.find((artifact) => artifact.format === 'bundle');
  assert(bundleReport);
  const parsedBundle = JSON.parse(await fs.readFile(bundleReport.path, 'utf8'));
  assert.equal(parsedBundle.manifest.kind, 'proxyforge-evidence-bundle');
  assert.equal(parsedBundle.signature.status, 'signed');
  assert(!JSON.stringify(parsedBundle).includes('headless-signing-secret'));

  const projectPath = path.join(tempDir, 'headless-project.proxyforge.json');
  const projectExchange = {
    id: 'hx-project-seed',
    method: 'GET',
    host: '127.0.0.1',
    path: '/orders?status=open',
    url: `http://127.0.0.1:${port}/orders?status=open`,
    status: 200,
    length: 42,
    mime: 'text/html',
    risk: 'low',
    timing: 12,
    notes: 'Saved project request from Repeater',
    source: 'repeater',
    time: '12:00:00',
    requestRaw: [
      'GET /orders?status=open HTTP/1.1',
      `Host: 127.0.0.1:${port}`,
      'Accept: text/html',
      '',
      '',
    ].join('\n'),
    responseRaw: 'HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html>saved evidence</html>',
    tags: ['saved', 'authz'],
  };
  await fs.writeFile(projectPath, JSON.stringify({
    version: 1,
    savedAt: new Date().toISOString(),
    projectName: 'Saved Project Replay',
    scopeAllowlist: ['127.0.0.1'],
    exchanges: [projectExchange],
    importedBundleIssues: [
      {
        id: 'issue-project-1',
        title: 'Project file retained issue',
        severity: 'low',
        host: '127.0.0.1',
        path: '/orders?status=open',
        confidence: 'firm',
        status: 'open',
        detail: 'Issue imported from a saved project file.',
        remediation: 'Confirm the saved project issue still reproduces in CI.',
      },
    ],
  }, null, 2));

  const projectSummary = await runHeadlessScan({
    projectFile: projectPath,
    projectExchangeId: 'hx-project-seed',
    outDir: path.join(tempDir, 'project-artifacts'),
    crawl: { enabled: false },
    activeScan: {
      checks: ['security-headers'],
      throttleMs: 0,
      maxRequests: 1,
    },
    report: { formats: ['json'], sections: ['executive', 'technical', 'evidence'] },
    ci: { outputs: ['sarif'] },
    failOnSeverity: 'none',
  });
  assert.equal(projectSummary.projectName, 'Saved Project Replay');
  assert.equal(projectSummary.projectFilePath, projectPath);
  assert.equal(projectSummary.projectExchangeCount, 1);
  assert.equal(projectSummary.seedExchangeId, 'hx-project-seed');
  assert.equal(projectSummary.targetUrl, projectExchange.url);
  assert(projectSummary.totalRequests >= 2);
  assert(projectSummary.findings.some((finding) => finding.title === 'Project file retained issue'));
  assert(projectSummary.logs.some((line) => line.includes('Loaded project file')));
  const projectJsonReport = projectSummary.reports.find((artifact) => artifact.format === 'json');
  assert(projectJsonReport);
  const parsedProjectReport = JSON.parse(await fs.readFile(projectJsonReport.path, 'utf8'));
  assert(parsedProjectReport.exchanges.some((exchange) => exchange.id === 'hx-project-seed' && exchange.tags.includes('project-file')));

  const configPath = path.join(tempDir, 'proxyforge-headless.json');
  const cliOutDir = path.join(tempDir, 'cli-artifacts');
  await fs.writeFile(configPath, JSON.stringify({
    projectName: 'Headless CLI Assessment',
    projectFile: projectPath,
    projectExchangeId: 'hx-project-seed',
    scopeAllowlist: ['127.0.0.1'],
    crawl: { enabled: false },
    activeScan: {
      checks: ['security-headers'],
      throttleMs: 0,
      maxRequests: 1,
    },
    report: { formats: ['json'] },
    ci: { outputs: ['sarif'] },
    failOnSeverity: 'critical',
  }, null, 2));

  const cli = await runCli([
    path.join(process.cwd(), 'dist-electron', 'headlessRunner.js'),
    'headless',
    '--config',
    configPath,
    '--out-dir',
    cliOutDir,
    '--report',
    'json',
    '--junit',
  ], {
    env: {
      ...process.env,
      PROXYFORGE_AUTHORIZATION: 'Bearer cli-token',
      PROXYFORGE_COOKIE: 'session=cli-session',
      PROXYFORGE_BEARER_TOKEN: '',
      PROXYFORGE_API_KEY: '',
      PROXYFORGE_SESSION_HEADERS: '',
    },
  });
  assert.equal(cli.status, 0, cli.stderr);
  const cliSummary = JSON.parse(cli.stdout);
  assert.equal(cliSummary.projectName, 'Headless CLI Assessment');
  assert.equal(cliSummary.projectFilePath, projectPath);
  assert.equal(cliSummary.seedExchangeId, 'hx-project-seed');
  assert.equal(cliSummary.sessionHeaderCount, 2);
  assert.equal(cliSummary.sessionCookieCount, 1);
  assert.equal(cliSummary.reportCount, 1);
  assert.equal(cliSummary.ciArtifactCount, 2);
  assert.equal(cliSummary.outDir, cliOutDir);
  assert.equal(observedAuth.cliActiveScan, true);
  assert(!cli.stdout.includes('cli-token'));
  assert(!cli.stdout.includes('cli-session'));
  assert(!cli.stderr.includes('cli-token'));
  assert(!cli.stderr.includes('cli-session'));
  assert.equal((await fs.stat(cliSummary.summaryPath)).isFile(), true);
  assert.equal((await fs.stat(path.join(cliOutDir, 'proxyforge-results.sarif'))).isFile(), true);
  assert.equal((await fs.stat(path.join(cliOutDir, 'proxyforge-junit.xml'))).isFile(), true);
  assert(!JSON.stringify(JSON.parse(await fs.readFile(cliSummary.summaryPath, 'utf8'))).includes('cli-token'));
  assert(!JSON.stringify(JSON.parse(await fs.readFile(cliSummary.summaryPath, 'utf8'))).includes('cli-session'));
} finally {
  await close(target);
  await fs.rm(tempDir, { recursive: true, force: true });
}

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return server.address().port;
}

async function close(server) {
  await new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}

function runCli(args, options = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, args, {
      ...options,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString('utf8');
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString('utf8');
    });
    child.on('error', (error) => {
      resolve({ status: 1, stdout, stderr: `${stderr}${error.message}` });
    });
    child.on('close', (status) => {
      resolve({ status: status ?? 1, stdout, stderr });
    });
  });
}
