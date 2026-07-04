import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';

const require = createRequire(import.meta.url);
const { AiEngine } = require('../dist-electron/aiEngine.js');

const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'proxyforge-ai-'));
let localServer;

try {
  const localProvider = await startOpenAiCompatibleProvider();
  process.env.PROXYFORGE_AI_TEST_KEY = 'local-secret';
  const engine = new AiEngine(path.join(tempDir, 'providers.json'));
  const providers = await engine.loadProviders();
  assert(providers.some((provider) => provider.id === 'codex'));
  assert(providers.some((provider) => provider.id === 'claude'));
  assert(providers.some((provider) => provider.id === 'local'));

  const probeScript = [
    'let stdin = "";',
    'process.stdin.on("data", (chunk) => { stdin += chunk; });',
    'process.stdin.on("end", () => {',
    '  process.stdout.write(JSON.stringify({',
    '    fullSecrets: stdin.includes("SECRET_TOKEN") && stdin.includes("session=abc123"),',
    '    hasScope: stdin.includes("*.shop.local"),',
    '    hasTask: stdin.includes("Triage captured traffic")',
    '  }));',
    '});',
  ].join('');

  const savedProviders = await engine.saveProviders([
    {
      id: 'codex',
      label: 'Codex',
      mode: 'cli',
      enabled: true,
      model: 'test-model',
      command: process.execPath,
      args: ['-e', probeScript],
      timeoutMs: 10000,
    },
    {
      id: 'claude',
      label: 'Claude',
      mode: 'cli',
      enabled: true,
      model: 'claude-test-model',
      command: process.execPath,
      args: ['-e', probeScript],
      timeoutMs: 10000,
    },
    {
      id: 'local',
      label: 'OpenAI-compatible Local',
      mode: 'http',
      enabled: true,
      model: 'local-test-model',
      endpoint: localProvider.endpoint,
      apiKeyEnv: 'PROXYFORGE_AI_TEST_KEY',
      timeoutMs: 10000,
      inputCostPerMillionTokens: 0.5,
      outputCostPerMillionTokens: 1,
    },
  ]);
  assert(savedProviders.find((provider) => provider.id === 'local')?.secretPresent, 'local provider should see test API key');

  const codexResult = await runTask(engine, 'codex', 'Find the strongest issue and include file command test diff verify gates.');
  const claudeResult = await runTask(engine, 'claude', 'Find the strongest issue using XML sections, bullets, and explicit assumptions.');
  const localResult = await runTask(engine, 'local', 'Find the strongest issue inside the authorized scope with safe next steps.');

  for (const result of [codexResult, claudeResult, localResult]) {
    assert.equal(result.status, 'complete', `${result.providerId} should complete`);
    assert.match(result.output, /"fullSecrets":true/, `${result.providerId} should receive full-fidelity secrets`);
    assert.match(result.output, /"hasScope":true/, `${result.providerId} should receive scope`);
    assert.match(result.output, /"hasTask":true/, `${result.providerId} should receive task label`);
    assert(result.usage.totalTokens > 0, `${result.providerId} should expose token accounting`);
    assert(result.streamEvents.some((event) => event.source === 'complete'), `${result.providerId} should emit completion telemetry`);
    assert(result.promptEvaluation.score > 0, `${result.providerId} should evaluate prompt readiness`);
    assert(result.suggestedActions.some((action) => action.kind === 'stage-repeater'), `${result.providerId} should suggest Repeater staging`);
    assert(result.suggestedActions.some((action) => action.kind === 'queue-active-scan'), `${result.providerId} should suggest Scanner queueing`);
  }

  assert.equal(codexResult.usage.source, 'estimated');
  assert(codexResult.streamEvents.some((event) => event.source === 'stdout' && event.text.includes('fullSecrets')));
  assert(codexResult.promptEvaluation.checks.some((check) => check.label === 'Codex execution shape' && check.status === 'ready'));
  assert(claudeResult.promptEvaluation.checks.some((check) => check.label === 'Claude structure' && check.status === 'ready'));
  assert.equal(localResult.usage.source, 'provider');
  assert(localResult.streamEvents.some((event) => event.source === 'http'));
  assert.equal(localProvider.requestCount, 1, 'local OpenAI-compatible provider should receive one request');
  assert.equal(localProvider.lastAuthorization, 'Bearer local-secret', 'local provider should receive API key from env');
} finally {
  await fs.rm(tempDir, { recursive: true, force: true });
  delete process.env.PROXYFORGE_AI_TEST_KEY;
  await new Promise((resolve) => {
    if (!localServer) {
      resolve();
      return;
    }
    localServer.close(resolve);
  });
}

async function runTask(engine, providerId, prompt) {
  return engine.runTask({
    providerId,
    task: 'triage',
    prompt,
    context: {
      projectName: 'Retail API Assessment',
      scopeAllowlist: ['*.shop.local'],
      taskHint: 'Traffic triage',
      exchanges: [
        {
          method: 'GET',
          host: 'app.shop.local',
          path: '/api/account/profile',
          status: 200,
          risk: 'medium',
          notes: 'Session object exposes role hints',
          requestRaw: 'GET /api/account/profile HTTP/2\nHost: app.shop.local\nAuthorization: Bearer SECRET_TOKEN\nCookie: session=abc123\n\n',
          responseRaw: 'HTTP/2 200 OK\nContent-Type: application/json\n\n{"role":"support_admin"}',
          tags: ['auth'],
        },
      ],
      issues: [
        {
          title: 'Role hint exposed in profile response',
          severity: 'medium',
          host: 'app.shop.local',
          path: '/api/account/profile',
          detail: 'Profile response exposes role hints.',
          remediation: 'Avoid returning internal role labels.',
        },
      ],
    },
  });
}

async function startOpenAiCompatibleProvider() {
  const state = {
    requestCount: 0,
    lastAuthorization: '',
    endpoint: '',
  };
  localServer = http.createServer(async (request, response) => {
    state.requestCount += 1;
    state.lastAuthorization = request.headers.authorization ?? '';
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const body = Buffer.concat(chunks).toString('utf8');
    const parsed = JSON.parse(body);
    const prompt = parsed.messages?.map((message) => message.content).join('\n') ?? '';
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({
      choices: [
        {
          message: {
            content: JSON.stringify({
              fullSecrets: prompt.includes('SECRET_TOKEN') && prompt.includes('session=abc123'),
              hasScope: prompt.includes('*.shop.local'),
              hasTask: prompt.includes('Triage captured traffic'),
            }),
          },
        },
      ],
      usage: {
        prompt_tokens: 100,
        completion_tokens: 20,
        total_tokens: 120,
      },
    }));
  });
  await new Promise((resolve) => localServer.listen(0, '127.0.0.1', resolve));
  const address = localServer.address();
  state.endpoint = `http://127.0.0.1:${address.port}/v1/chat/completions`;
  return state;
}
