import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';

const tempDir = path.resolve('.gitignored/test-artifacts/agent-advertised-command-dispatch', `${Date.now()}-${process.pid}`);
const projectPath = path.join(tempDir, 'project.proxyforge.json');
const specPath = path.join(tempDir, 'spec.json');

await fs.mkdir(tempDir, { recursive: true });
await fs.writeFile(projectPath, JSON.stringify({
  version: 1,
  projectName: 'Agent Advertised Command Dispatch',
  scopeAllowlist: ['127.0.0.1', 'localhost'],
  exchanges: [
    {
      id: 'hx-dispatch-1',
      method: 'GET',
      host: '127.0.0.1',
      path: '/dispatch?token=pf_live_validation_token',
      url: 'http://127.0.0.1:18090/dispatch?token=pf_live_validation_token',
      status: 200,
      length: 512,
      mime: 'text/html',
      risk: 'medium',
      timing: 24,
      source: 'proxy',
      time: '2026-06-22T01:45:00.000Z',
      requestRaw: 'GET /dispatch?token=pf_live_validation_token HTTP/1.1\r\nHost: 127.0.0.1:18090\r\nAuthorization: Bearer pf_live_validation_token\r\nCookie: session=pf_live_validation_secret\r\n\r\n',
      responseRaw: 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body><a href="/next">next</a><script>fetch("/api/dispatch")</script><div>pf_live_validation_secret</div></body></html>',
      tags: ['dispatch', 'agent'],
    },
  ],
  issues: [],
}), 'utf8');

await fs.writeFile(specPath, JSON.stringify({
  openapi: '3.0.0',
  info: { title: 'Dispatch API', version: '1.0.0' },
  paths: {
    '/dispatch': {
      get: {
        responses: { 200: { description: 'ok' } },
      },
    },
  },
}), 'utf8');

const commands = [
  ['playbook-list', ['playbook-list', '--project', projectPath, '--json']],
  ['playbook-plan', ['playbook-plan', '--project', projectPath, '--request-id', 'hx-dispatch-1', '--json']],
  ['playbook-run', ['playbook-run', '--project', projectPath, '--request-id', 'hx-dispatch-1', '--execute', '--json']],
  ['playbook-export', ['playbook-export', '--project', projectPath, '--request-id', 'hx-dispatch-1', '--out', path.join(tempDir, 'playbook-export.json'), '--json']],
  ['playback-client', ['playback-client', '--project', projectPath, '--target', 'http://127.0.0.1:18090', '--execute', '--json']],
  ['playback-server', ['playback-server', '--project', projectPath, '--json']],
  ['spec-import', ['spec-import', '--project', projectPath, '--file', specPath, '--json']],
  ['spider-passive-run', ['spider-passive-run', '--project', projectPath, '--target', 'http://127.0.0.1:18090/dispatch', '--json']],
  ['spider-ajax-run', ['spider-ajax-run', '--project', projectPath, '--target', 'http://127.0.0.1:18090/dispatch', '--json']],
  ['dom-tracer-sessions', ['dom-tracer-sessions', '--project', projectPath, '--target', 'http://127.0.0.1:18090/dispatch', '--json']],
  ['dom-tracer-export', ['dom-tracer-export', '--project', projectPath, '--target', 'http://127.0.0.1:18090/dispatch', '--out', path.join(tempDir, 'dom-tracer-export.json'), '--json']],
];

for (const [name, args] of commands) {
  const proc = spawnSync(process.execPath, ['scripts/proxyforge-agent.mjs', ...args], {
    cwd: path.resolve('.'),
    encoding: 'utf8',
    maxBuffer: 8 * 1024 * 1024,
  });
  await fs.writeFile(path.join(tempDir, `${name}.stdout`), proc.stdout || '', 'utf8');
  await fs.writeFile(path.join(tempDir, `${name}.stderr`), proc.stderr || '', 'utf8');
  assert.equal(proc.status, 0, `${name} exited non-zero: ${proc.stderr || proc.stdout}`);
  const parsed = JSON.parse(proc.stdout);
  await fs.writeFile(path.join(tempDir, `${name}.json`), JSON.stringify(parsed, null, 2), 'utf8');
  assert.equal(parsed.command, name, `${name} should round-trip command name`);
  assert.notEqual(parsed.status, 'blocked', `${name} should be wired`);
  assert.equal(parsed.safety.trafficSent, false, `${name} should not claim socket traffic from the agent wrapper`);
}
