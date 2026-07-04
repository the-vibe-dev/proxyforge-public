import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';

const require = createRequire(import.meta.url);
const {
  ProjectLifecycleService,
  projectSnapshotPath,
  resolveProjectCreateRoot,
  resolveProjectOpenRoot,
} = require('../dist-electron/services/projectLifecycleService.js');
const { ProjectStore } = require('../dist-electron/projectStore.js');

const artifactRoot = path.resolve('.gitignored/test-artifacts/project-lifecycle-ipc-contract', `${Date.now()}-${process.pid}`);
const projectsRootDir = path.join(artifactRoot, 'projects');
const backupsRootDir = path.join(artifactRoot, 'restore-points');
await fs.mkdir(artifactRoot, { recursive: true });

const mainSource = await fs.readFile('electron/main.ts', 'utf8');
const preloadSource = await fs.readFile('electron/preload.ts', 'utf8');
assert.match(mainSource, /secureIpcHandle\('project:create'/, 'main process should expose secured project:create IPC');
assert.match(mainSource, /secureIpcHandle\('project:open'/, 'main process should expose secured project:open IPC');
assert.match(mainSource, /secureIpcHandle\('project:close'/, 'main process should expose secured project:close IPC');
assert.match(mainSource, /secureIpcHandle\('project:backup'/, 'main process should expose secured project:backup IPC');
assert.equal((mainSource.match(/ipcMain\.handle\(/g) ?? []).length, 1, 'main process should centralize raw ipcMain.handle registration in secureIpcHandle');
assert.match(mainSource, /assertAuthorizedIpcSender/, 'main process should authorize IPC sender identity before dispatch');
assert.match(mainSource, /bindProjectRecorders/, 'project lifecycle IPC should rebind Project Store recorders');
assert.match(preloadSource, /createProject:.*project:create/s, 'preload should expose a typed createProject bridge');
assert.match(preloadSource, /backupProject:.*project:backup/s, 'preload should expose a typed backupProject bridge');

assert.throws(() => resolveProjectCreateRoot({
  projectsRootDir,
  projectName: 'Traversal Fixture',
  rootDir: '../escape.proxyforge',
}), /traversal/i);
assert.throws(() => resolveProjectOpenRoot({
  projectsRootDir,
  rootDir: path.join(artifactRoot, 'external.proxyforge'),
}), /allowExternalRoot/i);
const externalResolution = resolveProjectOpenRoot({
  projectsRootDir,
  rootDir: path.join(artifactRoot, 'external.proxyforge'),
  allowExternalRoot: true,
});
assert.equal(externalResolution.external, true);

const service = new ProjectLifecycleService({
  projectsRootDir,
  backupsRootDir,
  defaultProjectName: 'Lifecycle Default',
});

try {
  const initial = await service.status();
  assert.equal(initial.kind, 'proxyforge-project-lifecycle-state');
  assert.equal(initial.status, 'closed');
  assert.equal(initial.requirements.typedIpcContract, true);
  assert.equal(initial.requirements.pathTraversalRejected, true);

  const created = await service.createProject({
    projectName: 'Beta Lifecycle Fixture',
    projectId: 'beta-lifecycle-fixture',
    operator: 'ci-lifecycle',
  });
  assert.equal(created.status, 'open');
  assert.equal(created.activeProject.projectId, 'beta-lifecycle-fixture');
  assert.equal(created.activeProject.snapshotPath, projectSnapshotPath(created.activeProject.rootDir));
  assert.equal(created.activeProject.stats.auditEventCount, 1);
  assert.match(created.activeProject.auditEvents[0].hash, /^[a-f0-9]{64}$/);
  await fs.access(path.join(created.activeProject.rootDir, 'manifest.json'));
  if (process.platform !== 'win32') {
    assert.equal((await fs.stat(created.activeProject.rootDir)).mode & 0o777, 0o700, 'project directory should be owner-only');
    assert.equal((await fs.stat(path.join(created.activeProject.rootDir, 'manifest.json'))).mode & 0o777, 0o600, 'manifest should be owner-only');
    assert.equal((await fs.stat(path.join(created.activeProject.rootDir, 'project.db'))).mode & 0o777, 0o600, 'database should be owner-only');
  }

  const store = await ProjectStore.open(created.activeProject.rootDir);
  try {
    await store.addHttpExchange({
      id: 'hx-lifecycle-secret',
      method: 'POST',
      url: 'https://lifecycle.fixture.local/api/session',
      host: 'lifecycle.fixture.local',
      path: '/api/session',
      protocol: 'https',
      status: 200,
      mime: 'application/json',
      timingMs: 41,
      source: 'proxy',
      tags: ['lifecycle', 'full-fidelity'],
      notes: 'Project lifecycle IPC must keep executor material until report export.',
      requestRaw: [
        'POST /api/session HTTP/1.1',
        'Host: lifecycle.fixture.local',
        'Authorization: Bearer lifecycle-secret-token',
        'Cookie: pf_session=lifecycle-secret-cookie',
        'X-API-Key: lifecycle-secret-key',
        '',
        '{"token":"lifecycle-secret-token"}',
      ].join('\r\n'),
      responseRaw: [
        'HTTP/1.1 200 OK',
        'Content-Type: application/json',
        '',
        '{"ok":true,"secretEcho":"lifecycle-secret-token"}',
      ].join('\r\n'),
    });
  } finally {
    store.close();
  }

  const reopenedAfterWrite = await service.openProject({
    rootDir: created.activeProject.rootDir,
    operator: 'ci-lifecycle',
  });
  assert.equal(reopenedAfterWrite.activeProject.stats.exchangeCount, 1);
  assert.equal(reopenedAfterWrite.activeProject.stats.auditEventCount >= 2, true);

  const backup = await service.backupProject({
    label: 'lifecycle-restore-point',
    operator: 'ci-lifecycle',
  });
  assert.equal(backup.kind, 'proxyforge-project-lifecycle-backup-response');
  assert.equal(backup.backup.kind, 'proxyforge-project-store-backup');
  assert.equal(backup.backup.requirements.databaseCopied, true);
  assert.equal(backup.backup.requirements.rawOperationalSecretsPreserved, true);
  assert.match(backup.backup.content, /beta-lifecycle-fixture/);
  await fs.access(backup.backup.manifestPath);

  const restored = await ProjectStore.open(backup.backup.backupDir);
  try {
    const restoredExchange = restored.getHttpExchange('hx-lifecycle-secret');
    assert(restoredExchange);
    assert.match(restoredExchange.requestRaw.toString('utf8'), /Bearer lifecycle-secret-token/);
    assert.match(restoredExchange.requestRaw.toString('utf8'), /pf_session=lifecycle-secret-cookie/);
    assert.match(restoredExchange.requestRaw.toString('utf8'), /lifecycle-secret-key/);
  } finally {
    restored.close();
  }

  const closed = await service.closeProject({ operator: 'ci-lifecycle' });
  assert.equal(closed.status, 'closed');
  assert.equal(closed.recentProjects[0].projectId, 'beta-lifecycle-fixture');

  const reopened = await service.openProject({
    rootDir: created.activeProject.rootDir,
    operator: 'ci-lifecycle',
  });
  assert.equal(reopened.status, 'open');
  assert.equal(reopened.activeProject.stats.exchangeCount, 1);
  assert.equal(reopened.activeProject.auditEvents.some((event) => event.action === 'project.open'), true);

  await assert.rejects(
    service.createProject({
      projectName: 'External Blocked',
      rootDir: path.join(artifactRoot, 'external-blocked.proxyforge'),
      operator: 'ci-lifecycle',
    }),
    /allowExternalRoot/i,
  );

  const symlinkEscapeTarget = path.join(artifactRoot, 'symlink-escape-target');
  const symlinkProjectRoot = path.join(projectsRootDir, 'escaped.proxyforge');
  await fs.mkdir(symlinkEscapeTarget, { recursive: true });
  try {
    await fs.symlink(symlinkEscapeTarget, symlinkProjectRoot, 'dir');
    await assert.rejects(
      service.createProject({
        projectName: 'Symlink Escape',
        rootDir: symlinkProjectRoot,
        operator: 'ci-lifecycle',
      }),
      /symlink|junction/i,
    );
    await assert.rejects(
      service.openProject({
        rootDir: symlinkProjectRoot,
        operator: 'ci-lifecycle',
      }),
      /symlink|junction/i,
    );
    await assert.rejects(fs.access(path.join(symlinkEscapeTarget, 'manifest.json')), /ENOENT/);
  } catch (error) {
    if ((error?.code ?? '') !== 'EPERM' && (error?.code ?? '') !== 'EACCES') throw error;
  }

  const external = await service.createProject({
    projectName: 'External Allowed',
    rootDir: path.join(artifactRoot, 'external-allowed.proxyforge'),
    operator: 'ci-lifecycle',
    allowExternalRoot: true,
  });
  assert.equal(external.activeProject.rootDir.endsWith('external-allowed.proxyforge'), true);
  assert.equal(external.activeProject.auditEvents[0].detail.includes('explicit capability'), true);

  console.log(`project-lifecycle-ipc-contract: created/opened/closed/backed up active Project Store, validated IPC bridge exposure, rejected traversal, and preserved full-fidelity secrets in ${artifactRoot}`);
} finally {
  await service.dispose();
}
