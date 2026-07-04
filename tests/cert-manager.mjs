import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

const require = createRequire(import.meta.url);
const { CertificateAuthorityManager } = require('../dist-electron/certManager.js');

const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'proxyforge-ca-'));

try {
  const manager = new CertificateAuthorityManager(tempDir);
  const initialStatus = await manager.status();
  assert.equal(initialStatus.ready, false);

  const generatedStatus = await manager.ensureRoot();
  assert.equal(generatedStatus.ready, true);
  assert.match(generatedStatus.fingerprintSha256, /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);

  const exported = await manager.exportRootPem();
  assert.match(exported.pem, /BEGIN CERTIFICATE/);
  assert.equal(exported.path, path.join(tempDir, 'projects', 'default-project', 'proxyforge-root-ca.pem'));

  const secureContext = await manager.secureContextForHost('example.test');
  assert.ok(secureContext);
  assert.equal((await manager.status()).hostCertificateCount, 1);

  const defaultFingerprint = exported.fingerprintSha256;
  const projectStatus = await manager.setProject('Retail API Assessment');
  assert.equal(projectStatus.projectId, 'retail-api-assessment');
  assert.equal(projectStatus.ready, false);
  assert.notEqual(projectStatus.rootCertificatePath, exported.path);

  const projectRoot = await manager.ensureRoot();
  assert.equal(projectRoot.ready, true);
  assert.notEqual(projectRoot.fingerprintSha256, defaultFingerprint);
  await manager.secureContextForHost('api.shop.local');
  assert.equal((await manager.status()).hostCertificateCount, 1);

  const rotated = await manager.rotateRoot();
  assert.equal(rotated.ready, true);
  assert.match(rotated.fingerprintSha256, /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
  assert.notEqual(rotated.fingerprintSha256, projectRoot.fingerprintSha256);
  assert.ok(rotated.lastRotatedAt);
  assert.equal(rotated.hostCertificateCount, 0);

  const revoked = await manager.revokeRoot();
  assert.equal(revoked.ready, false);
  assert.ok(revoked.revokedAt);
  assert.equal(revoked.hostCertificateCount, 0);
} finally {
  await fs.rm(tempDir, { recursive: true, force: true });
}
