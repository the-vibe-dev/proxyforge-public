import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import tls from 'node:tls';
import forge from 'node-forge';

export interface CertificateAuthorityStatus {
  ready: boolean;
  rootCertificatePath: string;
  projectId: string;
  projectLabel: string;
  projectCertificateDir: string;
  fingerprintSha256?: string;
  validUntil?: string;
  hostCertificateCount: number;
  lastRotatedAt?: string;
  revokedAt?: string;
  message: string;
}

interface RootMaterial {
  certPem: string;
  keyPem: string;
  privateKey: forge.pki.rsa.PrivateKey;
  certificate: forge.pki.Certificate;
}

const ROOT_CERT_FILE = 'proxyforge-root-ca.pem';
const ROOT_KEY_FILE = 'proxyforge-root-ca.key.pem';
const HOST_CERT_DAYS = 825;
const DEFAULT_PROJECT_LABEL = 'Default Project';
const REVOCATION_FILE = 'revoked-root.json';

export class CertificateAuthorityManager {
  private rootMaterial: RootMaterial | null = null;
  private contexts = new Map<string, tls.SecureContext>();
  private activeProject = {
    id: projectSlug(DEFAULT_PROJECT_LABEL),
    label: DEFAULT_PROJECT_LABEL,
  };

  constructor(private readonly baseDir: string) {}

  async setProject(label: string): Promise<CertificateAuthorityStatus> {
    const nextLabel = label.trim() || DEFAULT_PROJECT_LABEL;
    const nextProject = { id: projectSlug(nextLabel), label: nextLabel };
    if (nextProject.id !== this.activeProject.id) {
      this.rootMaterial = null;
      this.contexts.clear();
    }
    this.activeProject = nextProject;
    return this.status(`Certificate workspace switched to ${nextProject.label}.`);
  }

  rootCertificatePath() {
    return path.join(this.projectDir(), ROOT_CERT_FILE);
  }

  projectCertificateDir() {
    return this.projectDir();
  }

  private projectDir() {
    return path.join(this.baseDir, 'projects', this.activeProject.id);
  }

  async status(message?: string): Promise<CertificateAuthorityStatus> {
    const rootCertificatePath = this.rootCertificatePath();
    const projectCertificateDir = this.projectDir();
    const [hostCertificateCount, revocation] = await Promise.all([
      countHostCertificates(path.join(projectCertificateDir, 'hosts')),
      readRevocation(projectCertificateDir),
    ]);

    try {
      const certPem = await fs.readFile(rootCertificatePath, 'utf8');
      const certificate = forge.pki.certificateFromPem(certPem);
      return {
        ready: true,
        rootCertificatePath,
        projectId: this.activeProject.id,
        projectLabel: this.activeProject.label,
        projectCertificateDir,
        fingerprintSha256: sha256Fingerprint(certPem),
        validUntil: certificate.validity.notAfter.toISOString(),
        hostCertificateCount,
        lastRotatedAt: revocation?.rotatedAt,
        revokedAt: revocation?.revokedAt,
        message: message ?? 'Project root CA exists. Import only this project certificate into the browser or OS trust store.',
      };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      return {
        ready: false,
        rootCertificatePath,
        projectId: this.activeProject.id,
        projectLabel: this.activeProject.label,
        projectCertificateDir,
        hostCertificateCount,
        lastRotatedAt: revocation?.rotatedAt,
        revokedAt: revocation?.revokedAt,
        message: message ?? (revocation?.revokedAt ? 'Project root CA was revoked locally. Rotate or generate a fresh project CA before HTTPS inspection.' : 'Project root CA has not been generated yet.'),
      };
    }
  }

  async ensureRoot(): Promise<CertificateAuthorityStatus> {
    await this.loadOrCreateRoot();
    return this.status();
  }

  async exportRootPem() {
    const root = await this.loadOrCreateRoot();
    return {
      pem: root.certPem,
      path: this.rootCertificatePath(),
      fingerprintSha256: sha256Fingerprint(root.certPem),
    };
  }

  async rotateRoot(reason = 'operator-requested'): Promise<CertificateAuthorityStatus> {
    const root = await this.loadOrCreateRoot();
    const projectDir = this.projectDir();
    const rotatedAt = new Date().toISOString();
    const archiveDir = path.join(projectDir, 'rotated', rotatedAt.replace(/[:.]/g, '-'));
    await fs.mkdir(archiveDir, { recursive: true });

    await Promise.all([
      moveIfExists(path.join(projectDir, ROOT_CERT_FILE), path.join(archiveDir, ROOT_CERT_FILE)),
      moveIfExists(path.join(projectDir, ROOT_KEY_FILE), path.join(archiveDir, ROOT_KEY_FILE)),
      moveIfExists(path.join(projectDir, 'hosts'), path.join(archiveDir, 'hosts')),
    ]);
    await fs.writeFile(
      path.join(archiveDir, 'rotation.json'),
      JSON.stringify({
        projectId: this.activeProject.id,
        projectLabel: this.activeProject.label,
        rotatedAt,
        reason,
        previousFingerprintSha256: sha256Fingerprint(root.certPem),
      }, null, 2),
      'utf8',
    );
    await writeRevocation(projectDir, {
      rotatedAt,
      reason,
      previousFingerprintSha256: sha256Fingerprint(root.certPem),
    });

    this.rootMaterial = null;
    this.contexts.clear();
    await this.loadOrCreateRoot();
    return this.status('Project root CA rotated. Re-import the new PEM into any browser or OS trust store.');
  }

  async revokeRoot(reason = 'operator-requested'): Promise<CertificateAuthorityStatus> {
    let previousFingerprintSha256: string | undefined;
    try {
      const root = await this.loadOrCreateRoot();
      previousFingerprintSha256 = sha256Fingerprint(root.certPem);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }

    const projectDir = this.projectDir();
    const revokedAt = new Date().toISOString();
    await Promise.all([
      removeIfExists(path.join(projectDir, ROOT_CERT_FILE)),
      removeIfExists(path.join(projectDir, ROOT_KEY_FILE)),
      removeIfExists(path.join(projectDir, 'hosts')),
    ]);
    await writeRevocation(projectDir, {
      revokedAt,
      reason,
      previousFingerprintSha256,
    });
    this.rootMaterial = null;
    this.contexts.clear();
    return this.status('Project root CA revoked locally. Remove the old PEM from external trust stores before continuing.');
  }

  async secureContextForHost(host: string) {
    const normalizedHost = host.split(':')[0].toLowerCase();
    const cached = this.contexts.get(normalizedHost);
    if (cached) return cached;

    const root = await this.loadOrCreateRoot();
    const hostMaterial = await this.loadOrCreateHostCertificate(root, normalizedHost);
    const context = tls.createSecureContext({
      cert: hostMaterial.certPem,
      key: hostMaterial.keyPem,
    });
    this.contexts.set(normalizedHost, context);
    return context;
  }

  private async loadOrCreateRoot(): Promise<RootMaterial> {
    if (this.rootMaterial) return this.rootMaterial;

    await fs.mkdir(this.projectDir(), { recursive: true });
    const certPath = this.rootCertificatePath();
    const keyPath = path.join(this.projectDir(), ROOT_KEY_FILE);

    try {
      const [certPem, keyPem] = await Promise.all([fs.readFile(certPath, 'utf8'), fs.readFile(keyPath, 'utf8')]);
      this.rootMaterial = {
        certPem,
        keyPem,
        privateKey: forge.pki.privateKeyFromPem(keyPem) as forge.pki.rsa.PrivateKey,
        certificate: forge.pki.certificateFromPem(certPem),
      };
      return this.rootMaterial;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }

    const keys = forge.pki.rsa.generateKeyPair({ bits: 2048, workers: -1 });
    const cert = forge.pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = serialNumber();
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = addYears(new Date(), 10);

    const attrs = [
      { name: 'commonName', value: 'ProxyForge Local Root CA' },
      { name: 'organizationName', value: 'ProxyForge Authorized Testing' },
      { name: 'countryName', value: 'US' },
    ];

    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    cert.setExtensions([
      { name: 'basicConstraints', cA: true, critical: true },
      { name: 'keyUsage', keyCertSign: true, cRLSign: true, digitalSignature: true, critical: true },
      { name: 'subjectKeyIdentifier' },
    ]);
    cert.sign(keys.privateKey, forge.md.sha256.create());

    const certPem = forge.pki.certificateToPem(cert);
    const keyPem = forge.pki.privateKeyToPem(keys.privateKey);
    await Promise.all([fs.writeFile(certPath, certPem, 'utf8'), fs.writeFile(keyPath, keyPem, { encoding: 'utf8', mode: 0o600 })]);

    this.rootMaterial = {
      certPem,
      keyPem,
      privateKey: keys.privateKey,
      certificate: cert,
    };
    return this.rootMaterial;
  }

  private async loadOrCreateHostCertificate(root: RootMaterial, host: string) {
    const hostDir = path.join(this.projectDir(), 'hosts');
    await fs.mkdir(hostDir, { recursive: true });
    const safeHost = host.replace(/[^a-z0-9.-]/gi, '_');
    const certPath = path.join(hostDir, `${safeHost}.pem`);
    const keyPath = path.join(hostDir, `${safeHost}.key.pem`);

    try {
      const [certPem, keyPem] = await Promise.all([fs.readFile(certPath, 'utf8'), fs.readFile(keyPath, 'utf8')]);
      return { certPem, keyPem };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }

    const keys = forge.pki.rsa.generateKeyPair({ bits: 2048, workers: -1 });
    const cert = forge.pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = serialNumber();
    cert.validity.notBefore = new Date(Date.now() - 60_000);
    cert.validity.notAfter = addDays(new Date(), HOST_CERT_DAYS);
    cert.setSubject([
      { name: 'commonName', value: host },
      { name: 'organizationName', value: 'ProxyForge Generated Host Certificate' },
    ]);
    cert.setIssuer(root.certificate.subject.attributes);
    cert.setExtensions([
      { name: 'basicConstraints', cA: false, critical: true },
      { name: 'keyUsage', digitalSignature: true, keyEncipherment: true, critical: true },
      { name: 'extKeyUsage', serverAuth: true },
      {
        name: 'subjectAltName',
        altNames: [subjectAltName(host)],
      },
    ]);
    cert.sign(root.privateKey, forge.md.sha256.create());

    const certPem = forge.pki.certificateToPem(cert);
    const keyPem = forge.pki.privateKeyToPem(keys.privateKey);
    await Promise.all([fs.writeFile(certPath, certPem, 'utf8'), fs.writeFile(keyPath, keyPem, { encoding: 'utf8', mode: 0o600 })]);
    return { certPem, keyPem };
  }
}

function projectSlug(label: string) {
  const slug = label.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 72);
  return slug || 'default-project';
}

async function countHostCertificates(hostDir: string) {
  try {
    const entries = await fs.readdir(hostDir);
    return entries.filter((entry) => entry.endsWith('.pem') && !entry.endsWith('.key.pem')).length;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    return 0;
  }
}

async function moveIfExists(source: string, destination: string) {
  try {
    await fs.rename(source, destination);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
}

async function removeIfExists(target: string) {
  try {
    await fs.rm(target, { recursive: true, force: true });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
}

interface RevocationMetadata {
  revokedAt?: string;
  rotatedAt?: string;
  reason?: string;
  previousFingerprintSha256?: string;
}

async function readRevocation(projectDir: string): Promise<RevocationMetadata | null> {
  try {
    return JSON.parse(await fs.readFile(path.join(projectDir, REVOCATION_FILE), 'utf8')) as RevocationMetadata;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    return null;
  }
}

async function writeRevocation(projectDir: string, metadata: RevocationMetadata) {
  await fs.mkdir(projectDir, { recursive: true });
  await fs.writeFile(path.join(projectDir, REVOCATION_FILE), JSON.stringify(metadata, null, 2), 'utf8');
}

function subjectAltName(host: string) {
  if (netIsIp(host)) {
    return { type: 7, ip: host };
  }
  return { type: 2, value: host };
}

function netIsIp(host: string) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(host) || host.includes(':');
}

function serialNumber() {
  return crypto.randomBytes(16).toString('hex');
}

function addYears(date: Date, years: number) {
  const next = new Date(date);
  next.setFullYear(next.getFullYear() + years);
  return next;
}

function addDays(date: Date, days: number) {
  return new Date(date.getTime() + days * 24 * 60 * 60 * 1000);
}

function sha256Fingerprint(pem: string) {
  const der = forge.asn1.toDer(forge.pki.certificateToAsn1(forge.pki.certificateFromPem(pem))).getBytes();
  const buffer = Buffer.from(der, 'binary');
  return crypto
    .createHash('sha256')
    .update(buffer)
    .digest('hex')
    .match(/.{1,2}/g)
    ?.join(':')
    .toUpperCase();
}
