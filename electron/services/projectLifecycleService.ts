import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import {
  ProjectStore,
  type ProjectStoreAuditEventInput,
  type ProjectStoreAuditEventRecord,
  type ProjectStoreBackupResult,
  type ProjectStoreManifest,
  type ProjectStoreStats,
} from '../projectStore';

export interface ProjectLifecycleServiceOptions {
  projectsRootDir: string;
  backupsRootDir: string;
  defaultProjectName?: string;
}

export interface ProjectLifecycleCreateRequest {
  projectName?: string;
  projectId?: string;
  rootDir?: string;
  operator?: string;
  allowExternalRoot?: boolean;
}

export interface ProjectLifecycleOpenRequest {
  rootDir: string;
  operator?: string;
  recover?: boolean;
  allowExternalRoot?: boolean;
}

export interface ProjectLifecycleCloseRequest {
  operator?: string;
}

export interface ProjectLifecycleBackupRequest {
  backupRootDir?: string;
  label?: string;
  operator?: string;
  allowExternalRoot?: boolean;
}

export interface ProjectLifecycleProject {
  projectId: string;
  projectName: string;
  rootDir: string;
  snapshotPath: string;
  manifest: ProjectStoreManifest;
  stats: ProjectStoreStats;
  auditEvents: ProjectStoreAuditEventRecord[];
}

export interface ProjectLifecycleRecentProject {
  projectId: string;
  projectName: string;
  rootDir: string;
  openedAt: string;
}

export interface ProjectLifecycleState {
  kind: 'proxyforge-project-lifecycle-state';
  status: 'open' | 'closed';
  projectsRootDir: string;
  backupsRootDir: string;
  activeProject?: ProjectLifecycleProject;
  recentProjects: ProjectLifecycleRecentProject[];
  requirements: {
    typedIpcContract: boolean;
    projectStoreBackbone: boolean;
    activeProjectRebindsRecorders: boolean;
    lifecycleAuditLedger: boolean;
    pathTraversalRejected: boolean;
    rawOperationalSecretsPreserved: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
}

export interface ProjectLifecycleBackupResponse {
  kind: 'proxyforge-project-lifecycle-backup-response';
  backup: ProjectStoreBackupResult;
  state: ProjectLifecycleState;
}

export interface ActiveProjectReference {
  projectId: string;
  projectName: string;
  rootDir: string;
  snapshotPath: string;
}

interface ProjectPathResolution {
  rootDir: string;
  external: boolean;
}

const DEFAULT_PROJECT_NAME = 'Default ProxyForge Project';
const PROJECT_ID_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/;
const RECENT_PROJECTS_FILE = 'recent-projects.json';
const SECURE_DIR_MODE = 0o700;
const SECURE_FILE_MODE = 0o600;

export class ProjectLifecycleService {
  readonly projectsRootDir: string;
  readonly backupsRootDir: string;
  private readonly defaultProjectName: string;
  private activeStore: ProjectStore | null = null;

  constructor(options: ProjectLifecycleServiceOptions) {
    this.projectsRootDir = path.resolve(options.projectsRootDir);
    this.backupsRootDir = path.resolve(options.backupsRootDir);
    this.defaultProjectName = normalizeProjectName(options.defaultProjectName || DEFAULT_PROJECT_NAME);
  }

  activeProjectReference(): ActiveProjectReference | null {
    if (!this.activeStore) return null;
    return {
      projectId: this.activeStore.manifest.projectId,
      projectName: this.activeStore.manifest.projectName,
      rootDir: this.activeStore.rootDir,
      snapshotPath: projectSnapshotPath(this.activeStore.rootDir),
    };
  }

  async status(): Promise<ProjectLifecycleState> {
    return this.buildState();
  }

  async createProject(request: ProjectLifecycleCreateRequest = {}): Promise<ProjectLifecycleState> {
    const projectName = normalizeProjectName(request.projectName || this.defaultProjectName);
    const projectId = normalizeProjectId(request.projectId || slugifyProjectId(projectName));
    const resolution = resolveProjectCreateRoot({
      projectsRootDir: this.projectsRootDir,
      projectName,
      rootDir: request.rootDir,
      allowExternalRoot: request.allowExternalRoot === true,
    });
    await enforceProjectRootContainment(this.projectsRootDir, resolution.rootDir, {
      allowExternalRoot: request.allowExternalRoot === true,
      createParentDirectories: true,
      allowMissingLeaf: true,
    });
    await ensureProjectDoesNotExist(resolution.rootDir);
    const store = await ProjectStore.create(resolution.rootDir, { projectName, projectId });
    await enforceProjectRootContainment(this.projectsRootDir, resolution.rootDir, {
      allowExternalRoot: request.allowExternalRoot === true,
      createParentDirectories: false,
      allowMissingLeaf: false,
    });
    await store.addAuditEvent({
      actor: request.operator,
      action: 'project.create',
      targetRef: resolution.rootDir,
      decision: 'completed',
      detail: `Created project ${projectName}${resolution.external ? ' outside default project root with explicit capability' : ''}.`,
    });
    await this.switchActiveStore(store);
    await this.rememberActiveProject();
    return this.buildState();
  }

  async openProject(request: ProjectLifecycleOpenRequest): Promise<ProjectLifecycleState> {
    const resolution = resolveProjectOpenRoot({
      projectsRootDir: this.projectsRootDir,
      rootDir: request.rootDir,
      allowExternalRoot: request.allowExternalRoot === true,
    });
    await enforceProjectRootContainment(this.projectsRootDir, resolution.rootDir, {
      allowExternalRoot: request.allowExternalRoot === true,
      createParentDirectories: false,
      allowMissingLeaf: false,
    });
    const store = await ProjectStore.open(resolution.rootDir, { recover: request.recover !== false });
    await store.addAuditEvent({
      actor: request.operator,
      action: 'project.open',
      targetRef: resolution.rootDir,
      decision: 'completed',
      detail: `Opened project ${store.manifest.projectName}${resolution.external ? ' outside default project root with explicit capability' : ''}.`,
    });
    await this.switchActiveStore(store);
    await this.rememberActiveProject();
    return this.buildState();
  }

  async closeProject(request: ProjectLifecycleCloseRequest = {}): Promise<ProjectLifecycleState> {
    if (!this.activeStore) return this.buildState();
    await this.activeStore.addAuditEvent({
      actor: request.operator,
      action: 'project.close',
      targetRef: this.activeStore.rootDir,
      decision: 'completed',
      detail: `Closed project ${this.activeStore.manifest.projectName}.`,
    });
    this.activeStore.close();
    this.activeStore = null;
    return this.buildState();
  }

  async backupProject(request: ProjectLifecycleBackupRequest = {}): Promise<ProjectLifecycleBackupResponse> {
    const store = this.requireActiveStore();
    const backupRootDir = resolveBackupRoot({
      backupsRootDir: this.backupsRootDir,
      backupRootDir: request.backupRootDir,
      allowExternalRoot: request.allowExternalRoot === true,
    });
    await enforceProjectRootContainment(this.backupsRootDir, backupRootDir, {
      allowExternalRoot: request.allowExternalRoot === true,
      createParentDirectories: true,
      allowMissingLeaf: false,
    });
    const backup = await store.createBackup(backupRootDir, {
      label: request.label || store.manifest.projectName,
    });
    await store.addAuditEvent({
      actor: request.operator,
      action: 'project.backup',
      targetRef: backup.backupDir,
      decision: 'completed',
      detail: `Created restore point for ${store.manifest.projectName}.`,
    });
    return {
      kind: 'proxyforge-project-lifecycle-backup-response',
      backup,
      state: await this.buildState(),
    };
  }

  async recordAuditEvent(input: ProjectStoreAuditEventInput): Promise<void> {
    if (!this.activeStore) return;
    await this.activeStore.addAuditEvent(input);
  }

  async dispose() {
    if (!this.activeStore) return;
    this.activeStore.close();
    this.activeStore = null;
  }

  private async switchActiveStore(nextStore: ProjectStore) {
    const previous = this.activeStore;
    this.activeStore = nextStore;
    if (previous && previous !== nextStore) previous.close();
  }

  private requireActiveStore() {
    if (!this.activeStore) throw new Error('Open or create a project before using Project Store lifecycle actions.');
    return this.activeStore;
  }

  private async buildState(): Promise<ProjectLifecycleState> {
    return {
      kind: 'proxyforge-project-lifecycle-state',
      status: this.activeStore ? 'open' : 'closed',
      projectsRootDir: this.projectsRootDir,
      backupsRootDir: this.backupsRootDir,
      activeProject: this.activeStore ? buildProjectState(this.activeStore) : undefined,
      recentProjects: await this.readRecentProjects(),
      requirements: {
        typedIpcContract: true,
        projectStoreBackbone: true,
        activeProjectRebindsRecorders: true,
        lifecycleAuditLedger: true,
        pathTraversalRejected: true,
        rawOperationalSecretsPreserved: true,
        reportPhaseOnlyRedaction: true,
      },
    };
  }

  private async rememberActiveProject() {
    if (!this.activeStore) return;
    const next: ProjectLifecycleRecentProject = {
      projectId: this.activeStore.manifest.projectId,
      projectName: this.activeStore.manifest.projectName,
      rootDir: this.activeStore.rootDir,
      openedAt: new Date().toISOString(),
    };
    const existing = await this.readRecentProjects();
    const deduped = [
      next,
      ...existing.filter((project) => path.resolve(project.rootDir) !== path.resolve(next.rootDir)),
    ].slice(0, 20);
    await fs.mkdir(this.projectsRootDir, { recursive: true, mode: SECURE_DIR_MODE });
    await chmodIfPossible(this.projectsRootDir, SECURE_DIR_MODE);
    await fs.writeFile(path.join(this.projectsRootDir, RECENT_PROJECTS_FILE), JSON.stringify(deduped, null, 2), { encoding: 'utf8', mode: SECURE_FILE_MODE });
    await chmodIfPossible(path.join(this.projectsRootDir, RECENT_PROJECTS_FILE), SECURE_FILE_MODE);
  }

  private async readRecentProjects(): Promise<ProjectLifecycleRecentProject[]> {
    try {
      const raw = await fs.readFile(path.join(this.projectsRootDir, RECENT_PROJECTS_FILE), 'utf8');
      const parsed = JSON.parse(raw) as unknown;
      if (!Array.isArray(parsed)) return [];
      return parsed
        .map(normalizeRecentProject)
        .filter((project): project is ProjectLifecycleRecentProject => project !== null)
        .slice(0, 20);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
      throw error;
    }
  }
}

export function projectSnapshotPath(projectRootDir: string) {
  return path.join(projectRootDir, 'snapshot.proxyforge.json');
}

export function resolveProjectCreateRoot(options: {
  projectsRootDir: string;
  projectName: string;
  rootDir?: string;
  allowExternalRoot?: boolean;
}): ProjectPathResolution {
  const fallback = `${slugifyProjectId(options.projectName)}.proxyforge`;
  return resolveProjectRoot({
    projectsRootDir: options.projectsRootDir,
    rootDir: options.rootDir || fallback,
    allowExternalRoot: options.allowExternalRoot === true,
    allowBackup: false,
  });
}

export function resolveProjectOpenRoot(options: {
  projectsRootDir: string;
  rootDir: string;
  allowExternalRoot?: boolean;
}): ProjectPathResolution {
  return resolveProjectRoot({
    projectsRootDir: options.projectsRootDir,
    rootDir: options.rootDir,
    allowExternalRoot: options.allowExternalRoot === true,
    allowBackup: true,
  });
}

function buildProjectState(store: ProjectStore): ProjectLifecycleProject {
  return {
    projectId: store.manifest.projectId,
    projectName: store.manifest.projectName,
    rootDir: store.rootDir,
    snapshotPath: projectSnapshotPath(store.rootDir),
    manifest: store.exportManifest(),
    stats: store.stats(),
    auditEvents: store.listAuditEvents(50),
  };
}

function resolveProjectRoot(options: {
  projectsRootDir: string;
  rootDir: string;
  allowExternalRoot: boolean;
  allowBackup: boolean;
}): ProjectPathResolution {
  const raw = normalizePathInput(options.rootDir, 'Project root');
  if (hasTraversalSegment(raw)) throw new Error('Project root must not contain path traversal segments.');
  const projectsRootDir = path.resolve(options.projectsRootDir);
  const rootDir = path.resolve(path.isAbsolute(raw) ? raw : path.join(projectsRootDir, raw));
  const basename = path.basename(rootDir);
  const allowedSuffix = options.allowBackup
    ? basename.endsWith('.proxyforge') || basename.endsWith('.proxyforge-backup')
    : basename.endsWith('.proxyforge');
  if (!allowedSuffix) throw new Error('Project root must end with .proxyforge.');
  if (rootDir === path.parse(rootDir).root) throw new Error('Project root must not be the filesystem root.');
  const external = !isInsideOrEqual(projectsRootDir, rootDir);
  if (external && !options.allowExternalRoot) {
    throw new Error('External project roots require the explicit allowExternalRoot capability.');
  }
  return { rootDir, external };
}

function resolveBackupRoot(options: {
  backupsRootDir: string;
  backupRootDir?: string;
  allowExternalRoot: boolean;
}) {
  const backupsRootDir = path.resolve(options.backupsRootDir);
  if (!options.backupRootDir?.trim()) return backupsRootDir;
  const raw = normalizePathInput(options.backupRootDir, 'Backup root');
  if (hasTraversalSegment(raw)) throw new Error('Backup root must not contain path traversal segments.');
  const resolved = path.resolve(path.isAbsolute(raw) ? raw : path.join(backupsRootDir, raw));
  const external = !isInsideOrEqual(backupsRootDir, resolved);
  if (external && !options.allowExternalRoot) {
    throw new Error('External backup roots require the explicit allowExternalRoot capability.');
  }
  return resolved;
}

async function ensureProjectDoesNotExist(rootDir: string) {
  await rejectSymlink(rootDir, 'Project root');
  const existing = await Promise.all([
    pathExists(path.join(rootDir, 'manifest.json')),
    pathExists(path.join(rootDir, 'project.db')),
  ]);
  if (existing.some(Boolean)) throw new Error(`Project already exists at ${rootDir}. Open it instead of creating over it.`);
}

async function enforceProjectRootContainment(
  trustedRootDir: string,
  targetRootDir: string,
  options: { allowExternalRoot: boolean; createParentDirectories: boolean; allowMissingLeaf: boolean },
) {
  const trustedRoot = path.resolve(trustedRootDir);
  const targetRoot = path.resolve(targetRootDir);
  await fs.mkdir(trustedRoot, { recursive: true, mode: SECURE_DIR_MODE });
  await chmodIfPossible(trustedRoot, SECURE_DIR_MODE);

  if (options.allowExternalRoot) {
    if (options.createParentDirectories && !options.allowMissingLeaf) {
      await fs.mkdir(targetRoot, { recursive: true, mode: SECURE_DIR_MODE });
      await chmodIfPossible(targetRoot, SECURE_DIR_MODE);
    }
    await rejectSymlink(targetRoot, 'Project root');
    if (!options.allowMissingLeaf) await ensureCanonicalDirectory(targetRoot, 'Project root');
    return;
  }

  if (!isInsideOrEqual(trustedRoot, targetRoot)) {
    throw new Error('Project root escaped the allowed projects directory.');
  }

  const parentDir = path.dirname(targetRoot);
  if (options.createParentDirectories && !options.allowMissingLeaf) {
    await ensureContainedDirectoryPath(trustedRoot, targetRoot, true);
  } else {
    await ensureContainedDirectoryPath(trustedRoot, parentDir, options.createParentDirectories);
  }
  await rejectSymlink(targetRoot, 'Project root');
  if (!options.allowMissingLeaf) await ensureCanonicalDirectory(targetRoot, 'Project root');

  const trustedReal = await fs.realpath(trustedRoot);
  const existingReal = await fs.realpath(options.allowMissingLeaf ? parentDir : targetRoot);
  if (!isInsideOrEqual(trustedReal, existingReal)) {
    throw new Error('Project root escaped the allowed projects directory through a filesystem alias.');
  }
}

async function ensureContainedDirectoryPath(trustedRoot: string, targetDir: string, createMissing: boolean) {
  const relative = path.relative(trustedRoot, targetDir);
  if (relative === '') return;
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new Error('Project root escaped the allowed projects directory.');
  }
  let current = trustedRoot;
  for (const segment of relative.split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    let stat;
    try {
      stat = await fs.lstat(current);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT' || !createMissing) throw error;
      await fs.mkdir(current, { mode: SECURE_DIR_MODE });
      await chmodIfPossible(current, SECURE_DIR_MODE);
      stat = await fs.lstat(current);
    }
    if (stat.isSymbolicLink()) throw new Error(`Project root must not traverse symlink or junction component: ${current}`);
    if (!stat.isDirectory()) throw new Error(`Project root component is not a directory: ${current}`);
  }
}

async function ensureCanonicalDirectory(dirPath: string, label: string) {
  const stat = await fs.lstat(dirPath);
  if (stat.isSymbolicLink()) throw new Error(`${label} must not be a symlink or junction.`);
  if (!stat.isDirectory()) throw new Error(`${label} must be a directory.`);
  await chmodIfPossible(dirPath, SECURE_DIR_MODE);
}

async function rejectSymlink(filePath: string, label: string) {
  try {
    const stat = await fs.lstat(filePath);
    if (stat.isSymbolicLink()) throw new Error(`${label} must not be a symlink or junction.`);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
}

async function chmodIfPossible(filePath: string, mode: number) {
  if (process.platform === 'win32') return;
  try {
    await fs.chmod(filePath, mode);
  } catch (error) {
    if (!['ENOENT', 'EPERM', 'EACCES'].includes((error as NodeJS.ErrnoException).code ?? '')) throw error;
  }
}

async function pathExists(filePath: string) {
  try {
    await fs.access(filePath);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false;
    throw error;
  }
}

function normalizePathInput(value: string, label: string) {
  const normalized = value.trim();
  if (!normalized) throw new Error(`${label} is required.`);
  if (normalized.includes('\0')) throw new Error(`${label} must not contain null bytes.`);
  return normalized;
}

function normalizeProjectName(value: string) {
  const normalized = value.trim().replace(/\s+/g, ' ');
  if (!normalized) throw new Error('Project name is required.');
  if (normalized.length > 160) throw new Error('Project name must be 160 characters or fewer.');
  return normalized;
}

function normalizeProjectId(value: string) {
  const normalized = value.trim();
  if (!PROJECT_ID_PATTERN.test(normalized)) {
    throw new Error('Project id must start with a letter or number and contain only letters, numbers, dots, underscores, or dashes.');
  }
  return normalized;
}

function normalizeRecentProject(value: unknown): ProjectLifecycleRecentProject | null {
  if (!value || typeof value !== 'object') return null;
  const candidate = value as Partial<ProjectLifecycleRecentProject>;
  if (typeof candidate.projectId !== 'string' || typeof candidate.projectName !== 'string' || typeof candidate.rootDir !== 'string') return null;
  return {
    projectId: candidate.projectId,
    projectName: candidate.projectName,
    rootDir: path.resolve(candidate.rootDir),
    openedAt: typeof candidate.openedAt === 'string' ? candidate.openedAt : new Date(0).toISOString(),
  };
}

function hasTraversalSegment(value: string) {
  return value.split(/[\\/]+/).some((segment) => segment === '..');
}

function isInsideOrEqual(parent: string, child: string) {
  const relative = path.relative(path.resolve(parent), path.resolve(child));
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

function slugifyProjectId(value: string) {
  const slug = value.toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '');
  return slug || `project-${createHash('sha256').update(value).digest('hex').slice(0, 12)}`;
}
