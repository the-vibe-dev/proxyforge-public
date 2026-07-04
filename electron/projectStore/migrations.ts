// Schema migration registry — Phase 2-12 tables.
// Each migration carries a unique id, monotone version, description, and SQLite DDL.

export interface Migration {
  id: string;
  version: number;
  description: string;
  up: string;
}

export const MIGRATIONS: Migration[] = [
  {
    id: 'scanner_check_packs',
    version: 1,
    description: 'Scanner check packs registry',
    up: `CREATE TABLE IF NOT EXISTS scanner_check_packs (
  id TEXT PRIMARY KEY NOT NULL,
  name TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  checksJson TEXT NOT NULL DEFAULT '[]',
  createdAt TEXT NOT NULL
);`,
  },
  {
    id: 'scanner_probe_runs',
    version: 2,
    description: 'Scanner probe run records',
    up: `CREATE TABLE IF NOT EXISTS scanner_probe_runs (
  id TEXT PRIMARY KEY NOT NULL,
  projectId TEXT NOT NULL,
  checkId TEXT NOT NULL,
  status TEXT NOT NULL,
  exchangeId TEXT,
  startedAt TEXT NOT NULL,
  completedAt TEXT
);`,
  },
  {
    id: 'scanner_probe_variants',
    version: 3,
    description: 'Scanner probe variant payloads',
    up: `CREATE TABLE IF NOT EXISTS scanner_probe_variants (
  id TEXT PRIMARY KEY NOT NULL,
  runId TEXT NOT NULL,
  variantId TEXT NOT NULL,
  family TEXT NOT NULL,
  encoding TEXT NOT NULL,
  payload TEXT NOT NULL,
  destructiveRisk INTEGER NOT NULL DEFAULT 0
);`,
  },
  {
    id: 'scanner_probe_observations',
    version: 4,
    description: 'Scanner probe response observations',
    up: `CREATE TABLE IF NOT EXISTS scanner_probe_observations (
  id TEXT PRIMARY KEY NOT NULL,
  runId TEXT NOT NULL,
  variantId TEXT NOT NULL,
  responseClass TEXT NOT NULL,
  confidence REAL NOT NULL DEFAULT 0,
  evidence TEXT NOT NULL DEFAULT '',
  timestamp TEXT NOT NULL
);`,
  },
  {
    id: 'scanner_evidence_matrices',
    version: 5,
    description: 'Scanner evidence matrix snapshots',
    up: `CREATE TABLE IF NOT EXISTS scanner_evidence_matrices (
  id TEXT PRIMARY KEY NOT NULL,
  projectId TEXT NOT NULL,
  matrixJson TEXT NOT NULL DEFAULT '{}',
  createdAt TEXT NOT NULL,
  updatedAt TEXT NOT NULL
);`,
  },
  {
    id: 'scanner_negative_evidence',
    version: 6,
    description: 'Scanner negative evidence records',
    up: `CREATE TABLE IF NOT EXISTS scanner_negative_evidence (
  id TEXT PRIMARY KEY NOT NULL,
  projectId TEXT NOT NULL,
  checkId TEXT NOT NULL,
  insertionPointId TEXT NOT NULL,
  reason TEXT NOT NULL,
  timestamp TEXT NOT NULL
);`,
  },
  {
    id: 'skilllet_metadata',
    version: 7,
    description: 'Skilllet check metadata',
    up: `CREATE TABLE IF NOT EXISTS skilllet_metadata (
  id TEXT PRIMARY KEY NOT NULL,
  checkId TEXT NOT NULL,
  family TEXT NOT NULL,
  summaryJson TEXT NOT NULL DEFAULT '{}',
  createdAt TEXT NOT NULL
);`,
  },
  {
    id: 'playbook_recipes',
    version: 8,
    description: 'Playbook recipe definitions',
    up: `CREATE TABLE IF NOT EXISTS playbook_recipes (
  id TEXT PRIMARY KEY NOT NULL,
  name TEXT NOT NULL,
  stepsJson TEXT NOT NULL DEFAULT '[]',
  evidenceGatesJson TEXT NOT NULL DEFAULT '[]',
  createdAt TEXT NOT NULL
);`,
  },
  {
    id: 'playbook_runs',
    version: 9,
    description: 'Playbook execution run records',
    up: `CREATE TABLE IF NOT EXISTS playbook_runs (
  id TEXT PRIMARY KEY NOT NULL,
  recipeId TEXT NOT NULL,
  status TEXT NOT NULL,
  currentStep TEXT,
  startedAt TEXT NOT NULL,
  completedAt TEXT
);`,
  },
  {
    id: 'playbook_steps',
    version: 10,
    description: 'Playbook run step execution records',
    up: `CREATE TABLE IF NOT EXISTS playbook_steps (
  id TEXT PRIMARY KEY NOT NULL,
  runId TEXT NOT NULL,
  stepId TEXT NOT NULL,
  status TEXT NOT NULL,
  timestamp TEXT NOT NULL
);`,
  },
  {
    id: 'playbook_evidence_gates',
    version: 11,
    description: 'Playbook run evidence gate evaluations',
    up: `CREATE TABLE IF NOT EXISTS playbook_evidence_gates (
  id TEXT PRIMARY KEY NOT NULL,
  runId TEXT NOT NULL,
  gateId TEXT NOT NULL,
  passed INTEGER NOT NULL DEFAULT 0,
  reason TEXT NOT NULL DEFAULT '',
  timestamp TEXT NOT NULL
);`,
  },
  {
    id: 'exploit_template_runs',
    version: 12,
    description: 'Exploit template execution records',
    up: `CREATE TABLE IF NOT EXISTS exploit_template_runs (
  id TEXT PRIMARY KEY NOT NULL,
  projectId TEXT NOT NULL,
  templateId TEXT NOT NULL,
  inputJson TEXT NOT NULL DEFAULT '{}',
  resultJson TEXT NOT NULL DEFAULT '{}',
  createdAt TEXT NOT NULL
);`,
  },
  {
    id: 'traffic_rule_packs',
    version: 13,
    description: 'Traffic rule pack registry',
    up: `CREATE TABLE IF NOT EXISTS traffic_rule_packs (
  id TEXT PRIMARY KEY NOT NULL,
  name TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  rulesJson TEXT NOT NULL DEFAULT '[]',
  createdAt TEXT NOT NULL
);`,
  },
  {
    id: 'traffic_rule_events',
    version: 14,
    description: 'Traffic rule match events',
    up: `CREATE TABLE IF NOT EXISTS traffic_rule_events (
  id TEXT PRIMARY KEY NOT NULL,
  ruleId TEXT NOT NULL,
  exchangeId TEXT NOT NULL,
  action TEXT NOT NULL,
  annotationJson TEXT NOT NULL DEFAULT '{}',
  timestamp TEXT NOT NULL
);`,
  },
  {
    id: 'flow_filter_presets',
    version: 15,
    description: 'Flow filter expression presets',
    up: `CREATE TABLE IF NOT EXISTS flow_filter_presets (
  id TEXT PRIMARY KEY NOT NULL,
  name TEXT NOT NULL,
  expression TEXT NOT NULL,
  createdAt TEXT NOT NULL
);`,
  },
  {
    id: 'har_exports',
    version: 16,
    description: 'HAR export records',
    up: `CREATE TABLE IF NOT EXISTS har_exports (
  id TEXT PRIMARY KEY NOT NULL,
  projectId TEXT NOT NULL,
  filename TEXT NOT NULL,
  entryCount INTEGER NOT NULL DEFAULT 0,
  createdAt TEXT NOT NULL
);`,
  },
  {
    id: 'cut_exports',
    version: 17,
    description: 'CUT (custom unit test) export records',
    up: `CREATE TABLE IF NOT EXISTS cut_exports (
  id TEXT PRIMARY KEY NOT NULL,
  projectId TEXT NOT NULL,
  specsJson TEXT NOT NULL DEFAULT '[]',
  resultJson TEXT NOT NULL DEFAULT '{}',
  createdAt TEXT NOT NULL
);`,
  },
  {
    id: 'content_view_preferences',
    version: 18,
    description: 'Content view display preferences',
    up: `CREATE TABLE IF NOT EXISTS content_view_preferences (
  id TEXT PRIMARY KEY NOT NULL,
  viewId TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  priority INTEGER NOT NULL DEFAULT 0
);`,
  },
  {
    id: 'playback_sessions',
    version: 19,
    description: 'Playback session records',
    up: `CREATE TABLE IF NOT EXISTS playback_sessions (
  id TEXT PRIMARY KEY NOT NULL,
  name TEXT NOT NULL,
  mode TEXT NOT NULL,
  exchangesJson TEXT NOT NULL DEFAULT '[]',
  createdAt TEXT NOT NULL
);`,
  },
  {
    id: 'proxy_mode_configs',
    version: 20,
    description: 'Proxy mode configuration records',
    up: `CREATE TABLE IF NOT EXISTS proxy_mode_configs (
  id TEXT PRIMARY KEY NOT NULL,
  mode TEXT NOT NULL,
  configJson TEXT NOT NULL DEFAULT '{}',
  createdAt TEXT NOT NULL
);`,
  },
  {
    id: 'dns_record_rules',
    version: 21,
    description: 'DNS record rewrite rules',
    up: `CREATE TABLE IF NOT EXISTS dns_record_rules (
  id TEXT PRIMARY KEY NOT NULL,
  pattern TEXT NOT NULL,
  action TEXT NOT NULL,
  ip TEXT,
  enabled INTEGER NOT NULL DEFAULT 1
);`,
  },
  {
    id: 'http2_streams',
    version: 22,
    description: 'HTTP/2 stream frame records',
    up: `CREATE TABLE IF NOT EXISTS http2_streams (
  id TEXT PRIMARY KEY NOT NULL,
  projectId TEXT NOT NULL,
  exchangeId TEXT NOT NULL,
  streamId INTEGER NOT NULL,
  framesJson TEXT NOT NULL DEFAULT '[]',
  createdAt TEXT NOT NULL
);`,
  },
  {
    id: 'streaming_spool_refs',
    version: 23,
    description: 'Streaming body spool file references',
    up: `CREATE TABLE IF NOT EXISTS streaming_spool_refs (
  id TEXT PRIMARY KEY NOT NULL,
  exchangeId TEXT NOT NULL,
  spoolPath TEXT NOT NULL,
  size INTEGER NOT NULL DEFAULT 0,
  capped INTEGER NOT NULL DEFAULT 0,
  mimeType TEXT NOT NULL DEFAULT '',
  createdAt TEXT NOT NULL
);`,
  },
];

/** Returns a migration by its table id, or null if not found. */
export function getMigration(id: string): Migration | null {
  return MIGRATIONS.find((m) => m.id === id) ?? null;
}

/** Returns the migration with the highest version number. */
export function getLatestMigration(): Migration {
  return MIGRATIONS.reduce((latest, m) => (m.version > latest.version ? m : latest));
}

/** Returns all migrations with version <= the given version, sorted ascending. */
export function getMigrationsUpTo(version: number): Migration[] {
  return MIGRATIONS.filter((m) => m.version <= version).sort((a, b) => a.version - b.version);
}
