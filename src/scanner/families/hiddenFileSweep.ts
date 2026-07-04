import type { PayloadVariant } from '../types';

export const META = {
  id: 'hidden-file-sweep',
  family: 'lfi-traversal' as const,
  name: 'Hidden File Sweep',
  description: 'Sweeps for commonly exposed hidden files: .git/HEAD, .svn, .DS_Store, web.config, and similar.',
  defaultRisk: 'none' as const,
  insertionPointKinds: ['path'],
};

const PROBES = [
  { value: '/.git/HEAD', intent: 'Probe .git/HEAD — presence confirms git repository exposure', signals: ['scm-file-exposed'] },
  { value: '/.git/config', intent: 'Probe .git/config — exposes remote URL and git configuration', signals: ['scm-file-exposed'] },
  { value: '/.svn/entries', intent: 'Probe .svn/entries — Subversion working copy file listing', signals: ['scm-file-exposed'] },
  { value: '/.DS_Store', intent: 'Probe .DS_Store — macOS metadata file reveals directory structure', signals: ['scm-file-exposed'] },
  { value: '/web.config', intent: 'Probe web.config — IIS configuration may expose connection strings and secrets', signals: ['config-file-exposed'] },
  { value: '/.env', intent: 'Probe .env file — environment variable file often contains secrets', signals: ['config-file-exposed'] },
  { value: '/.git/COMMIT_EDITMSG', intent: 'Probe .git/COMMIT_EDITMSG — confirms active git repo and reveals commit message', signals: ['scm-file-exposed'] },
  { value: '/.hg/hgrc', intent: 'Probe Mercurial .hg/hgrc — Mercurial repository config exposure', signals: ['scm-file-exposed'] },
];

export function variants(): PayloadVariant[] {
  return PROBES.map((p, i) => ({
    id: `hidden-file-${i + 1}`,
    family: 'lfi-traversal' as const,
    value: p.value,
    encoding: 'raw' as const,
    intent: p.intent,
    requiresOast: false,
    requiresBrowser: false,
    destructiveRisk: 'none' as const,
    expectedSignals: p.signals,
  }));
}
