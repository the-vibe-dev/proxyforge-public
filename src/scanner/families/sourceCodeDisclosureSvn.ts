import type { PayloadVariant } from '../types';

export const META = {
  id: 'source-code-disclosure-svn',
  family: 'lfi-traversal' as const,
  name: 'Source Code Disclosure via Subversion',
  description: 'Detects exposed Subversion (.svn) working copy files that allow source code reconstruction.',
  defaultRisk: 'none' as const,
  insertionPointKinds: ['path'],
};

const PROBES = [
  { value: '/.svn/wc.db', intent: 'Probe .svn/wc.db — SQLite database containing full working copy file tree', signals: ['scm-file-exposed'] },
  { value: '/.svn/entries', intent: 'Probe .svn/entries — older SVN format file listing directory contents', signals: ['scm-file-exposed'] },
  { value: '/.svn/all-wcprops', intent: 'Probe .svn/all-wcprops — SVN working copy properties file', signals: ['scm-file-exposed'] },
  { value: '/.svn/pristine/', intent: 'Probe .svn/pristine/ directory — stores original file content for diffs', signals: ['scm-file-exposed'] },
  { value: '/.svn/format', intent: 'Probe .svn/format — single-line file revealing SVN working copy format version', signals: ['scm-file-exposed'] },
  { value: '/.svn/tmp/', intent: 'Probe .svn/tmp/ directory — temporary SVN files may contain sensitive data', signals: ['scm-file-exposed'] },
  { value: '/admin/.svn/wc.db', intent: 'Probe .svn/wc.db in /admin/ — confirms admin directory source exposure', signals: ['scm-file-exposed'] },
  { value: '/.svn/README.txt', intent: 'Probe .svn/README.txt — metadata file confirming SVN directory is accessible', signals: ['scm-file-exposed'] },
];

export function variants(): PayloadVariant[] {
  return PROBES.map((p, i) => ({
    id: `svn-disclosure-${i + 1}`,
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
