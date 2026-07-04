import type { PayloadVariant } from '../types';

export const META = {
  id: 'htaccess-exposure',
  family: 'lfi-traversal' as const,
  name: '.htaccess File Exposure',
  description: 'Detects directly accessible Apache .htaccess, .htpasswd, and related configuration files.',
  defaultRisk: 'none' as const,
  insertionPointKinds: ['path'],
};

const PROBES = [
  { value: '/.htaccess', intent: 'Probe root .htaccess — exposes Apache rewrite rules and security config', signals: ['config-file-exposed'] },
  { value: '/.htpasswd', intent: 'Probe .htpasswd — exposes HTTP basic auth credentials in hashed form', signals: ['config-file-exposed'] },
  { value: '/.htaccess.bak', intent: 'Probe .htaccess backup — leftover backup files often lack access restrictions', signals: ['config-file-exposed', 'backup-file-exposed'] },
  { value: '/.htaccess.swp', intent: 'Probe .htaccess vim swap file — editor temporary file reveals config', signals: ['config-file-exposed', 'backup-file-exposed'] },
  { value: '/.htaccess~', intent: 'Probe .htaccess tilde backup — common editor backup naming convention', signals: ['config-file-exposed', 'backup-file-exposed'] },
  { value: '/.htpasswd.bak', intent: 'Probe .htpasswd backup — backup credentials file', signals: ['config-file-exposed', 'backup-file-exposed'] },
  { value: '/admin/.htaccess', intent: 'Probe .htaccess in /admin/ — may reveal admin directory protection rules', signals: ['config-file-exposed'] },
  { value: '/.htgroups', intent: 'Probe .htgroups file — Apache group authorization file exposure', signals: ['config-file-exposed'] },
];

export function variants(): PayloadVariant[] {
  return PROBES.map((p, i) => ({
    id: `htaccess-${i + 1}`,
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
