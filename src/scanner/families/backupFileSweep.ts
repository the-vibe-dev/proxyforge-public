import type { PayloadVariant } from '../types';

export const META = {
  id: 'backup-file-sweep',
  family: 'lfi-traversal' as const,
  name: 'Backup File Sweep',
  description: 'Sweeps for common backup file extensions appended to discovered paths: .bak, .old, ~, .swp, .orig.',
  defaultRisk: 'none' as const,
  insertionPointKinds: ['path'],
};

const PROBES = [
  { value: '.bak', intent: 'Append .bak to path — common backup extension for configuration and source files', signals: ['backup-file-exposed'] },
  { value: '.old', intent: 'Append .old to path — versioned backup extension', signals: ['backup-file-exposed'] },
  { value: '~', intent: 'Append tilde to path — Unix editor (Emacs/vi) backup convention', signals: ['backup-file-exposed'] },
  { value: '.swp', intent: 'Append .swp to path — vim swap file left during editing', signals: ['backup-file-exposed'] },
  { value: '.orig', intent: 'Append .orig to path — patch/diff original file backup', signals: ['backup-file-exposed'] },
  { value: '.save', intent: 'Append .save to path — editor save file backup', signals: ['backup-file-exposed'] },
  { value: '.copy', intent: 'Append .copy to path — manually created copy backup', signals: ['backup-file-exposed'] },
  { value: '.tmp', intent: 'Append .tmp to path — temporary file left during processing', signals: ['backup-file-exposed'] },
];

export function variants(): PayloadVariant[] {
  return PROBES.map((p, i) => ({
    id: `backup-sweep-${i + 1}`,
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
