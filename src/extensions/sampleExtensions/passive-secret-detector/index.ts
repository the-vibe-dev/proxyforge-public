// Sample extension: passive secret detector
// Scans response bodies for secret-like patterns (API keys, tokens, passwords)

import type { ProxyForgeExtension, ScannerPassivePayload, ScannerPassiveResult } from '../../sdk';

const SECRET_PATTERNS: Array<{ label: string; re: RegExp }> = [
  { label: 'API Key', re: /(?:api[_-]?key|apikey)\s*[:=]\s*["']?([A-Za-z0-9_\-]{20,})/i },
  {
    label: 'Access Token',
    re: /(?:access[_-]?token|accesstoken)\s*[:=]\s*["']?([A-Za-z0-9_\-]{20,})/i,
  },
  { label: 'Password', re: /(?:password|passwd|pwd)\s*[:=]\s*["']?(\S{8,})/i },
  { label: 'Private Key', re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
  {
    label: 'AWS Secret Access Key',
    re: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*([A-Za-z0-9\/+]{40})/i,
  },
  { label: 'GitHub Personal Access Token', re: /ghp_[A-Za-z0-9]{36}/ },
  { label: 'OpenAI API Key', re: /sk-[A-Za-z0-9]{48}/ },
];

export const extension: ProxyForgeExtension = {
  manifest: {
    id: 'passive-secret-detector',
    name: 'Passive Secret Detector',
    version: '1.0.0',
    description:
      'Passively scans HTTP response bodies for leaked secrets such as API keys, tokens, and private key material.',
    author: 'ProxyForge',
    license: 'MIT',
    hooks: ['scanner_passive'],
    permissions: ['read:history', 'write:issues'],
  },

  async onScannerPassive(payload: ScannerPassivePayload): Promise<ScannerPassiveResult | void> {
    const issues: ScannerPassiveResult['issues'] = [];
    const text = payload.responseRaw;

    for (const { label, re } of SECRET_PATTERNS) {
      if (re.test(text)) {
        issues.push({
          title: `Potential secret exposed in response: ${label}`,
          severity: 'high',
          detail: `The response for exchange ${payload.exchangeId} appears to contain a ${label}. ` +
            `Review the response body to confirm and rotate any exposed credentials immediately.`,
        });
      }
    }

    if (issues.length === 0) return;
    return { issues };
  },
};
