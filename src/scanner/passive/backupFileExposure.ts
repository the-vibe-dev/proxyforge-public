// Passive rule: Backup/temp file extensions (.bak, .old, .tmp, ~, .orig) returning 200
export interface PassiveCheckResult {
  checkId: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'tentative' | 'firm' | 'certain';
  detail: string;
  evidence?: string;
}

const BACKUP_EXT = /\.(?:bak|old|tmp|orig|save|swp|backup|copy)(?:\?|$)|~[^/]+$|\.php\.|\.asp\./i;

export function check(_requestRaw: string, responseRaw: string, url?: string): PassiveCheckResult | null {
  if (!url) return null;

  const statusMatch = /HTTP\/\S+\s+(\d+)/.exec(responseRaw);
  const status = statusMatch ? parseInt(statusMatch[1], 10) : 0;
  if (status < 200 || status >= 300) return null;

  if (!BACKUP_EXT.test(url)) return null;

  return {
    checkId: 'backup-file-exposure',
    title: 'Backup or temporary file accessible',
    severity: 'medium',
    confidence: 'firm',
    detail: 'Backup files often contain source code, configuration, or credentials that should not be publicly accessible.',
    evidence: `Backup-extension file returned ${status}: ${url}`,
  };
}
