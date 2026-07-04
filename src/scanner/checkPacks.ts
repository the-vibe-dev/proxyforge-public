// Named check packs: curated subsets of check IDs for common scan scenarios.

export interface CheckPack {
  id: string;
  name: string;
  description: string;
  checks: string[];
}

export const CHECK_PACKS: CheckPack[] = [
  {
    id: 'pf-core',
    name: 'ProxyForge Core',
    description: 'Essential injection, XSS, traversal, redirect, and SSRF checks.',
    checks: [
      'sql-injection',
      'xss-reflected',
      'ssti',
      'lfi-traversal',
      'command-injection',
      'ssrf',
      'open-redirect',
      'nosql-injection',
      'xxe-file',
    ],
  },
  {
    id: 'pf-auth',
    name: 'ProxyForge Auth',
    description: 'Authentication and session security checks.',
    checks: [
      'jwt-none-algorithm',
      'jwt-weak-secret',
      'session-fixation',
      'csrf-heuristic',
      'clickjacking',
      'host-header-injection',
      'crlf-header-injection',
    ],
  },
  {
    id: 'pf-oast',
    name: 'ProxyForge OAST',
    description: 'Out-of-band checks requiring a callback listener.',
    checks: [
      'ssrf-oast',
      'xxe-oast',
      'command-injection-blind-oast',
      'log4-shell',
    ],
  },
  {
    id: 'pf-cve',
    name: 'ProxyForge CVE Sweep',
    description: 'Named CVE and well-known vulnerability families.',
    checks: [
      'shell-shock',
      'log4-shell',
      'spring4-shell',
      'env-file-exposure',
      'source-code-disclosure-git',
    ],
  },
  {
    id: 'pf-full',
    name: 'ProxyForge Full',
    description: 'All available active checks (throttled, non-destructive).',
    checks: [
      'sql-injection', 'xss-reflected', 'xss-oracle', 'ssti',
      'lfi-traversal', 'command-injection', 'ssrf', 'ssrf-oast',
      'open-redirect', 'xxe-file', 'xxe-oast', 'nosql-injection',
      'xpath-injection', 'ldap-injection', 'expression-language-injection',
      'csv-formula-injection', 'jwt-none-algorithm', 'jwt-weak-secret',
      'session-fixation', 'csrf-heuristic', 'clickjacking',
      'host-header-injection', 'crlf-header-injection',
      'shell-shock', 'log4-shell', 'spring4-shell',
      'env-file-exposure', 'source-code-disclosure-git',
    ],
  },
];

export function getCheckPack(id: string): CheckPack | undefined {
  return CHECK_PACKS.find((pack) => pack.id === id);
}

export function getDefaultCheckPack(): CheckPack {
  return CHECK_PACKS.find((pack) => pack.id === 'pf-core') ?? CHECK_PACKS[0];
}
