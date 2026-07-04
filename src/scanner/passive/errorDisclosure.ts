// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.

export interface PassiveCheckResult {
  fired: boolean;
  evidence: string[];
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
}

const ERROR_PATTERNS: Array<{ pattern: RegExp; label: string; severity: 'info' | 'low' | 'medium' | 'high' }> = [
  // SQL errors
  { pattern: /you have an error in your sql syntax/i, label: 'MySQL syntax error', severity: 'high' },
  { pattern: /ORA-\d{5}:/m, label: 'Oracle ORA- error code', severity: 'high' },
  { pattern: /Microsoft OLE DB Provider for SQL Server/i, label: 'MSSQL OLE DB error', severity: 'high' },
  { pattern: /supplied argument is not a valid MySQL-Link resource/i, label: 'MySQL resource error', severity: 'high' },
  { pattern: /Warning:\s+mysqli?_/i, label: 'PHP MySQL warning', severity: 'high' },
  { pattern: /pg_query\(\): Query failed:/i, label: 'PostgreSQL query error', severity: 'high' },
  { pattern: /SQLite3::query\(\)/i, label: 'SQLite3 PHP error', severity: 'high' },
  { pattern: /ERROR:\s+syntax error at or near/i, label: 'PostgreSQL syntax error', severity: 'high' },
  { pattern: /Unclosed quotation mark after the character string/i, label: 'MSSQL unclosed quote', severity: 'high' },
  // Framework errors
  { pattern: /ActiveRecord::StatementInvalid/i, label: 'Rails ActiveRecord error', severity: 'medium' },
  { pattern: /SequelizeValidationError/i, label: 'Node Sequelize error', severity: 'medium' },
  { pattern: /Doctrine\\\w+Exception/i, label: 'Doctrine ORM exception', severity: 'medium' },
  { pattern: /HibernateException/i, label: 'Hibernate ORM exception', severity: 'medium' },
  { pattern: /PDOException/i, label: 'PHP PDO exception', severity: 'high' },
  { pattern: /Eloquent\\\w+Exception/i, label: 'Laravel Eloquent exception', severity: 'medium' },
  // Internal paths
  { pattern: /\/var\/www\/html\//m, label: 'Linux web root path disclosure', severity: 'low' },
  { pattern: /C:\\inetpub\\wwwroot\\/m, label: 'Windows IIS path disclosure', severity: 'low' },
  { pattern: /\/home\/\w+\/public_html\//m, label: 'Shared hosting path disclosure', severity: 'low' },
  // Generic
  { pattern: /SQLSTATE\[\w+\]/m, label: 'SQLSTATE error code (PDO/DBAL)', severity: 'high' },
  { pattern: /internal server error/i, label: 'Generic 500 internal server error text', severity: 'info' },
];

export function check(exchange: {
  url: string;
  requestRaw: string;
  responseRaw: string;
  status?: number;
  host?: string;
}): PassiveCheckResult {
  const evidence: string[] = [];
  let maxSeverity: 'info' | 'low' | 'medium' | 'high' | 'critical' = 'info';

  const bodyStart = exchange.responseRaw.indexOf('\r\n\r\n');
  const body = bodyStart !== -1 ? exchange.responseRaw.slice(bodyStart + 4) : exchange.responseRaw;

  const ORDER: PassiveCheckResult['severity'][] = ['info', 'low', 'medium', 'high', 'critical'];

  for (const { pattern, label, severity } of ERROR_PATTERNS) {
    const match = pattern.exec(body);
    if (match) {
      const excerpt = match[0].slice(0, 100).replace(/\n/g, ' ');
      evidence.push(`${label}: "${excerpt}"`);
      if (ORDER.indexOf(severity) > ORDER.indexOf(maxSeverity)) {
        maxSeverity = severity;
      }
    }
  }

  return {
    fired: evidence.length > 0,
    evidence,
    title: 'SQL / framework error message disclosure',
    severity: maxSeverity,
  };
}
