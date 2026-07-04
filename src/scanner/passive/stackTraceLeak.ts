// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.

export interface PassiveCheckResult {
  fired: boolean;
  evidence: string[];
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
}

const STACK_TRACE_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  // Java
  { pattern: /at\s+[\w.$]+\([\w$.]+\.java:\d+\)/m, label: 'Java stack trace' },
  { pattern: /java\.lang\.\w+Exception:/m, label: 'Java exception class' },
  { pattern: /Caused by:\s+\w/m, label: 'Java "Caused by:" chain' },
  // Python
  { pattern: /Traceback\s+\(most recent call last\)/m, label: 'Python traceback header' },
  { pattern: /File\s+"[^"]+",\s+line\s+\d+/m, label: 'Python file/line trace' },
  // .NET
  { pattern: /System\.\w+Exception\s*:/m, label: '.NET System exception' },
  { pattern: /at\s+[\w.]+\+<\w+>d__\d+/m, label: '.NET async iterator trace' },
  { pattern: /\[external code\]/m, label: '.NET [external code] stack frame' },
  // Node.js
  { pattern: /Error:\s+.*\n\s+at\s+.+:\d+:\d+/m, label: 'Node.js Error stack' },
  // PHP
  { pattern: /Stack trace:\n#\d+\s/m, label: 'PHP stack trace' },
  { pattern: /Fatal error:\s+Uncaught/m, label: 'PHP fatal error' },
  // Ruby
  { pattern: /\(RuntimeError\)\n\s+from /m, label: 'Ruby RuntimeError trace' },
  { pattern: /app\/\w+\/.*\.rb:\d+:in /m, label: 'Ruby source line trace' },
  // Go
  { pattern: /goroutine \d+ \[running\]/m, label: 'Go goroutine dump' },
  { pattern: /panic:\s+/m, label: 'Go panic' },
];

export function check(exchange: {
  url: string;
  requestRaw: string;
  responseRaw: string;
  status?: number;
  host?: string;
}): PassiveCheckResult {
  const evidence: string[] = [];

  // Extract body from raw response
  const bodyStart = exchange.responseRaw.indexOf('\r\n\r\n');
  const body = bodyStart !== -1 ? exchange.responseRaw.slice(bodyStart + 4) : exchange.responseRaw;

  for (const { pattern, label } of STACK_TRACE_PATTERNS) {
    const match = pattern.exec(body);
    if (match) {
      const excerpt = match[0].slice(0, 120).replace(/\n/g, ' ');
      evidence.push(`${label} detected in response body: "${excerpt}..."`);
    }
  }

  // Check for file path disclosure within stack traces
  if (evidence.length > 0) {
    const pathMatch = /\/[a-zA-Z0-9_./-]{10,}\.(?:java|py|rb|cs|php|go|js|ts)/.exec(body);
    if (pathMatch) {
      evidence.push(`File path disclosed in stack trace: "${pathMatch[0]}"`);
    }
  }

  return {
    fired: evidence.length > 0,
    evidence,
    title: 'Stack trace / exception disclosure in response body',
    severity: 'medium',
  };
}
