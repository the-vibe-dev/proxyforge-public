// Project SBOM (Software Bill of Materials) generator.
// Builds SBOM ZIP from the active project snapshot in CycloneDX 1.5 and SPDX 2.3 formats.
// No external dependencies — pure Node.js.

import { randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SbomComponent {
  name: string;
  version?: string;
  type: 'library' | 'framework' | 'application' | 'container' | 'device' | 'file';
  purl?: string;
  licenses?: string[];
  description?: string;
  supplier?: string;
  hash?: { algorithm: string; value: string };
}

export interface SbomEvidenceRef {
  id: string;
  kind: 'exchange' | 'issue' | 'scan_matrix' | 'exploit_run' | 'oast_interaction' | 'report';
  description?: string;
  createdAt: string;
}

export interface SbomMetadata {
  projectId: string;
  projectName: string;
  generatedAt: string;
  toolName: string;
  toolVersion: string;
  components: SbomComponent[];
  evidenceRefs: SbomEvidenceRef[];
}

// ---------------------------------------------------------------------------
// CycloneDX 1.5 JSON
// ---------------------------------------------------------------------------

export function buildCycloneDx(metadata: SbomMetadata): object {
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${generateUuid()}`,
    version: 1,
    metadata: {
      timestamp: metadata.generatedAt,
      tools: [{ vendor: 'ProxyForge', name: metadata.toolName, version: metadata.toolVersion }],
      component: {
        type: 'application',
        name: metadata.projectName,
        version: '1.0.0',
        description: `ProxyForge security project: ${metadata.projectName}`,
      },
    },
    components: metadata.components.map((c) => ({
      type: c.type,
      name: c.name,
      version: c.version,
      description: c.description,
      purl: c.purl,
      licenses: c.licenses?.map((l) => ({ license: { id: l } })),
      hashes: c.hash ? [{ alg: c.hash.algorithm, content: c.hash.value }] : undefined,
      supplier: c.supplier ? { name: c.supplier } : undefined,
    })),
    externalReferences: metadata.evidenceRefs.map((ref) => ({
      type: 'evidence',
      url: `proxyforge://project/${metadata.projectId}/evidence/${ref.id}`,
      comment: `[${ref.kind}] ${ref.description ?? ref.id}`,
    })),
  };
}

// ---------------------------------------------------------------------------
// SPDX 2.3 tag-value
// ---------------------------------------------------------------------------

export function buildSpdxTagValue(metadata: SbomMetadata): string {
  const lines: string[] = [
    'SPDXVersion: SPDX-2.3',
    'DataLicense: CC0-1.0',
    `SPDXID: SPDXRef-DOCUMENT`,
    `DocumentName: ${metadata.projectName}`,
    `DocumentNamespace: https://proxyforge.local/sbom/${metadata.projectId}`,
    `Creator: Tool: ${metadata.toolName}-${metadata.toolVersion}`,
    `Created: ${metadata.generatedAt}`,
    '',
  ];

  for (const comp of metadata.components) {
    const safeId = comp.name.replace(/[^A-Za-z0-9.\-]/g, '-');
    lines.push(
      `PackageName: ${comp.name}`,
      `SPDXID: SPDXRef-${safeId}`,
      `PackageVersion: ${comp.version ?? 'NOASSERTION'}`,
      `FilesAnalyzed: false`,
      comp.licenses?.length
        ? `PackageLicenseConcluded: ${comp.licenses.join(' AND ')}`
        : `PackageLicenseConcluded: NOASSERTION`,
      `PackageLicenseDeclared: NOASSERTION`,
      `PackageCopyrightText: NOASSERTION`,
      '',
    );
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// SPDX 2.3 JSON
// ---------------------------------------------------------------------------

export function buildSpdxJson(metadata: SbomMetadata): object {
  return {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    documentName: metadata.projectName,
    documentNamespace: `https://proxyforge.local/sbom/${metadata.projectId}`,
    creationInfo: {
      created: metadata.generatedAt,
      creators: [`Tool: ${metadata.toolName}-${metadata.toolVersion}`],
    },
    packages: metadata.components.map((c) => ({
      SPDXID: `SPDXRef-${c.name.replace(/[^A-Za-z0-9.\-]/g, '-')}`,
      name: c.name,
      versionInfo: c.version ?? 'NOASSERTION',
      filesAnalyzed: false,
      licenseConcluded: c.licenses?.join(' AND ') ?? 'NOASSERTION',
      licenseDeclared: 'NOASSERTION',
      copyrightText: 'NOASSERTION',
      supplier: c.supplier ? `Organization: ${c.supplier}` : 'NOASSERTION',
      checksums: c.hash ? [{ algorithm: c.hash.algorithm.toUpperCase(), checksumValue: c.hash.value }] : [],
    })),
    relationships: [
      { spdxElementId: 'SPDXRef-DOCUMENT', relationshipType: 'DESCRIBES', relatedSpdxElement: 'SPDXRef-DOCUMENT' },
    ],
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function generateUuid(): string {
  const b = randomBytes(16);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  return [
    b.slice(0, 4).toString('hex'),
    b.slice(4, 6).toString('hex'),
    b.slice(6, 8).toString('hex'),
    b.slice(8, 10).toString('hex'),
    b.slice(10).toString('hex'),
  ].join('-');
}

export function createProjectSbomMetadata(
  projectId: string,
  projectName: string,
  components: SbomComponent[],
  evidenceRefs: SbomEvidenceRef[],
): SbomMetadata {
  return {
    projectId,
    projectName,
    generatedAt: new Date().toISOString(),
    toolName: 'ProxyForge',
    toolVersion: '1.0.0',
    components,
    evidenceRefs,
  };
}
