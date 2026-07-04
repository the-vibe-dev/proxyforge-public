// Phase 12 — Tests that SBOM generation correctly includes evidence references.
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
let sbomEngine, cyclonedx, spdx;
try {
  sbomEngine = require('../dist-electron/src/sbomEngine.js');
  cyclonedx = require('../dist-electron/src/sbomFormats/cyclonedx.js');
  spdx = require('../dist-electron/src/sbomFormats/spdx.js');
} catch {
  console.log('SKIP sbom-includes-evidence-references (module not compiled)');
  process.exit(0);
}

const { createProjectSbomMetadata, buildCycloneDx, buildSpdxTagValue } = sbomEngine;
const { serializeCycloneDx } = cyclonedx;
const { serializeSpdxTagValue } = spdx;

const components = [
  { name: 'express', version: '4.18.2', type: 'library', licenses: ['MIT'] },
  { name: 'axios', version: '1.6.0', type: 'library', licenses: ['MIT'] },
];

const evidenceRefs = [
  { id: 'ex-001', kind: 'exchange', description: 'Captured POST /api/login', createdAt: new Date().toISOString() },
  { id: 'issue-007', kind: 'issue', description: 'Confirmed SSRF via OAST callback', createdAt: new Date().toISOString() },
  { id: 'oast-abc', kind: 'oast_interaction', description: 'Out-of-band DNS callback', createdAt: new Date().toISOString() },
];

const metadata = createProjectSbomMetadata('proj-evidence', 'Evidence Test', components, evidenceRefs);

// CycloneDX externalReferences includes all evidence ref IDs
const cdxObj = buildCycloneDx(metadata);
assert.ok(Array.isArray(cdxObj.externalReferences), 'externalReferences is an array');
const refUrls = cdxObj.externalReferences.map((r) => r.url);
assert.ok(refUrls.some((u) => u.includes('ex-001')), 'ex-001 appears in CycloneDX externalReferences');
assert.ok(refUrls.some((u) => u.includes('issue-007')), 'issue-007 appears in CycloneDX externalReferences');
assert.ok(refUrls.some((u) => u.includes('oast-abc')), 'oast-abc appears in CycloneDX externalReferences');
console.log('  CycloneDX externalReferences includes all evidence ref IDs: PASS');

// SPDX tag-value string mentions the project name
const tvStr = buildSpdxTagValue(metadata);
assert.ok(tvStr.includes('Evidence Test'), 'SPDX tag-value includes project name');
console.log('  SPDX tag-value mentions project name: PASS');

// Evidence refs with kind 'issue' appear in CycloneDX with correct URL format
const issueRefs = cdxObj.externalReferences.filter((r) => r.url.includes('issue-007'));
assert.ok(issueRefs.length >= 1, 'at least one issue ref in CycloneDX');
assert.ok(issueRefs[0].url.startsWith('proxyforge://project/'), 'issue ref URL has proxyforge:// scheme');
assert.ok(issueRefs[0].url.includes('/evidence/issue-007'), 'issue ref URL contains /evidence/<id>');
console.log('  Issue kind refs have correct URL format: PASS');

// Empty evidence refs produces valid SBOM (no crash)
const metaEmpty = createProjectSbomMetadata('proj-empty', 'Empty Refs Test', components, []);
let cdxEmpty;
assert.doesNotThrow(() => { cdxEmpty = buildCycloneDx(metaEmpty); }, 'buildCycloneDx with empty evidence refs does not throw');
assert.ok(Array.isArray(cdxEmpty.externalReferences), 'externalReferences is array even when empty');
assert.equal(cdxEmpty.externalReferences.length, 0, 'no external references when evidence refs empty');
let cdxJsonEmpty;
assert.doesNotThrow(() => { cdxJsonEmpty = serializeCycloneDx(metaEmpty); }, 'serializeCycloneDx with empty refs does not throw');
assert.ok(typeof cdxJsonEmpty === 'string' && cdxJsonEmpty.length > 0, 'serialized CycloneDX is non-empty string');
console.log('  Empty evidence refs: no crash, valid SBOM: PASS');

// Multiple components each appear in output
const cdxJson = serializeCycloneDx(metadata);
assert.ok(cdxJson.includes('express'), 'express component in CycloneDX JSON');
assert.ok(cdxJson.includes('axios'), 'axios component in CycloneDX JSON');
const spdxStr = serializeSpdxTagValue(metadata);
assert.ok(spdxStr.includes('PackageName: express'), 'express in SPDX tag-value');
assert.ok(spdxStr.includes('PackageName: axios'), 'axios in SPDX tag-value');
console.log('  Multiple components each appear in output: PASS');

console.log('PASS sbom-includes-evidence-references');
