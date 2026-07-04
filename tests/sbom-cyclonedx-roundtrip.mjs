// Phase 12 — Tests for sbomEngine.ts + sbomFormats/cyclonedx.ts + sbomFormats/spdx.ts
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
let sbomEngine, cyclonedx, spdx;
try {
  sbomEngine = require('../dist-electron/src/sbomEngine.js');
  cyclonedx = require('../dist-electron/src/sbomFormats/cyclonedx.js');
  spdx = require('../dist-electron/src/sbomFormats/spdx.js');
} catch {
  console.log('SKIP sbom-cyclonedx-roundtrip (module not compiled)');
  process.exit(0);
}

const { createProjectSbomMetadata, buildCycloneDx, buildSpdxJson, buildSpdxTagValue } = sbomEngine;
const { serializeCycloneDx, validateCycloneDxShape } = cyclonedx;
const { serializeSpdxJson, serializeSpdxTagValue, validateSpdxJsonShape } = spdx;

const components = [
  { name: 'express', version: '4.18.2', type: 'library', licenses: ['MIT'], purl: 'pkg:npm/express@4.18.2' },
  { name: 'node', version: '20.0.0', type: 'framework', licenses: ['MIT'] },
];
const evidenceRefs = [
  { id: 'ex-001', kind: 'exchange', description: 'Captured POST /api/login', createdAt: new Date().toISOString() },
  { id: 'issue-001', kind: 'issue', description: 'SQLi finding', createdAt: new Date().toISOString() },
];

const metadata = createProjectSbomMetadata('proj-123', 'Test Engagement', components, evidenceRefs);
assert.equal(metadata.projectId, 'proj-123', 'projectId set');
assert.equal(metadata.projectName, 'Test Engagement', 'projectName set');
assert.equal(metadata.components.length, 2, '2 components');
assert.equal(metadata.evidenceRefs.length, 2, '2 evidence refs');
console.log('  createProjectSbomMetadata: PASS');

// CycloneDX shape validation
const cdxObj = buildCycloneDx(metadata);
const cdxResult = validateCycloneDxShape(cdxObj);
assert.ok(cdxResult.valid, `CycloneDX shape valid (errors: ${cdxResult.errors.join(', ')})`);
assert.equal(cdxObj.bomFormat, 'CycloneDX', 'bomFormat');
assert.equal(cdxObj.specVersion, '1.5', 'specVersion');
assert.ok(cdxObj.serialNumber.startsWith('urn:uuid:'), 'serialNumber is URN');
assert.equal(cdxObj.components.length, 2, '2 components in CycloneDX');
console.log('  CycloneDX structure: PASS');

// CycloneDX serialize + parse round-trip
const cdxJson = serializeCycloneDx(metadata);
const cdxReparsed = JSON.parse(cdxJson);
assert.ok(validateCycloneDxShape(cdxReparsed).valid, 'CycloneDX JSON round-trip valid');
console.log('  CycloneDX serialize round-trip: PASS');

// SPDX JSON shape validation
const spdxObj = buildSpdxJson(metadata);
const spdxResult = validateSpdxJsonShape(spdxObj);
assert.ok(spdxResult.valid, `SPDX JSON shape valid (errors: ${spdxResult.errors.join(', ')})`);
assert.ok(String(spdxObj.spdxVersion).startsWith('SPDX-'), 'spdxVersion');
assert.equal(spdxObj.dataLicense, 'CC0-1.0', 'dataLicense');
assert.equal(spdxObj.packages.length, 2, '2 packages in SPDX');
console.log('  SPDX JSON structure: PASS');

// SPDX JSON serialize round-trip
const spdxJsonStr = serializeSpdxJson(metadata);
const spdxReparsed = JSON.parse(spdxJsonStr);
assert.ok(validateSpdxJsonShape(spdxReparsed).valid, 'SPDX JSON round-trip valid');
console.log('  SPDX JSON serialize round-trip: PASS');

// SPDX tag-value format
const tvStr = buildSpdxTagValue(metadata);
assert.ok(tvStr.includes('SPDXVersion: SPDX-2.3'), 'tag-value has SPDXVersion');
assert.ok(tvStr.includes('DataLicense: CC0-1.0'), 'tag-value has DataLicense');
assert.ok(tvStr.includes('PackageName: express'), 'tag-value has express package');
console.log('  SPDX tag-value format: PASS');

// Evidence refs appear in CycloneDX external references
assert.ok(cdxObj.externalReferences.some((r) => r.url.includes('ex-001')), 'exchange ref in CycloneDX');
assert.ok(cdxObj.externalReferences.some((r) => r.url.includes('issue-001')), 'issue ref in CycloneDX');
console.log('  Evidence refs in CycloneDX: PASS');

console.log('PASS sbom-cyclonedx-roundtrip');
