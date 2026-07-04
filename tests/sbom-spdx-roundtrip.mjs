// Phase 12 — Tests for SPDX 2.3 format serialization (sbomFormats/spdx.ts)
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
let sbomEngine, spdx;
try {
  sbomEngine = require('../dist-electron/src/sbomEngine.js');
  spdx = require('../dist-electron/src/sbomFormats/spdx.js');
} catch {
  console.log('SKIP sbom-spdx-roundtrip (module not compiled)');
  process.exit(0);
}

const { createProjectSbomMetadata, buildSpdxTagValue, buildSpdxJson } = sbomEngine;
const { serializeSpdxTagValue, serializeSpdxJson, validateSpdxJsonShape } = spdx;

const components = [
  { name: 'lodash', version: '4.17.21', type: 'library', licenses: ['MIT'] },
];
const evidenceRefs = [];

const metadata = createProjectSbomMetadata(
  'proj-test',
  'SPDX Test',
  components,
  evidenceRefs,
);

// buildSpdxTagValue includes required header fields
const tvStr = buildSpdxTagValue(metadata);
assert.ok(tvStr.includes('SPDXVersion: SPDX-2.3'), 'tag-value has SPDXVersion: SPDX-2.3');
assert.ok(tvStr.includes('DataLicense: CC0-1.0'), 'tag-value has DataLicense: CC0-1.0');
assert.ok(tvStr.includes('PackageName: lodash'), 'tag-value has package name');
console.log('  buildSpdxTagValue header fields: PASS');

// serializeSpdxTagValue returns the same string
const tvStr2 = serializeSpdxTagValue(metadata);
assert.equal(tvStr2, tvStr, 'serializeSpdxTagValue returns identical string to buildSpdxTagValue');
console.log('  serializeSpdxTagValue identity: PASS');

// buildSpdxJson has correct shape
const spdxObj = buildSpdxJson(metadata);
assert.ok(String(spdxObj.spdxVersion).startsWith('SPDX-'), 'spdxVersion starts with SPDX-');
assert.equal(spdxObj.dataLicense, 'CC0-1.0', 'dataLicense is CC0-1.0');
assert.ok(Array.isArray(spdxObj.packages), 'packages is an array');
assert.equal(spdxObj.packages.length, 1, '1 package in SPDX JSON');
console.log('  buildSpdxJson structure: PASS');

// serializeSpdxJson round-trips through JSON.parse
const jsonStr = serializeSpdxJson(metadata);
const reparsed = JSON.parse(jsonStr);
assert.ok(validateSpdxJsonShape(reparsed).valid, 'serializeSpdxJson round-trip produces valid SPDX JSON');
console.log('  serializeSpdxJson round-trip: PASS');

// validateSpdxJsonShape({}) returns valid: false with errors
const badResult = validateSpdxJsonShape({});
assert.equal(badResult.valid, false, 'empty object is not valid SPDX JSON');
assert.ok(Array.isArray(badResult.errors) && badResult.errors.length > 0, 'errors array is non-empty for invalid shape');
console.log('  validateSpdxJsonShape({}) returns invalid: PASS');

// Package with no version gets NOASSERTION
const noVersionComponents = [
  { name: 'unversioned-lib', type: 'library', licenses: ['Apache-2.0'] },
];
const metaNoVersion = createProjectSbomMetadata('proj-nover', 'NoVersion Test', noVersionComponents, []);
const tvNoVer = buildSpdxTagValue(metaNoVersion);
assert.ok(tvNoVer.includes('PackageVersion: NOASSERTION'), 'missing version → NOASSERTION in tag-value');
const spdxNoVer = buildSpdxJson(metaNoVersion);
assert.equal(spdxNoVer.packages[0].versionInfo, 'NOASSERTION', 'missing version → NOASSERTION in JSON');
console.log('  NOASSERTION for missing version: PASS');

console.log('PASS sbom-spdx-roundtrip');
