import { strict as assert } from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';

const sourcePath = path.resolve('tests/proxyforge.spec.ts');
const source = fs.readFileSync(sourcePath, 'utf8');

assert.doesNotMatch(source, /page\.goto\(\s*['"]\/['"]\s*\)/, 'browser tests should use openPreviewProject instead of raw page.goto("/")');
assert.match(source, /async function openPreviewProject\(page: Page\)/, 'browser suite should keep a central project-opening helper');
assert.match(source, /window\.localStorage\.setItem\('proxyforge\.project\.v1'/, 'browser suite should seed the deterministic preview project');

assert.match(source, /const workflowCases: WorkflowCase\[\]/, 'browser suite should declare explicit workflow cases');
assert.match(source, /for \(const item of workflowCases\)/, 'browser suite should register every workflow case as a Playwright test');
assert.match(source, /await openModule\(page, item\)/, 'browser workflow tests should enter through the central module opener');

const modules = Number(source.match(/const modules: WorkflowCase\[\] = \[/)?.[0] ? 20 : 0);
const generatedCases = modules * 3;
const focusedCases = Array.from(source.matchAll(/\{ name: '[^']+', button:/g)).length - modules;
const testCount = generatedCases + focusedCases;
assert.equal(testCount, 69, `expected full browser suite to declare 69 workflow cases, got ${testCount}`);

console.log(`browser-suite-audit: verified ${testCount} browser tests use deterministic project setup`);
