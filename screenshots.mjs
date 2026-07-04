import { chromium } from 'playwright';
import path from 'node:path';
import fs from 'node:fs/promises';

const OUT = '/tmp/proxy-forge-screens';
await fs.mkdir(OUT, { recursive: true });

const browser = await chromium.launch({ headless: true });
const ctx = await browser.newContext({ viewport: { width: 1920, height: 1080 }, deviceScaleFactor: 1 });
const page = await ctx.newPage();
page.on('console', m => console.log(`[browser ${m.type()}]`, m.text().slice(0, 200)));

await page.goto('http://localhost:5173/', { waitUntil: 'networkidle' });
await page.waitForTimeout(1500);

try {
  await page.click('button:has-text("Skip setup")', { timeout: 3000 });
  await page.waitForTimeout(500);
} catch (e) {}

const tabs = [['scanner', 'Scanner'], ['repeater', 'Repeater'], ['settings', 'Settings']];

for (const [id, label] of tabs) {
  try {
    await page.click(`button[aria-label="${label}"]`, { timeout: 3000 });
    await page.waitForTimeout(800);
    await page.screenshot({ path: path.join(OUT, `full-${id}.png`), fullPage: false });
    await page.screenshot({ path: path.join(OUT, `full-${id}-page.png`), fullPage: true });
    console.log(`shot ${id}`);
  } catch (e) { console.log(`FAILED ${id}: ${e.message.slice(0, 80)}`); }
}

await browser.close();
console.log('done');
