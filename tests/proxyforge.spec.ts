import { expect, test, type Locator, type Page } from '@playwright/test';
import { seedExchanges } from '../src/data';

type WorkflowCase = {
  name: string;
  button: string;
  heading: RegExp;
  texts?: RegExp[];
  buttons?: RegExp[];
};

const modules: WorkflowCase[] = [
  { name: 'dashboard', button: 'Dashboard', heading: /Imported Retail Audit/, texts: [/Live capture on 127\.0\.0\.1:8080/, /Findings by severity/i] },
  { name: 'target map', button: 'Target Map', heading: /Target Map/, texts: [/Site map/i, /content discovery/i] },
  { name: 'proxy', button: 'Proxy', heading: /Proxy/, texts: [/HTTP history/i, /Intercept/i, /Match & replace/i] },
  { name: 'logger', button: 'Logger', heading: /Logger/, texts: [/All tool-generated HTTP traffic/i] },
  { name: 'callbacks', button: 'Callbacks', heading: /Callbacks/, texts: [/OAST/i, /payload ownership/i] },
  { name: 'repeater', button: 'Repeater', heading: /Repeater/, texts: [/New request/i, /Send/i] },
  { name: 'intruder', button: 'Intruder', heading: /Intruder/, texts: [/Sniper/i, /Pitchfork/i] },
  { name: 'scanner', button: 'Scanner', heading: /Scanner/, texts: [/Passive \+ active checks/i, /audit queue/i] },
  { name: 'exploit lab', button: 'Exploit Lab', heading: /Exploit Lab/, texts: [/approval-gated/i, /OAST-correlated/i] },
  { name: 'organizer', button: 'Organizer', heading: /Organizer/, texts: [/Collections/i, /reviewer/i] },
  { name: 'sequencer', button: 'Sequencer', heading: /Sequencer/, texts: [/entropy/i, /token/i] },
  { name: 'decoder', button: 'Decoder', heading: /Decoder/, texts: [/Transforms/i, /smart decode/i] },
  { name: 'comparer', button: 'Comparer', heading: /Comparer/, texts: [/Word \+ byte diff/i, /structured HTTP/i] },
  { name: 'automations', button: 'Automations', heading: /Automations/, texts: [/Macros/i, /scheduled workflows/i] },
  { name: 'extensions', button: 'Extensions', heading: /Extensions/, texts: [/Sandboxed runtime/i, /signed manifests/i] },
  { name: 'ai agent', button: 'AI / Agent', heading: /AI \/ Agent/, texts: [/Codex/i, /proxyforge-agent/i] },
  { name: 'reports', button: 'Reports', heading: /Reports/, texts: [/Application security assessment/i, /Imported Retail Audit/i] },
  { name: 'search', button: 'Search', heading: /Search/, texts: [/matches across/i, /Search/i] },
  { name: 'viewer', button: 'Viewer', heading: /Viewer/, texts: [/raw/i, /pretty/i, /hex/i] },
  { name: 'settings', button: 'Settings', heading: /Settings/, texts: [/Project/i, /scope/i, /certificates/i] },
];

const workflowCases: WorkflowCase[] = [
  ...modules.map((item) => ({
    ...item,
    name: `${item.name} opens with current semantic heading`,
  })),
  ...modules.map((item) => ({
    ...item,
    name: `${item.name} preserves project chrome and global search`,
    texts: [/ProxyForge/, /Imported Retail Audit/, /listener . 127\.0\.0\.1:8080/i],
  })),
  ...modules.map((item) => ({
    ...item,
    name: `${item.name} exposes maturity or status metadata`,
    texts: [/ALPHA|COMING SOON|STABLE|Production Ready/i],
  })),
  { name: 'proxy exposes current capture workflow controls', button: 'Proxy', heading: /Proxy/, texts: [/5 captured/i, /HTTP history/i], buttons: [/Export/i, /Resume|Pause/i] },
  { name: 'target map exposes crawler and inventory panels', button: 'Target Map', heading: /Target Map/, texts: [/Site map/i, /app\.shop\.local/i, /Tech/i] },
  { name: 'logger exposes filterable traffic entries', button: 'Logger', heading: /Logger/, texts: [/app\.shop\.local/i, /api\/refunds/i] },
  { name: 'repeater exposes request editor and response panes', button: 'Repeater', heading: /Repeater/, texts: [/Request/i, /Response/i], buttons: [/New request/i] },
  { name: 'scanner exposes check packs and findings', button: 'Scanner', heading: /Scanner/, texts: [/Active checks/i, /Findings/i] },
  { name: 'reports expose package-ready report surface', button: 'Reports', heading: /Reports/, texts: [/report packages/i, /Imported Retail Audit/i] },
  { name: 'settings exposes project safety controls', button: 'Settings', heading: /Settings/, texts: [/Project . scope . policy/i, /Tool capture/i] },
  { name: 'search exposes seeded exchange corpus', button: 'Search', heading: /Search/, texts: [/0 matches across 5 exchanges/i, /app\.shop\.local/i] },
  { name: 'viewer exposes selected exchange render modes', button: 'Viewer', heading: /Viewer/, texts: [/Selected exchange/i, /Raw/i, /Pretty/i, /Hex/i] },
];

test.beforeEach(async ({ page }) => {
  await page.addInitScript((exchanges) => {
    window.localStorage.setItem('proxyforge.project.v1', JSON.stringify({
      version: 1,
      savedAt: new Date().toISOString(),
      projectName: 'Imported Retail Audit',
      scopeAllowlist: ['app.shop.local', 'api.shop.local', '*.shop.local'],
      exchanges,
    }));
  }, seedExchanges);
});

function railButton(page: Page, name: string): Locator {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return page.getByRole('navigation').getByRole('button', { name: new RegExp(`^${escaped}(?:\\s+\\d+)?$`) });
}

async function openPreviewProject(page: Page) {
  const appHomePath = '/';
  await page.goto(appHomePath);
  const welcome = page.getByText('Welcome to ProxyForge');
  if (await welcome.isVisible({ timeout: 8_000 }).catch(() => false)) {
    const continueButton = page.getByRole('button', { name: /^Continue / });
    if (await continueButton.isVisible({ timeout: 8_000 }).catch(() => false)) {
      await continueButton.click();
    } else {
      await page.getByRole('button', { name: 'Skip setup' }).click();
    }
    await expect(welcome).toBeHidden();
  }
}

async function openModule(page: Page, item: WorkflowCase) {
  await openPreviewProject(page);
  await railButton(page, item.button).click();
  await expect(page.getByRole('heading', { name: item.heading })).toBeVisible();
}

async function expectVisibleText(page: Page, pattern: RegExp) {
  await expect(page.getByText(pattern).first()).toBeVisible();
}

for (const item of workflowCases) {
  test(item.name, async ({ page }) => {
    await openModule(page, item);
    await expect(page).toHaveTitle('ProxyForge');
    await expect(page.getByRole('textbox', { name: /Search hosts/i })).toBeVisible();
    for (const pattern of item.texts ?? []) {
      await expectVisibleText(page, pattern);
    }
    for (const pattern of item.buttons ?? []) {
      await expect(page.getByRole('button', { name: pattern }).first()).toBeVisible();
    }
  });
}
