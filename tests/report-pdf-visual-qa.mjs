import { strict as assert } from 'node:assert';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { chromium } from '@playwright/test';

const {
  buildPdfRenderQaMetadata,
  evaluatePdfVisualQaSnapshot,
  renderReport,
} = await import('../dist-electron/reportEngine.js');

const generatedAt = new Date('2026-05-24T23:45:00.000Z');
const request = {
  projectName: 'PDF Visual QA Assessment',
  scopeAllowlist: ['app.visual.test'],
  format: 'pdf',
  sections: ['executive', 'technical', 'remediation', 'evidence', 'appendix'],
  brandName: 'ProxyForge',
  preparedFor: 'Visual QA Team',
  engagementId: 'PDF-QA-1',
  issues: [
    {
      id: 'issue-pdf-1',
      title: 'Authorization token appears in operational evidence',
      severity: 'high',
      host: 'app.visual.test',
      path: '/api/admin/export',
      confidence: 'firm',
      status: 'open',
      detail: 'Report rendering must redact submission evidence while preserving section pagination.',
      remediation: 'Use report-phase redaction and inspect rendered PDF output before submission.',
      assignee: 'Reporting',
      triageNote: 'Visual QA fixture for pagination and redaction.',
    },
  ],
  exchanges: [
    {
      id: 'hx-pdf-1',
      method: 'POST',
      host: 'app.visual.test',
      path: '/api/admin/export',
      url: 'https://app.visual.test/api/admin/export',
      status: 202,
      length: 2048,
      mime: 'application/json',
      risk: 'high',
      timing: 181,
      notes: 'Rendered PDF fixture evidence.',
      source: 'repeater',
      time: '23:45:00',
      requestRaw: [
        'POST /api/admin/export HTTP/2',
        'Host: app.visual.test',
        'Authorization: Bearer SECRET_PDF_TOKEN',
        'Cookie: session=SECRET_PDF_SESSION',
        'Content-Type: application/json',
        '',
        '{"api_key":"SECRET_PDF_KEY","export":"users"}',
      ].join('\n'),
      responseRaw: 'HTTP/2 202 Accepted\nContent-Type: application/json\n\n{"queued":true,"api_key":"SECRET_PDF_KEY"}',
      tags: ['pdf-qa', 'report-redaction'],
    },
  ],
};

const html = renderReport(request, generatedAt);
const metadata = readPdfRenderQaMetadata(html);
assert.deepEqual(metadata, buildPdfRenderQaMetadata(request, generatedAt));

const browser = await chromium.launch();
try {
  const page = await browser.newPage({
    viewport: { width: 794, height: 1123 },
    deviceScaleFactor: 1,
  });
  await page.emulateMedia({ media: 'print' });
  await page.setContent(html, { waitUntil: 'load' });
  await page.evaluate(() => document.fonts ? document.fonts.ready.then(() => true) : true);
  const sectionMetrics = await page.evaluate(() => Array.from(document.querySelectorAll('[data-pdf-section]')).map((element) => {
    const box = element.getBoundingClientRect();
    const styles = getComputedStyle(element);
    const section = element.getAttribute('data-pdf-section') || '';
    return {
      section,
      selector: `[data-pdf-section="${section}"]`,
      top: box.top + window.scrollY,
      height: box.height,
      width: box.width,
      computedBreakBefore: styles.breakBefore,
      computedPageBreakBefore: styles.pageBreakBefore,
      computedBreakInside: styles.breakInside || styles.pageBreakInside,
      text: element.textContent || '',
    };
  }));
  const screenshot = await captureScreenshotWithRetry(page);
  const png = decodePngRgba(screenshot);
  const snapshot = {
    generatedAt: new Date().toISOString(),
    viewport: { width: 794, height: 1123 },
    screenshot: {
      width: png.width,
      height: png.height,
      sha256: crypto.createHash('sha256').update(screenshot).digest('hex'),
      nonWhitePixelRatio: png.nonWhitePixelRatio,
      accentPixelCount: png.accentPixelCount,
    },
    sections: sectionMetrics,
  };
  const evaluation = evaluatePdfVisualQaSnapshot(metadata, snapshot);
  assert.equal(evaluation.passed, true, evaluation.failures.join('; '));
  assert(evaluation.checks.some((check) => check.startsWith('screenshot-size:')));
  assert(evaluation.checks.some((check) => check.startsWith('brand-accent-pixels:')));
  assert(evaluation.checks.includes('section-visual-order:monotonic'));
  assert(evaluation.checks.includes(`computed-page-breaks:${metadata.pageBreaks.length}/${metadata.pageBreaks.length}`));
  assert.equal(sectionMetrics.length, request.sections.length);
  assert(sectionMetrics.every((section, index) => index === 0 || section.top > sectionMetrics[index - 1].top));
  assert(!html.includes('SECRET_PDF_TOKEN'));
  assert(!html.includes('SECRET_PDF_SESSION'));
  assert(!html.includes('SECRET_PDF_KEY'));

  console.log(`report-pdf-visual-qa: verified rendered PNG pixels, ${sectionMetrics.length} computed page-break probes, and redacted PDF HTML`);
} finally {
  await browser.close();
}

function readPdfRenderQaMetadata(pdfHtml) {
  const match = pdfHtml.match(/<script type="application\/json" id="proxyforge-pdf-render-qa">([\s\S]*?)<\/script>/);
  assert(match, 'expected embedded PDF render QA metadata');
  return JSON.parse(match[1]);
}

async function captureScreenshotWithRetry(page) {
  let lastError;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      return await page.screenshot({ fullPage: true });
    } catch (error) {
      lastError = error;
      await page.waitForTimeout(150);
    }
  }
  throw lastError;
}

function decodePngRgba(buffer) {
  const signature = buffer.subarray(0, 8).toString('hex');
  assert.equal(signature, '89504e470d0a1a0a', 'expected PNG screenshot');
  let offset = 8;
  let width = 0;
  let height = 0;
  let bitDepth = 0;
  let colorType = 0;
  const idat = [];

  while (offset < buffer.length) {
    const length = buffer.readUInt32BE(offset);
    const type = buffer.subarray(offset + 4, offset + 8).toString('ascii');
    const data = buffer.subarray(offset + 8, offset + 8 + length);
    if (type === 'IHDR') {
      width = data.readUInt32BE(0);
      height = data.readUInt32BE(4);
      bitDepth = data.readUInt8(8);
      colorType = data.readUInt8(9);
    } else if (type === 'IDAT') {
      idat.push(data);
    } else if (type === 'IEND') {
      break;
    }
    offset += length + 12;
  }

  assert.equal(bitDepth, 8, 'expected 8-bit PNG screenshot');
  assert(colorType === 2 || colorType === 6, 'expected RGB or RGBA PNG screenshot');
  const inflated = zlib.inflateSync(Buffer.concat(idat));
  const bytesPerPixel = colorType === 6 ? 4 : 3;
  const stride = width * bytesPerPixel;
  const pixels = Buffer.alloc(stride * height);
  let sourceOffset = 0;
  let targetOffset = 0;
  let nonWhite = 0;
  let accentPixelCount = 0;

  for (let y = 0; y < height; y += 1) {
    const filter = inflated[sourceOffset];
    sourceOffset += 1;
    const row = inflated.subarray(sourceOffset, sourceOffset + stride);
    sourceOffset += stride;
    const previousRow = y === 0 ? undefined : pixels.subarray(targetOffset - stride, targetOffset);
    unfilterRow(row, pixels.subarray(targetOffset, targetOffset + stride), previousRow, filter, bytesPerPixel);
    for (let x = 0; x < stride; x += bytesPerPixel) {
      const r = pixels[targetOffset + x];
      const g = pixels[targetOffset + x + 1];
      const b = pixels[targetOffset + x + 2];
      const a = colorType === 6 ? pixels[targetOffset + x + 3] : 255;
      if (a > 0 && (r < 245 || g < 245 || b < 245)) nonWhite += 1;
      if (a > 0 && r >= 210 && g >= 95 && g <= 170 && b >= 20 && b <= 90) accentPixelCount += 1;
    }
    targetOffset += stride;
  }

  return {
    width,
    height,
    nonWhitePixelRatio: nonWhite / (width * height),
    accentPixelCount,
  };
}

function unfilterRow(source, target, previous, filter, bytesPerPixel) {
  for (let index = 0; index < source.length; index += 1) {
    const left = index >= bytesPerPixel ? target[index - bytesPerPixel] : 0;
    const up = previous ? previous[index] : 0;
    const upLeft = previous && index >= bytesPerPixel ? previous[index - bytesPerPixel] : 0;
    if (filter === 0) target[index] = source[index];
    else if (filter === 1) target[index] = (source[index] + left) & 0xff;
    else if (filter === 2) target[index] = (source[index] + up) & 0xff;
    else if (filter === 3) target[index] = (source[index] + Math.floor((left + up) / 2)) & 0xff;
    else if (filter === 4) target[index] = (source[index] + paeth(left, up, upLeft)) & 0xff;
    else throw new Error(`Unsupported PNG row filter ${filter}`);
  }
}

function paeth(left, up, upLeft) {
  const estimate = left + up - upLeft;
  const leftDistance = Math.abs(estimate - left);
  const upDistance = Math.abs(estimate - up);
  const upLeftDistance = Math.abs(estimate - upLeft);
  if (leftDistance <= upDistance && leftDistance <= upLeftDistance) return left;
  if (upDistance <= upLeftDistance) return up;
  return upLeft;
}
