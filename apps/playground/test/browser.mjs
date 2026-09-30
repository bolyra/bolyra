/**
 * Browser gate: serves the COMMITTED page from localhost under the production
 * CSP (test/fixtures/csp.txt), stubs only the approved external static
 * resources, records every request and fails on any unexpected one, drives
 * both views in Chromium, downloads the exported JSONL + signer document, and
 * writes PLAYGROUND_RUN_DIR for test:cli to consume.
 *
 *   node test/browser.mjs            (PLAYGROUND_RUN_DIR defaults to .playground-run/<timestamp>)
 */
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const APP = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ROOT = path.resolve(APP, '../..');
const HTML_PATH = path.join(ROOT, 'landing/playground.html');
const html = fs.readFileSync(HTML_PATH);
const htmlSha256 = crypto.createHash('sha256').update(html).digest('hex');
const CSP = fs.readFileSync(path.join(APP, 'test/fixtures/csp.txt'), 'utf8').trim();
const RUN_DIR = path.resolve(process.env.PLAYGROUND_RUN_DIR ?? path.join(APP, '.playground-run', new Date().toISOString().replace(/[:.]/g, '-')));
fs.mkdirSync(RUN_DIR, { recursive: true });

const failures = [];
const check = (cond, msg) => { if (!cond) failures.push(msg); return cond; };
const requests = [];
let phase = 'load';

// --- local server for the committed page --------------------------------
const server = http.createServer((req, res) => {
  const url = req.url.split('?')[0];
  if (url === '/playground' || url === '/playground.html') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'content-security-policy': CSP, 'cache-control': 'no-store' });
    res.end(html);
  } else { res.writeHead(404); res.end('not found'); }
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const origin = `http://127.0.0.1:${server.address().port}`;

const browser = await chromium.launch();
const STUBS = [
  [/^https:\/\/fonts\.googleapis\.com\//, { contentType: 'text/css', body: '/* stub: no @font-face, so no gstatic fetch */' }],
  [/^https:\/\/fonts\.gstatic\.com\//, { contentType: 'font/woff2', body: '' }],
  [/^https:\/\/plausible\.io\/js\/script\.js$/, { contentType: 'application/javascript', body: '/* stub */' }],
];

async function newPage(context) {
  const page = await context.newPage();
  const consoleErrors = [];
  page.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(m.text()); });
  page.on('pageerror', (e) => consoleErrors.push(`pageerror: ${e.message}`));
  page.consoleErrors = consoleErrors;
  return page;
}

async function newContext(opts = {}) {
  const context = await browser.newContext({ acceptDownloads: true, ...opts });
  await context.route('**/*', (route) => {
    const url = route.request().url();
    requests.push({ phase, url });
    if (url.startsWith(origin + '/playground')) return route.continue();
    const stub = STUBS.find(([re]) => re.test(url));
    if (stub && phase === 'load') return route.fulfill({ status: 200, contentType: stub[1].contentType, body: stub[1].body });
    failures.push(`unexpected request during ${phase}: ${url}`);
    return route.abort();
  });
  return context;
}

const resultsSel = '[data-results]';
async function verifyAndRead(page) {
  await page.click('[data-action=verify]');
  await page.waitForSelector(resultsSel);
  return page.getAttribute(resultsSel, 'data-overall');
}

// --- desktop run ----------------------------------------------------------
{
  const context = await newContext({ viewport: { width: 1280, height: 900 } });
  const page = await newPage(context);
  await page.goto(`${origin}/playground`, { waitUntil: 'load' });
  await page.waitForSelector('[data-view=verify]');
  phase = 'interact';

  const caps = await page.evaluate(() => ({ subtle: !!(crypto && crypto.subtle), grv: typeof crypto.getRandomValues === 'function', pg: typeof BolyraPlayground === 'object' }));
  check(caps.subtle && caps.grv, 'crypto.subtle / getRandomValues available'); check(caps.pg, 'BolyraPlayground global present');
  check((await page.$$('[role=tab]')).length === 2, 'two tabs rendered');

  // sample chain → ok, matched
  await page.click('[data-sample=chain]');
  check(await verifyAndRead(page) === 'ok', 'chain sample verifies ok');
  check((await page.$$('[data-row]')).length === 3, 'chain sample shows 3 rows');
  check(await page.getAttribute('[data-checkpoint]', 'data-checkpoint') === 'matched', 'chain sample checkpoint matched');
  check((await page.textContent('[data-row="0"] [data-cell=signer]')).includes('matched'), 'row 0 signer matched');

  // editing input clears results
  await page.type('[data-field=input]', ' ');
  check(await page.$(resultsSel) === null, 'editing input clears results');

  // each option change clears results
  for (const [field, action] of [['expectedSigner', (l) => l.fill('0x' + '11'.repeat(20))], ['expectedCount', (l) => l.fill('9')], ['expectedHeadHash', (l) => l.fill('0x' + '22'.repeat(32))], ['allowUnchained', (l) => l.check()]]) {
    await page.click('[data-sample=chain]');
    await verifyAndRead(page);
    await action(page.locator(`[data-field=${field}]`));
    check(await page.$(resultsSel) === null, `changing ${field} clears results`);
  }

  // a manually supplied signer survives editing the text; sample-sourced count/head are cleared
  await page.click('[data-sample=chain]');
  await page.fill('[data-field=expectedSigner]', '0x' + '33'.repeat(20));
  await page.type('[data-field=input]', ' ');
  check(await page.inputValue('[data-field=expectedSigner]') === '0x' + '33'.repeat(20), 'manual expected signer preserved after editing sample text');
  check(await page.inputValue('[data-field=expectedCount]') === '' && await page.inputValue('[data-field=expectedHeadHash]') === '', 'sample-sourced count/head cleared after editing text');
  check(await verifyAndRead(page) === 'failed', 'edited sample with manual wrong signer fails');

  // forged instance ref → signature valid, instance ref_mismatch, overall failed
  await page.click('[data-sample=forgedRef]');
  check(await verifyAndRead(page) === 'failed', 'forged-ref sample fails overall');
  check((await page.textContent('[data-row="0"] [data-cell=signature]')).includes('valid'), 'forged-ref signature valid');
  check((await page.textContent('[data-row="0"] [data-cell=instance]')).includes('ref_mismatch'), 'forged-ref instance ref_mismatch');
  await page.click('[data-sample=noInstance]');
  check(await verifyAndRead(page) === 'ok', 'no-instance sample verifies ok');
  check((await page.textContent('[data-row="0"] [data-cell=instance]')).includes('absent'), 'no-instance shows absent');
  check(await page.getAttribute('[data-checkpoint]', 'data-checkpoint') === 'not-applicable', 'single unchained → checkpoint not-applicable');

  // malformed paste → invalid
  await page.fill('[data-field=input]', 'not json at all');
  check(await verifyAndRead(page) === 'invalid', 'malformed paste → invalid');

  // simulate view: presets, export, reset
  await page.click('[data-tab=simulate]');
  await page.waitForSelector('[data-view=simulate]');
  await page.click('[data-preset=over-limit]');
  await page.waitForSelector('[data-run="1"]');
  await page.click('[data-preset=repeat]');
  await page.waitForSelector('[data-run="6"]');
  const outcomes = await page.$$eval('[data-run]', (els) => els.map((e) => e.getAttribute('data-outcome')));
  check(JSON.stringify(outcomes) === JSON.stringify(['allow', 'deny', 'allow', 'allow', 'allow', 'allow', 'allow']), `preset outcomes: ${outcomes.join(',')}`);
  const strip = await page.textContent('[data-chain-strip]');
  check(strip.includes('Chain 1') && strip.includes('seq 0..6'), `chain strip before reset: ${strip}`);
  // the session survives a tab switch: only Reset destroys it
  await page.click('[data-tab=verify]');
  await page.waitForSelector('[data-view=verify]');
  await page.click('[data-tab=simulate]');
  await page.waitForSelector('[data-view=simulate]');
  const stripAfterSwitch = await page.textContent('[data-chain-strip]');
  check(stripAfterSwitch === strip, `session preserved across tab switch (before: ${strip} / after: ${stripAfterSwitch})`);
  check((await page.$$('[data-run]')).length === 7, 'runs preserved across tab switch');
  const exportText = await page.textContent('.export');
  const expectedCount = Number((exportText.match(/--expect-count (\d+)/) || [])[1]);
  const expectedHead = (exportText.match(/--expect-head (0x[0-9a-f]{64})/) || [])[1];
  const signer = (exportText.match(/--signer (0x[0-9a-f]{40})/) || [])[1];
  check(expectedCount === 7 && !!expectedHead && !!signer, 'export paragraph carries signer, count and head');

  const saved = {};
  for (const [name, file] of [['receipts.jsonl', 'receipts.jsonl'], ['signer.json', 'signer.json']]) {
    const [download] = await Promise.all([page.waitForEvent('download'), page.click(`[data-download="${name}"]`)]);
    const target = path.join(RUN_DIR, file);
    await download.saveAs(target);
    saved[name] = target;
    check(fs.statSync(target).size > 0, `${name} downloaded with bytes`);
  }
  const lines = fs.readFileSync(saved['receipts.jsonl'], 'utf8').split('\n').filter(Boolean);
  check(lines.length === 7, `downloaded JSONL has 7 lines (got ${lines.length})`);
  const signerDoc = JSON.parse(fs.readFileSync(saved['signer.json'], 'utf8'));
  check(signerDoc.signer === signer && signerDoc.ephemeral === true, 'signer document matches the page');

  await page.click('[data-action=reset]');
  await page.waitForFunction(() => document.querySelector('[data-chain-strip]').textContent.includes('Chain 2'));
  check((await page.$$('[data-run]')).length === 0, 'reset clears runs');

  check(page.consoleErrors.length === 0, `console errors: ${page.consoleErrors.join(' | ')}`);
  fs.writeFileSync(path.join(RUN_DIR, 'manifest.json'), JSON.stringify({ htmlSha256, htmlPath: HTML_PATH, expectedCount, expectedHead, signer, files: { receipts: 'receipts.jsonl', signer: 'signer.json' } }, null, 2) + '\n');
  await context.close();
}

// --- mobile run -----------------------------------------------------------
{
  phase = 'load';
  const context = await newContext({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
  const page = await newPage(context);
  await page.goto(`${origin}/playground`, { waitUntil: 'load' });
  await page.waitForSelector('[data-view=verify]');
  phase = 'interact-mobile';
  const noHScroll = await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1);
  check(noHScroll, 'mobile: no horizontal page scroll');
  await page.click('[data-sample=chain]');
  check(await verifyAndRead(page) === 'ok', 'mobile: chain sample verifies');
  await page.click('[data-tab=simulate]');
  await page.waitForSelector('[data-view=simulate]');
  await page.click('[data-action=run]');
  await page.waitForSelector('[data-run="0"]');
  check(await page.getAttribute('[data-run="0"]', 'data-outcome') === 'allow', 'mobile: run works');
  check(page.consoleErrors.length === 0, `mobile console errors: ${page.consoleErrors.join(' | ')}`);
  await context.close();
}

await browser.close();
server.close();

const interactive = requests.filter((r) => r.phase !== 'load');
check(interactive.length === 0, `requests during interaction: ${interactive.map((r) => r.url).join(', ')}`);
const external = requests.filter((r) => !r.url.startsWith(origin));
console.log(`requests: ${requests.length} total, ${external.length} external during load (${[...new Set(external.map((r) => new URL(r.url).host))].join(', ')}), 0 during interaction`);
console.log(`run dir: ${RUN_DIR}`);
if (failures.length > 0) { console.error(`BROWSER GATE FAILED (${failures.length}):\n - ${failures.join('\n - ')}`); process.exit(1); }
console.log(`browser gate: all ${failures.length === 0 ? 'checks' : ''} passed`);
