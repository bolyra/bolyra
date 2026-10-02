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
import { extractEvcSpec } from '../tools/spec-extract.mjs';
import { EVENTS } from '../src/core/usage.js';

const APP = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ROOT = path.resolve(APP, '../..');
const HTML_PATH = path.join(ROOT, 'landing/playground.html');
const html = fs.readFileSync(HTML_PATH);
const htmlSha256 = crypto.createHash('sha256').update(html).digest('hex');
const CSP = fs.readFileSync(path.join(APP, 'test/fixtures/csp.txt'), 'utf8').trim();
const observed = JSON.parse(fs.readFileSync(path.join(ROOT, 'integrations/payment-protocols/test/fixtures/x402-issuer-quote/tavily-challenge-observed.json'), 'utf8'));
const evcX = extractEvcSpec(fs.readFileSync(path.join(ROOT, 'spec/external-verifier-contract-v1.md'), 'utf8'));
const cliRequest = JSON.parse(fs.readFileSync(path.join(ROOT, 'integrations/cli/test/fixtures/verify/allow-agent-only/request.json'), 'utf8'));
const encodeHeader = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64');
const deepEq = (a, b) => JSON.stringify(a) === JSON.stringify(b);
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
  } else if (url === '/e') { res.writeHead(eStatus, { 'content-type': 'text/plain', 'cache-control': 'no-store' }); res.end(''); }
  else { res.writeHead(404); res.end('not found'); }
});
let eStatus = 200;
const events = []; // { phase, ev }
const CANARY = 'CANARY-7f3a-secret-do-not-send';
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const origin = `http://127.0.0.1:${server.address().port}`;

const browser = await chromium.launch();
const STUBS = [
  [/^https:\/\/fonts\.googleapis\.com\//, { contentType: 'text/css', body: '/* stub: no @font-face, so no gstatic fetch */' }],
  [/^https:\/\/fonts\.gstatic\.com\//, { contentType: 'font/woff2', body: '' }],
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
  await context.route('**/*', async (route) => {
    const req = route.request();
    const url = req.url();
    requests.push({ phase, url });
    if (url.startsWith(origin + '/playground')) return route.continue();
    if (url.startsWith(origin + '/e?') || url === origin + '/e') {
      // Usage beacon policy: same-origin GET /e, empty body, exactly v=1 and one allowlisted ev,
      // no other params, no cookie, no referer; never during page load.
      const u = new URL(url); const keys = [...u.searchParams.keys()];
      const headers = await req.allHeaders();
      const ok = phase !== 'load' && req.method() === 'GET' && !req.postData() && u.pathname === '/e'
        && keys.length === 2 && keys[0] === 'v' && keys[1] === 'ev' && u.searchParams.get('v') === '1'
        && EVENTS.includes(u.searchParams.get('ev')) && !('cookie' in headers) && !('referer' in headers);
      if (!ok) failures.push(`beacon violates policy during ${phase}: ${req.method()} ${url} headers=${Object.keys(headers).join(',')}`);
      else events.push({ phase, ev: u.searchParams.get('ev') });
      return route.continue();
    }
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
  check((await page.$$('[role=tab]')).length === 4, 'four tabs rendered');

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

  // ---- Phase B: Decode a 402 ---------------------------------------------
  await page.click('[data-tab=decode]');
  await page.waitForSelector('[data-view=decode]');
  const decodeAndRead = async () => { await page.click('[data-action=decode]'); await page.waitForSelector('[data-results-decode]'); return page.getAttribute('[data-results-decode]', 'data-decode-ok'); };
  await page.click('[data-sample=tavily]');
  check(await decodeAndRead() === 'true', 'tavily sample decodes');
  check((await page.$$('[data-leg]')).length === 2, 'two legs rendered');
  check(await page.getAttribute('[data-leg="0"]', 'data-classification') === 'address-valued', 'leg 0 address-valued');
  check(await page.getAttribute('[data-leg="1"]', 'data-classification') === 'placeholder-urn', 'leg 1 placeholder-urn');
  check((await page.textContent('[data-leg="0"] [data-matcher]')).includes('Supply a host audience'), 'no audience → asks for one');
  const leg1Text = await page.textContent('[data-leg="1"]');
  check(leg1Text.includes('placeholder-and-token shape discussed in §4.2; issuer signature and host configuration are not checked here'), 'leg 1 shape sentence');
  check(!leg1Text.includes('§4.2 applies'), 'no affirmative "§4.2 applies"');
  check(leg1Text.includes('Decoded; signature not verified') && (await page.textContent('[data-leg="1"] [data-kid]')) === 'tavily-agentpay-x402-signing-key', 'token shown not verified with kid');
  check((await page.$$('[data-leg="1"] .musts li')).length === 9, 'nine host MUSTs listed');
  check((await page.textContent('[data-leg="0"] [data-observation]')).includes('differed on every call'), 'sourced observation on sample leg 0');
  await page.fill('[data-field=audience]', observed.decoded.accepts[0].payTo);
  check(await page.$('[data-results-decode]') === null, 'changing audience clears results');
  check(await decodeAndRead() === 'true' && (await page.textContent('[data-leg="0"] [data-matcher]')).includes('this check passes'), 'audience == payTo → passes');
  await page.fill('[data-field=audience]', observed.decoded.accepts[0].payTo + ' ');
  check(await decodeAndRead() === 'true' && (await page.textContent('[data-leg="0"] [data-matcher]')).includes('request_mismatch'), 'audience bytes are not trimmed: payTo + space → deny request_mismatch');
  await page.fill('[data-field=audience]', '0x' + '11'.repeat(20));
  check(await decodeAndRead() === 'true' && (await page.textContent('[data-leg="0"] [data-matcher]')).includes('request_mismatch'), 'other audience → deny request_mismatch');
  for (const [field, value] of [['resource', 'https://other.example/x'], ['now', '1790697720'], ['maxSeconds', '120']]) {
    await decodeAndRead(); await page.fill(`[data-field=${field}]`, value);
    check(await page.$('[data-results-decode]') === null, `changing ${field} clears results`);
  }
  check(await decodeAndRead() === 'true', 'decodes with a differing resource');
  check((await page.textContent('[data-header-resource]')) === 'https://x402.tavily.com/search' && (await page.textContent('[data-input-resource]')) === 'https://other.example/x', 'header resource and proposed URL shown separately');
  const otherRail = encodeHeader({ ...observed.decoded, accepts: [{ ...observed.decoded.accepts[1], payTo: 'urn:example:other-rail' }] });
  await page.fill('[data-field=x402-header]', otherRail);
  check(await page.$('[data-results-decode]') === null, 'editing header clears results');
  check(await decodeAndRead() === 'true' && await page.getAttribute('[data-leg="0"]', 'data-classification') === 'other', 'another rail placeholder → other');
  check((await page.textContent('[data-leg="0"] [data-require]')).includes('cannot determine whether §4.2 applies'), 'other → cannot determine');
  const malformedTok = encodeHeader({ ...observed.decoded, accepts: [{ ...observed.decoded.accepts[1], extra: { ...observed.decoded.accepts[1].extra, quoteToken: 'not.a.jws' } }] });
  await page.fill('[data-field=x402-header]', malformedTok);
  check(await decodeAndRead() === 'true' && (await page.textContent('[data-leg="0"] [data-require]')).includes('not a well-formed compact JWS'), 'malformed token → no claim');
  check(!(await page.textContent('[data-leg="0"]')).includes('placeholder-and-token shape'), 'malformed token → no shape sentence');
  await page.fill('[data-field=x402-header]', 'A'.repeat(65 * 1024));
  check(await decodeAndRead() === 'false' && (await page.textContent('[data-results-decode]')).includes('exceeds'), '65 KiB paste → inline error');
  // Codex review round 1: hostile decoded fields must not crash the page; bytes are not trimmed.
  const hostileResource = encodeHeader({ ...observed.decoded, resource: { url: { toString: 0 }, description: [1, 2] }, error: { toString: null }, accepts: [{ ...observed.decoded.accepts[1], extra: { ...observed.decoded.accepts[1].extra, quoteToken: Buffer.from('{"alg":{"toString":0},"kid":[1]}').toString('base64url') + '.' + Buffer.from('{"exp":"soon"}').toString('base64url') + '.c' } }] });
  await page.fill('[data-field=x402-header]', hostileResource);
  check(await decodeAndRead() === 'true', 'hostile object-valued fields still decode');
  check((await page.$$('[role=tab]')).length === 4 && await page.$('[data-view=decode]') !== null, 'page survives hostile decoded fields (no unmount)');
  check(page.consoleErrors.length === 0, `no console errors after hostile fields: ${page.consoleErrors.join(' | ')}`);
  await page.fill('[data-field=x402-header]', observed.paymentRequiredHeader + ' ');
  check(await decodeAndRead() === 'false' && (await page.textContent('[data-results-decode]')).includes('header_base64'), 'trailing whitespace is NOT trimmed: rejected as header_base64 like the package');
  check((await page.textContent('[data-statement=must-not-claim]')).includes('does NOT establish'), 'MUST NOT claim statement present');
  check((await page.textContent('[data-statement=role]')).includes('agent-side host'), 'Role statement present');

  // ---- Phase B: EVC wire shapes --------------------------------------------
  await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin });
  await page.click('[data-tab=wire]');
  await page.waitForSelector('[data-view=wire]');
  await page.$$eval('[data-view=wire] details', (els) => els.forEach((d) => { d.open = true; }));
  const expectedShapes = { 'request-example': evcX.request.example, 'request-schema': evcX.request.schema, 'real-request': cliRequest, 'verdict-allow': evcX.verdict.allow, 'verdict-consume': evcX.verdict.allowConsume, 'verdict-deny': evcX.verdict.deny, 'verdict-schema': evcX.verdict.schema };
  const blocks = [];
  for (const [id, json] of Object.entries(expectedShapes)) blocks.push({ sel: `[data-shape="${id}"]`, json, label: id });
  for (const e of evcX.examples) { blocks.push({ sel: `[data-example="${e.id}"] [data-example-part=verdict]`, json: e.verdict, label: `§${e.id} verdict` }); if (e.request) blocks.push({ sel: `[data-example="${e.id}"] [data-example-part=request]`, json: e.request, label: `§${e.id} request` }); }
  check(blocks.length === 7 + 9, `expected 16 JSON blocks, planned ${blocks.length}`);
  for (const b of blocks) {
    const shown = await page.$eval(`${b.sel} pre code`, (el) => el.textContent);
    check(deepEq(JSON.parse(shown), b.json), `${b.label}: displayed JSON equals the checkout's spec`);
    await page.click(`${b.sel} button.btn-ghost`);
    const clip = await page.evaluate(() => navigator.clipboard.readText());
    check(clip === shown, `${b.label}: clipboard equals displayed text`);
  }
  check((await page.textContent('[data-code=request_mismatch]')).includes('403'), 'request_mismatch row shows 403');
  check((await page.$$('[data-view=wire] [data-code]')).length === 16, '15 registry rows + 1 gate-local row');
  await page.click('[data-tab=simulate]');
  await page.waitForSelector('[data-view=simulate]');

  // ---- usage signals: canary never leaves; expected events, each once ------------
  await page.click('[data-tab=verify]'); await page.click('[data-tab=verify]');
  await page.fill('[data-field=input]', CANARY); await verifyAndRead(page);
  await page.fill('[data-field=expectedSigner]', CANARY);
  await page.click('[data-tab=decode]');
  await page.fill('[data-field=x402-header]', CANARY); await page.fill('[data-field=audience]', CANARY); await page.fill('[data-field=resource]', CANARY);
  await page.click('[data-action=decode]'); await page.waitForSelector('[data-results-decode]');
  check(requests.every((r) => !r.url.includes(CANARY) && !r.url.includes('CANARY')), 'pasted canary never appears in any request');
  const desk = events.filter((e) => e.phase === 'interact').map((e) => e.ev);
  check(desk.length === new Set(desk).size, `each usage event sent at most once per page load: ${desk.join(',')}`);
  check(desk[0] === 'interacted', `first usage event is interacted (got ${desk[0]})`);
  for (const ev of ['sample_verify', 'run_verify', 'verify_ok', 'verify_failed', 'verify_invalid', 'tab_simulate', 'sample_simulate', 'run_simulate', 'simulate_ok', 'simulate_failed', 'export_clicked', 'tab_decode', 'sample_decode', 'run_decode', 'decode_ok', 'decode_invalid', 'tab_evc', 'copy_clicked', 'tab_verify']) check(desk.includes(ev), `usage event ${ev} emitted`);
  check(desk.length <= 32, 'usage event cap respected');
  check(page.consoleErrors.length === 0, `console errors: ${page.consoleErrors.join(' | ')}`);
  fs.writeFileSync(path.join(RUN_DIR, 'manifest.json'), JSON.stringify({ htmlSha256, htmlPath: HTML_PATH, expectedCount, expectedHead, signer, files: { receipts: 'receipts.jsonl', signer: 'signer.json' } }, null, 2) + '\n');
  await context.close();
}

// --- mobile run -----------------------------------------------------------
{
  phase = 'load';
  eStatus = 500; // the beacon endpoint failing must not affect the page
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
  await page.click('[data-tab=decode]');
  await page.waitForSelector('[data-view=decode]');
  await page.click('[data-sample=tavily]');
  await page.click('[data-action=decode]');
  await page.waitForSelector('[data-results-decode]');
  check((await page.$$('[data-leg]')).length === 2, 'mobile: tavily decodes');
  check(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'mobile: no horizontal scroll after decode');
  check(events.some((e) => e.phase === 'interact-mobile'), 'mobile: usage events attempted while /e returns 500');
  const mobileErrors = page.consoleErrors.filter((t) => !/status of 500/.test(t));
  check(mobileErrors.length === 0, `mobile console errors (besides the forced /e 500): ${mobileErrors.join(' | ')}`);
  await context.close();
}

await browser.close();
server.close();

const interactive = requests.filter((r) => r.phase !== 'load');
const nonBeacon = interactive.filter((r) => !(r.url.startsWith(origin + '/e?')));
check(nonBeacon.length === 0, `non-beacon requests during interaction: ${nonBeacon.map((r) => r.url).join(', ')}`);
check(!requests.some((r) => r.phase === 'load' && r.url.startsWith(origin + '/e')), 'no usage beacon during page load');
const external = requests.filter((r) => !r.url.startsWith(origin));
console.log(`requests: ${requests.length} total, ${external.length} external during load (${[...new Set(external.map((r) => new URL(r.url).host))].join(', ')}), ${interactive.length} during interaction (all /e usage beacons; ${events.length} allowlisted events)`);
console.log(`run dir: ${RUN_DIR}`);
if (failures.length > 0) { console.error(`BROWSER GATE FAILED (${failures.length}):\n - ${failures.join('\n - ')}`); process.exit(1); }
console.log(`browser gate: all ${failures.length === 0 ? 'checks' : ''} passed`);
