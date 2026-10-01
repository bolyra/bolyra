#!/usr/bin/env node
/**
 * Builds landing/playground.html: one static page with the React UI and the
 * pinned @bolyra/receipts verifier bundled inline. Deterministic: no
 * timestamps, no absolute paths, LF only.
 *
 *   node build.mjs                 write ../../landing/playground.html
 *   node build.mjs --out <path>    write elsewhere
 *   node build.mjs --check [path]  build to memory and byte-compare (default: the committed page); writes nothing
 *   node build.mjs --meta <path>   also write esbuild's metafile
 *
 * Samples are read from committed repository fixtures at build time and
 * embedded in memory via `define`; nothing generated is written to the tree.
 * PLAYGROUND_EXTRA_SAMPLES=<json> adds samples (used by build.test.js only).
 */
import { build } from 'esbuild';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { extractEvcSpec, extractProfile42 } from './tools/spec-extract.mjs';
import { denyTable } from './tools/deny-table.mjs';
import { decodeBase64Strict, PLACEHOLDER_URN } from './src/core/x402.js';

const APP = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(APP, '../..');
const pkg = JSON.parse(fs.readFileSync(path.join(APP, 'package.json'), 'utf8'));
const args = process.argv.slice(2);
const flag = (name) => { const i = args.indexOf(name); return i === -1 ? undefined : (args[i + 1] && !args[i + 1].startsWith('--') ? args[i + 1] : true); };
const CHECK = flag('--check');
const OUT = typeof flag('--out') === 'string' ? path.resolve(flag('--out')) : path.join(ROOT, 'landing/playground.html');
const META = typeof flag('--meta') === 'string' ? path.resolve(flag('--meta')) : undefined;

const installed = JSON.parse(fs.readFileSync(path.join(APP, 'node_modules/@bolyra/receipts/package.json'), 'utf8')).version;
if (installed !== pkg.config.receiptsVersion) throw new Error(`config.receiptsVersion ${pkg.config.receiptsVersion} != installed @bolyra/receipts ${installed}`);
const installedPP = JSON.parse(fs.readFileSync(path.join(APP, 'node_modules/@bolyra/payment-protocols/package.json'), 'utf8')).version;
if (installedPP !== pkg.config.paymentProtocolsVersion) throw new Error(`config.paymentProtocolsVersion ${pkg.config.paymentProtocolsVersion} != installed @bolyra/payment-protocols ${installedPP}`);

// ---- samples from committed fixtures ------------------------------------
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');
const corpusManifest = JSON.parse(read('examples/receipt-scoring-kit/corpus/manifest.json')).chains;
const corpusSigner = JSON.parse(read('examples/receipt-scoring-kit/corpus/signer.json')).signer;
const claimedSigner = (text) => {
  const t = text.trim();
  let first; try { first = JSON.parse(t); } catch { first = JSON.parse(t.split('\n')[0]); }
  return first.signature.signer;
};
const samples = {
  chain: { label: 'Signed chain (3 receipts)', text: read('examples/receipt-scoring-kit/corpus/operator-b.jsonl'), ...corpusManifest['operator-b.jsonl'] },
  tampered: { label: 'Tampered log', text: read('examples/receipt-scoring-kit/corpus/tampered.jsonl'), signer: corpusSigner },
  forgedRef: { label: 'Commerce receipt, forged instance ref', text: read('spec/fixtures/receipt-conformance/forged-ref.json'), signer: corpusSigner },
  noInstance: { label: 'Receipt without instance binding', text: read('spec/fixtures/receipt-conformance/no-instance.json'), signer: corpusSigner },
  authInstance: { label: 'Auth receipt carrying an instance block', text: read('spec/fixtures/receipt-conformance/auth-kind-instance.json'), signer: corpusSigner },
};
for (const [id, s] of Object.entries(samples)) {
  if (s.signer && claimedSigner(s.text) !== s.signer) throw new Error(`sample ${id}: fixture claims ${claimedSigner(s.text)} but the manifest/signer document says ${s.signer}`);
}
if (process.env.PLAYGROUND_EXTRA_SAMPLES) Object.assign(samples, JSON.parse(fs.readFileSync(process.env.PLAYGROUND_EXTRA_SAMPLES, 'utf8')));

// ---- Phase B: x402 sample (Tavily fixture) + EVC wire shapes -------------
const sha = (buf) => createHash('sha256').update(buf).digest('hex');
const tavilyPath = 'integrations/payment-protocols/test/fixtures/x402-issuer-quote/tavily-challenge-observed.json';
const tavily = JSON.parse(read(tavilyPath));
{
  const bytes = decodeBase64Strict(tavily.paymentRequiredHeader);
  if (bytes === null) throw new Error('tavily fixture header is not canonical base64');
  const decoded = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  if (JSON.stringify(decoded) !== JSON.stringify(tavily.decoded)) throw new Error('tavily fixture: header does not decode to `decoded`');
  if (decoded.accepts[1].payTo !== PLACEHOLDER_URN) throw new Error(`tavily fixture leg 1 payTo != PLACEHOLDER_URN`);
}
const evcMd = read('spec/external-verifier-contract-v1.md');
const profileMd = read('spec/x402-evc-profile-v0.md');
const evc = extractEvcSpec(evcMd);
const profile42 = extractProfile42(profileMd);
const x402Samples = {
  tavily: {
    label: 'Tavily POST /search 402 (observed 2026-09-29)',
    header: tavily.paymentRequiredHeader,
    source: tavily._source,
    resource: 'https://x402.tavily.com/search',
    now: 1790697716,
    nowNote: 'sample time = the quote token\u2019s iat',
    observation: profile42.example,
  },
};
const deny = denyTable(evc.registry.map((r) => r.code));
const cliRequestPath = 'integrations/cli/test/fixtures/verify/allow-agent-only/request.json';
const cliRequest = JSON.parse(read(cliRequestPath));
const evcShapes = {
  source: { spec: 'spec/external-verifier-contract-v1.md', specSha256: sha(evcMd), revision: evc.revision, profile: 'spec/x402-evc-profile-v0.md', profileSha256: sha(profileMd), fixture: tavilyPath, fixtureSha256: sha(read(tavilyPath)), cliRequest: cliRequestPath, mppVersion: deny.mppVersion, paymentProtocolsVersion: pkg.config.paymentProtocolsVersion },
  request: evc.request,
  verdict: { ...evc.verdict, kinds: evc.kinds, omittedKindMeans: evc.omittedKindMeans },
  registry: evc.registry.map((r, i) => ({ ...r, ...deny.registry[i] })),
  gateLocal: deny.gateLocal,
  examples: evc.examples,
  realRequest: { label: 'Real request from the CLI verify fixture (full bundle)', json: cliRequest, bundleChars: cliRequest.bundle.length },
  profile42,
};
for (let i = 0; i < evc.registry.length; i++) if (evc.registry[i].code !== deny.registry[i].code) throw new Error('registry/deny-table order mismatch');

// ---- bundle -------------------------------------------------------------
const result = await build({
  entryPoints: [path.join(APP, 'src/main.jsx')],
  bundle: true, write: false, format: 'iife', minify: true, target: 'es2020', platform: 'browser',
  jsx: 'automatic', legalComments: 'none', charset: 'utf8', metafile: true, absWorkingDir: APP,
  define: {
    'process.env.NODE_ENV': '"production"',
    __PLAYGROUND_VERSION__: JSON.stringify(pkg.version),
    __RECEIPTS_VERSION__: JSON.stringify(pkg.config.receiptsVersion),
    __CLI_VERSION__: JSON.stringify(pkg.config.cliVersion),
    __SAMPLES__: JSON.stringify(samples),
    __PAYMENT_PROTOCOLS_VERSION__: JSON.stringify(pkg.config.paymentProtocolsVersion),
    __X402_SAMPLES__: JSON.stringify(x402Samples),
    __EVC_SHAPES__: JSON.stringify(evcShapes),
  },
  supported: { 'inline-script': true },
});
// esbuild escapes `</script` in string literals; it does not escape `<!--` or `<script`, which
// together can flip the HTML parser into the double-escaped script state and swallow the rest
// of the page. `\x3C` decodes to `<` inside string, template and regex literals alike; anywhere
// else it is a syntax error that the artifact test would surface immediately.
let bundle = result.outputFiles[0].text.replace(/\r\n/g, '\n').replace(/<(!--|script)/gi, '\\x3C$1');
if (/<\/script|<script|<!--/i.test(bundle)) throw new Error('bundle contains an unescaped inline-script terminator');
for (const input of Object.keys(result.metafile.inputs)) {
  if (input.includes('@bolyra/mpp')) throw new Error('@bolyra/mpp must not be bundled');
  if (input.includes('@bolyra/payment-protocols')) throw new Error('@bolyra/payment-protocols must not be bundled (the page ports its parser; see src/core/x402.js)');
  if (/node_modules\/jose\//.test(input)) throw new Error('jose must not be bundled in Phase B (verification is deferred)');
}

// ---- licenses -----------------------------------------------------------
const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const LICENSED = [
  ['react', 'node_modules/react/LICENSE'], ['react-dom', 'node_modules/react-dom/LICENSE'], ['scheduler', 'node_modules/scheduler/LICENSE'],
  ['@bolyra/receipts', null /* tarball ships no LICENSE; the repository's Apache-2.0 LICENSE applies */],
  ['@noble/secp256k1', 'node_modules/@noble/secp256k1/LICENSE'], ['@noble/hashes', 'node_modules/@noble/hashes/LICENSE'],
];
const licenses = LICENSED.map(([name, file]) => {
  const meta = JSON.parse(fs.readFileSync(path.join(APP, 'node_modules', name, 'package.json'), 'utf8'));
  const text = fs.readFileSync(file ? path.join(APP, file) : path.join(ROOT, 'LICENSE'), 'utf8').replace(/\r\n/g, '\n').trim();
  return `<details><summary>${esc(name)}@${esc(meta.version)} (${esc(meta.license)})</summary><pre>${esc(text)}</pre></details>`;
}).join('\n');

// ---- page ---------------------------------------------------------------
const template = fs.readFileSync(path.join(APP, 'template.html'), 'utf8').replace(/\r\n/g, '\n');
const fill = (tpl, map) => Object.entries(map).reduce((acc, [k, v]) => acc.split(`{{${k}}}`).join(v), tpl);
const count = (k) => (template.match(new RegExp(`\\{\\{${k}\\}\\}`, 'g')) || []).length;
if (count('BUNDLE') !== 1 || count('LICENSES') !== 1) throw new Error('template must contain exactly one {{BUNDLE}} and one {{LICENSES}}');
if (count('RECEIPTS_VERSION') < 1 || count('CLI_VERSION') < 1 || count('PAYMENT_PROTOCOLS_VERSION') < 1) throw new Error('template must mention {{RECEIPTS_VERSION}}, {{CLI_VERSION}} and {{PAYMENT_PROTOCOLS_VERSION}}');
const html = fill(template, { BUNDLE: bundle, LICENSES: licenses, RECEIPTS_VERSION: esc(pkg.config.receiptsVersion), CLI_VERSION: esc(pkg.config.cliVersion), PAYMENT_PROTOCOLS_VERSION: esc(pkg.config.paymentProtocolsVersion) });
if (!html.endsWith('\n')) throw new Error('template must end with a newline');

if (CHECK !== undefined) {
  const target = typeof CHECK === 'string' ? path.resolve(CHECK) : OUT;
  const committed = fs.existsSync(target) ? fs.readFileSync(target, 'utf8') : null;
  if (committed !== html) { console.error(`playground: ${path.relative(ROOT, target)} is out of date; run \`npm run build\` in apps/playground`); process.exit(1); }
  console.log(`playground: ${path.relative(ROOT, target)} matches the build (${html.length} chars)`);
} else {
  fs.writeFileSync(OUT, html);
  console.log(`playground: wrote ${path.relative(ROOT, OUT)} (${html.length} chars, bundle ${bundle.length})`);
}
if (META) fs.writeFileSync(META, JSON.stringify(result.metafile));
