#!/usr/bin/env node
// build.mjs — publish the operator-trial reviewer evidence report, rendered from the
// COMMITTED dry-run fixture, as bolyra.ai/evidence-report-sample (labeled SIMULATED).
//
//   node landing/evidence-sample/build.mjs          # writes the seven artifacts under landing/
//   node landing/evidence-sample/build.mjs --check  # regenerates and compares; exit 1 on drift
//
// The report tool is run unchanged (examples/operator-trial `npm run report`); this file only
// wraps its output in a banner and copies the inputs next to it. Requires examples/operator-trial
// node_modules (`npm ci` there first). Nothing here is evidence of demand or of a customer run.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, '..', '..');
const trialDir = path.join(repo, 'examples', 'operator-trial');
const fixtureDir = path.join(trialDir, 'test', 'report-fixtures', 'dry-run');
const landing = path.join(repo, 'landing');
const PAGE = path.join(landing, 'evidence-report-sample.html');
const OUT_DIR = path.join(landing, 'evidence-report-sample');

/** Last commit that touched the operator-trial tool sources, lockfile and fixture. deploy.sh refuses to ship if any of those changed since. */
export const PIN_COMMIT = '93239a88dbc6c48036b6e954e22ea9feb7f4056e';
/** Status counts the committed fixture must produce. A different tool or fixture must change this line on purpose. */
export const BASELINE = { SIGNED: 18, OBSERVED: 12, DERIVED: 21, ABSENT: 27, FAILED: 0 };
export const BUNDLE_FILES = ['receipts.jsonl', 'summary.json', 'signer.json', 'VERIFY.txt'];
const BANNER_START = '<!-- simulated-sample-banner:start -->';
const BANNER_END = '<!-- simulated-sample-banner:end -->';
const TITLE_PREFIX = 'SIMULATED sample: ';

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
const read = (p) => fs.readFileSync(p);
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

/** sha256 over the report implementation and the fixture, so --check notices a tool change even on a shallow checkout. */
export function sourceManifest() {
  const files = [
    ...fs.readdirSync(path.join(trialDir, 'src', 'report')).filter((f) => f.endsWith('.ts')).sort().map((f) => path.join('src', 'report', f)),
    'package.json',
    ...BUNDLE_FILES.map((f) => path.join('test', 'report-fixtures', 'dry-run', f)),
  ];
  const lines = files.map((rel) => `${rel}\n${sha256(read(path.join(trialDir, rel)))}\n`);
  return { files, hash: sha256(lines.join('')) };
}

export function readAnchors() {
  const signer = String(JSON.parse(read(path.join(fixtureDir, 'signer.json')).toString('utf8')).signer || '').toLowerCase();
  const head = String(JSON.parse(read(path.join(fixtureDir, 'summary.json')).toString('utf8')).headReceiptHash || '').toLowerCase();
  const count = read(path.join(fixtureDir, 'receipts.jsonl')).toString('utf8').split('\n').filter((l) => l.trim() !== '').length;
  if (!/^0x[0-9a-f]{40}$/.test(signer)) throw new Error(`fixture signer.json has no 20-byte signer: ${signer}`);
  if (!/^0x[0-9a-f]{64}$/.test(head)) throw new Error(`fixture summary.json has no 32-byte headReceiptHash: ${head}`);
  // VERIFY.txt is part of the bundle; it must agree with the anchors we type, or the sample would contradict itself.
  const verify = read(path.join(fixtureDir, 'VERIFY.txt')).toString('utf8').trim();
  const m = verify.match(/^npx @bolyra\/cli@(\S+) receipt verify-chain \S+ --signer (0x[0-9a-fA-F]{40}) --expect-count (\d+) --expect-head (0x[0-9a-fA-F]{64})$/);
  if (!m) throw new Error(`fixture VERIFY.txt has an unexpected shape: ${verify}`);
  const [, cliPin, vSigner, vCount, vHead] = m;
  if (vSigner.toLowerCase() !== signer) throw new Error(`VERIFY.txt signer ${vSigner} != signer.json ${signer}`);
  if (Number(vCount) !== count) throw new Error(`VERIFY.txt --expect-count ${vCount} != ${count} receipt lines`);
  if (vHead.toLowerCase() !== head) throw new Error(`VERIFY.txt --expect-head ${vHead} != summary.json ${head}`);
  return { signer, head, count, cliPin };
}

export function reportArgs(a) {
  return ['--bundle', 'test/report-fixtures/dry-run', '--signer', a.signer, '--expect-count', String(a.count), '--expect-head', a.head];
}

/** Runs the unchanged report tool on the fixture; returns the exact bytes it wrote. */
export function generateReport(a) {
  if (!fs.existsSync(path.join(trialDir, 'node_modules'))) {
    throw new Error(`examples/operator-trial/node_modules is missing; run \`npm ci\` in examples/operator-trial first`);
  }
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'evidence-sample-'));
  try {
    const r = spawnSync('npm', ['run', 'report', '--silent', '--', ...reportArgs(a), '--out', tmp], { cwd: trialDir, encoding: 'utf8' });
    if (r.status !== 0) throw new Error(`report tool exited ${r.status}\n${r.stdout}\n${r.stderr}`);
    return { html: read(path.join(tmp, 'report.html')).toString('utf8'), json: read(path.join(tmp, 'report.json')).toString('utf8') };
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

export function statusCounts(report) {
  const c = { SIGNED: 0, OBSERVED: 0, DERIVED: 0, ABSENT: 0, FAILED: 0 };
  for (const f of report.findings) c[f.status] = (c[f.status] ?? 0) + 1;
  return c;
}

function assertBaseline(report, a) {
  const c = statusCounts(report);
  for (const k of Object.keys(BASELINE)) {
    if (c[k] !== BASELINE[k]) throw new Error(`status counts drifted from the committed baseline: got ${JSON.stringify(c)}, expected ${JSON.stringify(BASELINE)}`);
  }
  if (report.tool.cli !== a.cliPin) throw new Error(`report CLI pin ${report.tool.cli} != VERIFY.txt pin ${a.cliPin}`);
  if (report.anchors.signer !== a.signer || report.anchors.expectCount !== a.count || report.anchors.expectHead !== a.head) {
    throw new Error(`report anchors ${JSON.stringify(report.anchors)} differ from the fixture-derived anchors`);
  }
  if (!Array.isArray(report.findings) || report.findings.length === 0) throw new Error('report has no findings');
}

export function banner(report, a, manifest) {
  const pinShort = PIN_COMMIT.slice(0, 8);
  const src = `https://github.com/bolyra/bolyra/tree/${PIN_COMMIT}/examples/operator-trial`;
  const cmd = `npm run report -- ${reportArgs(a).join(' ')}`;
  const counts = statusCounts(report);
  const bundleLinks = BUNDLE_FILES.map((f) => `<a href="/evidence-report-sample/bundle/${f}">${f}</a>`).join(' · ');
  return [
    BANNER_START,
    '<style>',
    '.sim-banner{border:3px solid #b71c1c;background:#fff4f4;padding:.9rem 1.1rem;margin:0 0 1.5rem;font-size:14px;line-height:1.5}',
    '.sim-banner h2{margin:0 0 .4rem;border:0;padding:0;font-size:1.1rem;color:#b71c1c;letter-spacing:.04em}',
    '.sim-banner p{margin:.35rem 0}.sim-banner pre{margin:.4rem 0 0;background:#fff;border:1px solid #ddd}.sim-banner code{word-break:break-all}',
    '</style>',
    '<div class="sim-banner" role="note">',
    '<h2>SIMULATED SAMPLE</h2>',
    `<p>This report was generated from the committed dry-run fixture in the Bolyra repository by the shipped report tool, <strong>${esc(report.tool.name)} ${esc(report.tool.version)}</strong> with <code>@bolyra/receipts ${esc(report.tool.receipts)}</code> (re-verify command pinned to <code>@bolyra/cli@${esc(report.tool.cli)}</code>). The fixture came from a dry run: simulated credentials, an ephemeral signer, no proof verification, a built-in localhost echo endpoint, no customer endpoint. It shows the deliverable&#39;s form and limits, not a customer run, and it is not evidence that anyone uses Bolyra.</p>`,
    `<p>The anchors below (signer, receipt count, head hash) were copied from the bundle&#39;s own files, so they establish consistency with the bundle only, not signer identity or completeness. Status counts: ${['SIGNED', 'OBSERVED', 'DERIVED', 'ABSENT', 'FAILED'].map((s) => `${s} ${counts[s]}`).join(' · ')}. Missing evidence is printed as ABSENT and failed checks as FAILED; nothing is filtered.</p>`,
    `<p><strong>Files.</strong> <a href="/evidence-report-sample/report.json">report.json</a> (same findings as this page) · input bundle: ${bundleLinks} · <a href="${src}">source at commit ${pinShort}</a> (tool and fixture) · <a href="/#acceptance-exercise">back to the acceptance-exercise offer</a>.</p>`,
    `<p><strong>Reproduce.</strong> Node 20 or newer. This regenerates <code>report.html</code> and <code>report.json</code>. Compared with the published files, <code>report.json</code> differs only in the generation timestamp; <code>report.html</code> additionally lacks this banner and the &quot;SIMULATED sample:&quot; title prefix, which the publication step (<code>landing/evidence-sample/build.mjs</code>) adds around the unchanged report. Source manifest sha256 (report tool + fixture) <code>${manifest.hash}</code>.</p>`,
    `<pre>git clone https://github.com/bolyra/bolyra.git &amp;&amp; cd bolyra &amp;&amp; git checkout ${pinShort}\ncd examples/operator-trial &amp;&amp; npm ci\n${esc(cmd)}</pre>`,
    '<p>The <em>Re-verify yourself</em> command further down verifies the receipt chain with the published CLI; it does not reproduce the report&#39;s own findings (the id check B1a is report-local).</p>',
    '</div>',
    BANNER_END,
  ].join('\n');
}

/** Wraps the generated page. The invariant: strip the banner block and the title prefix and the original bytes come back exactly. */
export function compose(html, bannerHtml) {
  const titleMatches = html.match(/<title>[^<]*<\/title>/g) || [];
  if (titleMatches.length !== 1) throw new Error(`expected exactly one <title>, found ${titleMatches.length}`);
  if (html.split('<body>').length !== 2) throw new Error('expected exactly one <body>');
  if (html.includes(BANNER_START) || html.includes(TITLE_PREFIX)) throw new Error('generated report already contains banner markers');
  const out = html.replace('<title>', `<title>${TITLE_PREFIX}`).replace('<body>', `<body>\n${bannerHtml}`);
  const block = `\n${bannerHtml}`;
  if (out.split(block).length !== 2) throw new Error('banner must occur exactly once');
  const restored = out.replace(block, '').replace(`<title>${TITLE_PREFIX}`, '<title>');
  if (restored !== html) throw new Error('composition invariant violated: stripping the banner does not restore the original report');
  return out;
}

export function buildArtifacts() {
  const a = readAnchors();
  const manifest = sourceManifest();
  const gen = generateReport(a);
  const report = JSON.parse(gen.json);
  assertBaseline(report, a);
  const page = compose(gen.html, banner(report, a, manifest));
  const artifacts = new Map();
  artifacts.set(PAGE, Buffer.from(page, 'utf8'));
  artifacts.set(path.join(OUT_DIR, 'report.json'), Buffer.from(gen.json, 'utf8'));
  for (const f of BUNDLE_FILES) artifacts.set(path.join(OUT_DIR, 'bundle', f), read(path.join(fixtureDir, f)));
  return { artifacts, generatedAt: report.generatedAt };
}

/** Only the report-generation timestamp may differ between a committed artifact and a fresh one. */
function normalize(file, text, generatedAt) {
  if (!generatedAt) return text;
  if (file.endsWith('report.json') || file.endsWith('evidence-report-sample.html')) return text.split(generatedAt).join('<generatedAt>');
  return text;
}

function generatedAtOf(jsonPath) {
  try {
    return JSON.parse(read(jsonPath).toString('utf8')).generatedAt;
  } catch {
    return undefined;
  }
}

export function check() {
  const { artifacts, generatedAt } = buildArtifacts();
  const committedTs = generatedAtOf(path.join(OUT_DIR, 'report.json'));
  const drift = [];
  for (const [file, fresh] of artifacts) {
    if (!fs.existsSync(file)) {
      drift.push(`${path.relative(repo, file)}: missing`);
      continue;
    }
    const committed = read(file);
    const same = file.endsWith('.html') || file.endsWith('report.json')
      ? normalize(file, committed.toString('utf8'), committedTs) === normalize(file, fresh.toString('utf8'), generatedAt)
      : committed.equals(fresh);
    if (!same) drift.push(`${path.relative(repo, file)}: differs from a fresh build`);
  }
  return drift;
}

export function write() {
  const { artifacts } = buildArtifacts();
  for (const [file, bytes] of artifacts) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, bytes);
    console.log(`wrote ${path.relative(repo, file)}`);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.includes('--check')) {
      const drift = check();
      if (drift.length) {
        console.error('ERROR: published evidence sample drifts from a fresh build:\n  ' + drift.join('\n  ') + '\n  run: node landing/evidence-sample/build.mjs');
        process.exit(1);
      }
      console.log('OK: landing/evidence-report-sample.html and landing/evidence-report-sample/ match a fresh build of the committed fixture');
    } else {
      write();
    }
  } catch (err) {
    console.error(`ERROR: ${err.message}`);
    process.exit(1);
  }
}
