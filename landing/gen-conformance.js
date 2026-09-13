#!/usr/bin/env node
'use strict';
// Renders interop/claims.json to landing/conformance.html. Zero dependencies.
//   node landing/gen-conformance.js          # (re)generate the page
//   node landing/gen-conformance.js --check  # exit 1 if the committed page drifts
// Never hand-edit conformance.html; CI runs --check.

const fs = require('fs');
const path = require('path');
const { validateClaim, kindOf, REPO_RE } = require('../interop/replay.js');

const ROOT = path.resolve(__dirname, '..');
const REGISTRY_PATH = path.join(ROOT, 'interop', 'claims.json');
const OUT_PATH = path.join(__dirname, 'conformance.html');

const KINDS = new Set(['bolyra-suite', 'external-suite']);
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const SHA40 = /^[0-9a-f]{40}$/;

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
const isStr = (v) => typeof v === 'string' && v.length > 0;

function validateRegistry(reg) {
  if (!reg || !Array.isArray(reg.claims)) return ['registry.claims must be an array'];
  const errors = [];
  const seen = new Set();
  reg.claims.forEach((c, i) => {
    if (!c || typeof c !== 'object' || Array.isArray(c)) { errors.push(`claim #${i}: not an object`); return; }
    const id = isStr(c.id) ? c.id : `#${i}`;
    if (!isStr(c.id)) errors.push(`${id}: id must be a non-empty string`);
    else if (seen.has(c.id)) errors.push(`${id}: duplicate id ${c.id}`);
    seen.add(c.id);
    const kind = kindOf(c);
    if (!KINDS.has(kind)) errors.push(`${id}: unknown kind ${String(kind)}`);
    const impl = c.implementer && typeof c.implementer === 'object' ? c.implementer : {};
    if (!isStr(impl.repo) || !REPO_RE.test(impl.repo)) errors.push(`${id}: implementer.repo must match https://github.com/<owner>/<repo>`);
    if (!isStr(impl.commit) || !SHA40.test(impl.commit)) errors.push(`${id}: implementer.commit must be a full 40-hex sha`);
    if ('verification_run_url' in c) errors.push(`${id}: verification_run_url is not rendered in v1; remove it`);
    if (!isStr(c.verified_on) || !DATE_RE.test(c.verified_on)) errors.push(`${id}: verified_on must be YYYY-MM-DD`);
    if (!isStr(c.claim_text)) errors.push(`${id}: claim_text must be a non-empty string`);
    if (c.scope !== undefined && typeof c.scope !== 'string') errors.push(`${id}: scope must be a string when present`);
    if (KINDS.has(kind) && isStr(c.id)) for (const e of validateClaim(c)) errors.push(`${id}: ${e}`);
  });
  return errors;
}

function coveredClasses(c) {
  if (kindOf(c) === 'external-suite') return 'not applicable (own corpus)';
  const args = (c.suite && Array.isArray(c.suite.runner_args)) ? c.suite.runner_args : [];
  const types = [];
  for (let i = 0; i + 1 < args.length; i++) if (args[i] === '--type') types.push(args[i + 1]);
  return types.length ? types.join(', ') : 'Not specified';
}

const EXTERNAL_QUALIFIER =
  "Own-corpus reproduction: the implementer's published numbers reproduce at the pin. This is NOT Bolyra-suite conformance.";

// Code-unit comparisons: identical output on every machine and in CI.
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
function sortClaims(claims) {
  return [...claims].sort((a, b) => cmp(b.verified_on, a.verified_on) || cmp(a.id, b.id));
}

function renderClaim(c) {
  const kind = kindOf(c);
  const repo = c.implementer.repo;      // validated by REPO_RE
  const commit = c.implementer.commit;  // validated 40-hex
  const rows = [];
  const row = (k, v) => rows.push(`<tr><th>${esc(k)}</th><td>${v}</td></tr>`);
  row('Implementer', `<a href="${esc(repo)}">${esc(repo.replace('https://github.com/', ''))}</a>`);
  row('Implementation commit', `<a href="${esc(repo)}/commit/${esc(commit)}"><code>${esc(commit)}</code></a>`);
  row('Kind', esc(kind));
  if (kind === 'bolyra-suite') {
    row('Suite commit', `<a href="https://github.com/bolyra/bolyra/commit/${esc(c.suite.commit)}"><code>${esc(c.suite.commit)}</code></a>`);
    row('Vector set', esc(c.suite.vector_set || 'Not specified'));
    row('test-vectors.json sha256', `<code>${esc(c.suite.test_vectors_sha256)}</code>`);
    row('Covered classes', esc(coveredClasses(c)));
    row('Runner arguments', `<code>${esc(JSON.stringify(c.suite.runner_args || []))}</code>`);
    row('Adapter', `<code>${esc(c.adapter)}</code> (sha256 <code>${esc(c.adapter_sha256)}</code>)`);
    row('Expected', esc(`${c.expected.pass} pass / ${c.expected.fail} fail / ${c.expected.skip} skip`));
  } else {
    row('Covered classes', esc(coveredClasses(c)));
    row('Run', `<code>${esc(JSON.stringify(c.run.command))}</code> in <code>${esc(c.run.image)}</code>, network <code>${esc(c.run.network)}</code>`);
    row('Expected', esc(`${c.run.expect.pass}/${c.run.expect.run} pass, ${c.run.expect.scoped_out} scoped out`));
  }
  row('Claim', esc(c.claim_text));
  if (c.scope) row('Scope', esc(c.scope));
  row('Recorded verification date', esc(c.verified_on));
  const qualifier = kind === 'external-suite' ? `<p class="qualifier">${esc(EXTERNAL_QUALIFIER)}</p>` : '';
  return `<section class="claim">
<h2 class="claim-id">${esc(c.id)}</h2>
${qualifier}<table>${rows.join('')}</table>
</section>`;
}

function renderRegistry(reg) {
  const errors = validateRegistry(reg);
  if (errors.length) throw new Error(errors.join('\n'));
  const sections = sortClaims(reg.claims).map(renderClaim).join('\n');
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Conformance Claims — Bolyra</title>
  <meta name="description" content="Every external interoperability claim Bolyra publishes, with the pins that make it mechanically reproducible.">
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='12' fill='%230a0a0a'/%3E%3Ctext x='32' y='44' font-family='-apple-system,BlinkMacSystemFont,sans-serif' font-size='38' font-weight='700' text-anchor='middle' fill='%236366f1'%3EB%3C/text%3E%3C/svg%3E">
  <style>
    *, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }
    :root { --bg: #0a0a0a; --bg-elevated: #111113; --bg-code: #1a1a2e; --text: #e0e0e0; --text-muted: #888; --accent: #6366f1; --accent-hover: #818cf8; --cyan: #22d3ee; --border: #222; --max-width: 1100px; }
    body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; line-height: 1.6; }
    main { max-width: var(--max-width); margin: 0 auto; padding: 48px 24px 96px; }
    a { color: var(--accent); text-decoration: none; } a:hover { color: var(--accent-hover); }
    h1 { font-size: 2rem; margin-bottom: 8px; } .lede { color: var(--text-muted); margin-bottom: 8px; }
    .notice { color: var(--cyan); margin: 16px 0 32px; font-weight: 600; }
    .claim { background: var(--bg-elevated); border: 1px solid var(--border); border-radius: 12px; padding: 24px; margin-bottom: 24px; overflow-x: auto; }
    .claim-id { font-size: 1.1rem; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; margin-bottom: 12px; word-break: break-all; }
    .qualifier { color: var(--cyan); margin-bottom: 12px; }
    table { border-collapse: collapse; width: 100%; } th, td { text-align: left; vertical-align: top; padding: 6px 12px 6px 0; border-bottom: 1px solid var(--border); }
    th { color: var(--text-muted); white-space: nowrap; width: 220px; font-weight: 500; }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.9em; word-break: break-all; }
    .links a { margin-right: 24px; } footer { color: var(--text-muted); margin-top: 48px; font-size: 0.9rem; }
  </style>
</head>
<body>
<main>
  <p><a href="/">&larr; bolyra.ai</a></p>
  <h1>Conformance claims</h1>
  <p class="lede">Every external interoperability claim Bolyra publishes, with the pins that make it mechanically reproducible from <code>interop/claims.json</code> using <code>interop/replay.js</code>.</p>
  <p class="notice">These are dated claims. This page does not report current replay status.</p>
  <p class="links"><a href="https://github.com/bolyra/bolyra/actions/workflows/interop-replay.yml">Replay history</a><a href="https://github.com/bolyra/bolyra/blob/main/interop/SUBMITTING.md">How to add yours</a><a href="https://github.com/bolyra/bolyra/blob/main/spec/IMPLEMENTER.md">IMPLEMENTER.md</a></p>
${sections}
  <footer>Source of truth: <a href="https://github.com/bolyra/bolyra/blob/main/interop/claims.json">interop/claims.json</a>. A red replay means investigate, never edit the claim.</footer>
</main>
</body>
</html>
`;
}

function checkFile(reg, filePath) {
  const expected = renderRegistry(reg);
  if (!fs.existsSync(filePath)) return { ok: false, diff: [`${filePath}: missing (run: node landing/gen-conformance.js)`] };
  const actual = fs.readFileSync(filePath, 'utf8');
  if (actual === expected) return { ok: true, diff: [] };
  const a = actual.split('\n'), e = expected.split('\n');
  const diff = [];
  for (let i = 0; i < Math.max(a.length, e.length) && diff.length < 20; i++) {
    if (a[i] !== e[i]) diff.push(`line ${i + 1}:\n  committed: ${a[i] ?? '<EOF>'}\n  expected:  ${e[i] ?? '<EOF>'}`);
  }
  return { ok: false, diff };
}

module.exports = { validateRegistry, renderRegistry, checkFile, coveredClasses, esc };

if (require.main === module) {
  const reg = JSON.parse(fs.readFileSync(REGISTRY_PATH, 'utf8'));
  if (process.argv.includes('--check')) {
    const r = checkFile(reg, OUT_PATH);
    if (r.ok) { console.log('gen-conformance --check OK: landing/conformance.html matches interop/claims.json'); process.exit(0); }
    process.stderr.write(`gen-conformance --check FAILED: landing/conformance.html drifts from interop/claims.json\n${r.diff.join('\n')}\nRun: node landing/gen-conformance.js\n`);
    process.exit(1);
  }
  fs.writeFileSync(OUT_PATH, renderRegistry(reg));
  console.log(`wrote ${path.relative(ROOT, OUT_PATH)} (${reg.claims.length} claims)`);
}
