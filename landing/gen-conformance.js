#!/usr/bin/env node
'use strict';
// Renders interop/claims.json to landing/conformance.html. Zero dependencies.
//   node landing/gen-conformance.js          # (re)generate the page
//   node landing/gen-conformance.js --check  # exit 1 if the committed page drifts
// Never hand-edit conformance.html; CI runs --check.

const fs = require('fs');
const path = require('path');
const { validateClaim } = require('../interop/replay.js');

const ROOT = path.resolve(__dirname, '..');
const REGISTRY_PATH = path.join(ROOT, 'interop', 'claims.json');
const OUT_PATH = path.join(__dirname, 'conformance.html');

const KINDS = new Set(['bolyra-suite', 'external-suite']);
const REPO_RE = /^https:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)$/;
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
    const kind = c.kind === undefined ? 'bolyra-suite' : c.kind;
    if (!KINDS.has(kind)) errors.push(`${id}: unknown kind ${String(kind)}`);
    const impl = c.implementer && typeof c.implementer === 'object' ? c.implementer : {};
    const m = isStr(impl.repo) ? REPO_RE.exec(impl.repo) : null;
    if (!m || m[1] === '.' || m[1] === '..' || m[2] === '.' || m[2] === '..') errors.push(`${id}: implementer.repo must match https://github.com/<owner>/<repo>`);
    if (!isStr(impl.commit) || !SHA40.test(impl.commit)) errors.push(`${id}: implementer.commit must be a full 40-hex sha`);
    if ('verification_run_url' in c) errors.push(`${id}: verification_run_url is not rendered in v1; remove it`);
    if (!isStr(c.verified_on) || !DATE_RE.test(c.verified_on)) errors.push(`${id}: verified_on must be YYYY-MM-DD`);
    if (!isStr(c.claim_text)) errors.push(`${id}: claim_text must be a non-empty string`);
    if (c.scope !== undefined && typeof c.scope !== 'string') errors.push(`${id}: scope must be a string when present`);
    if (KINDS.has(kind) && isStr(c.id)) for (const e of validateClaim(c)) errors.push(`${id}: ${e}`);
  });
  return errors;
}

module.exports = { validateRegistry, esc };

if (require.main === module) {
  process.stderr.write('renderRegistry not implemented yet\n');
  process.exit(2);
}
