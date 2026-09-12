#!/usr/bin/env node
'use strict';
// Overlay ONE submission's registry + (for bolyra-suite) its ONE new adapter
// from a commit into the working tree, as git BLOBS — never a checkout, so a
// symlink or non-regular entry at either path is rejected rather than
// installed. Harness, runner, and every other adapter stay at the checked-out
// base. Used by .github/workflows/interop-replay.yml (spec §3.3 step 4, §3.5).
//   node interop/submission-overlay.js --ref <40-hex commit> --claim <id>
// Prints: id<TAB>kind<TAB>adapter on success (exit 0). Exit 1 on any refusal.
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = process.cwd();
const REGISTRY = 'interop/claims.json';
const KINDS = new Set(['bolyra-suite', 'external-suite']);
const ADAPTER_RE = /^adapters\/[A-Za-z0-9._-]+\.ts$/;
const ID_BAD = /[\x00-\x1f\x7f]/;

function die(msg) { process.stderr.write(`submission-overlay: ${msg}\n`); process.exit(1); }
function lstatOrNull(p) { try { return fs.lstatSync(p); } catch (e) { if (e.code === 'ENOENT') return null; throw e; } }
// Every ancestor of a destination must be a real directory (no symlinked dirs).
function requireRealDirs(rel) {
  const parts = rel.split('/').slice(0, -1);
  for (let i = 1; i <= parts.length; i++) {
    const st = lstatOrNull(path.join(ROOT, ...parts.slice(0, i)));
    if (!st || !st.isDirectory()) die(`${parts.slice(0, i).join('/')} is not a real directory`);
  }
}
function git(...args) { return execFileSync('git', ['-C', ROOT, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }); }
function gitRaw(...args) { return execFileSync('git', ['-C', ROOT, ...args], { stdio: ['ignore', 'pipe', 'pipe'] }); }

// `git ls-tree <ref> -- <path>` → { mode, type, sha } or null.
function treeEntry(ref, p) {
  const out = git('ls-tree', ref, '--', p).trim();
  if (!out) return null;
  const m = /^(\d{6}) (\w+) ([0-9a-f]{40})\t/.exec(out);
  return m ? { mode: m[1], type: m[2], sha: m[3] } : null;
}
function requireRegularBlob(ref, p) {
  const e = treeEntry(ref, p);
  if (!e) die(`${p} not present in ${ref}`);
  if (e.type !== 'blob' || e.mode !== '100644') die(`${p} in ${ref} is not a regular file (mode ${e.mode}, ${e.type})`);
  return e;
}

const args = process.argv.slice(2);
const opt = (n) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : undefined; };
const ref = opt('--ref');
const claimId = opt('--claim');
if (!ref || !/^[0-9a-f]{40}$/.test(ref)) die('ref must be a full 40-hex commit sha');
if (!claimId) die('--claim <id> is required');
if (ID_BAD.test(claimId) || claimId.startsWith('-')) die(`claim id not allowed: ${JSON.stringify(claimId)}`);

let type;
try { type = git('cat-file', '-t', ref).trim(); } catch { type = ''; }
if (type !== 'commit') die(`${ref} is not a commit in this repository (fetch it first)`);

// 1. Registry blob (validated as a regular file), parsed as data.
requireRegularBlob(ref, REGISTRY);
const registryBytes = gitRaw('cat-file', '-p', `${ref}:${REGISTRY}`);
let reg;
try { reg = JSON.parse(registryBytes.toString('utf8')); } catch { die(`${REGISTRY} in ${ref}: claims.json is not valid JSON`); }
if (!reg || !Array.isArray(reg.claims)) die(`${REGISTRY} in ${ref}: registry.claims must be an array`);
const matches = reg.claims.filter((c) => c && c.id === claimId);
if (matches.length !== 1) die(matches.length ? `duplicate id ${claimId} in ${ref}` : `no claim with id ${claimId} in ${ref}`);
const c = matches[0];
const kind = c.kind === undefined ? 'bolyra-suite' : c.kind;
if (!KINDS.has(kind)) die(`unknown kind ${kind} (claim ${claimId})`);

// 2. Adapter (bolyra-suite only): pathname allowlist, regular blob, and never
//    a replacement of an adapter that already exists at the base.
let adapter = '';
let adapterBytes = null;
if (kind === 'bolyra-suite') {
  adapter = String(c.adapter || '');
  if (!ADAPTER_RE.test(adapter)) die(`adapter pathname not allowed: ${JSON.stringify(adapter)} (claim ${claimId})`);
  const rel = `interop/${adapter}`;
  requireRealDirs(rel);
  if (lstatOrNull(path.join(ROOT, rel))) die(`${adapter} already exists at the base; submissions may only ADD an adapter`);
  requireRegularBlob(ref, rel);
  adapterBytes = gitRaw('cat-file', '-p', `${ref}:${rel}`);
}

// 3. Materialize as regular files (mode 0644): the adapter is created
//    exclusively (wx: fails if anything appeared meanwhile); the registry is
//    written to a temp file and renamed over (never follows a planted link).
requireRealDirs(REGISTRY);
if (adapterBytes) fs.writeFileSync(path.join(ROOT, 'interop', adapter), adapterBytes, { mode: 0o644, flag: 'wx' });
const tmp = path.join(ROOT, 'interop', `.claims.json.${process.pid}.tmp`);
fs.writeFileSync(tmp, registryBytes, { mode: 0o644, flag: 'wx' });
fs.renameSync(tmp, path.join(ROOT, REGISTRY));
process.stdout.write(`${claimId}\t${kind}\t${adapter}\n`);
