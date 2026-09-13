#!/usr/bin/env node
'use strict';
// Snapshot/verify the protected tree so that a replay of one claim cannot
// alter what a later claim executes (spec §3.5). Pure filesystem: never runs
// git (a tampered .git/config could make git execute a command). The workflow
// COPIES this file out of the workspace and runs the copy under env -i, so the
// verifier cannot be replaced by the tamper it is looking for.
//   node harness-integrity.js snapshot <file.json> --root <workspace>
//   node harness-integrity.js verify   <file.json> --root <workspace>
// Coverage: everything under interop/ spec/ landing/ .github/ (ignored files
// included) plus the paths the runner LOADS CODE FROM (see PROTECTED_LOAD_PATHS);
// ALL of .git/
// including objects (stored bytes are not immutable and objects/info/alternates
// can redirect lookups); and EVERY root-level entry non-recursively — files,
// directories and symlinks — so a planted root node_modules/, which the runner
// unshifts onto module.paths, cannot appear unnoticed.
// NOT covered, by design: the contents of unprotected root directories beyond
// their immediate entry list (this includes integrations/ subtrees the harness
// never loads, e.g. integrations/x402-evc/ — a change there cannot alter what a
// later claim executes), the host toolchain (node/git/docker), $HOME,
// scratch dirs, and changes restored before verification. A container escape or
// host compromise is out of this checker's scope (spec §3.5 stated residual).
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PROTECTED_ROOTS = ['interop', 'spec', 'landing', '.github'];
// Beyond the first-party roots above, the runner LOADS code from these paths, so a
// replayed claim could use them to change what a later claim executes.
// spec/conformance-runner.js require()s ../integrations/receipts/dist/index.js
// (whose own bare requires then resolve through integrations/receipts/node_modules),
// and its lines 113-118 unshift CANDIDATE_MODULE_PATHS onto module.paths. Scoping by
// what is loaded rather than by repo layout is both wider and narrower than
// protecting integrations/ wholesale: it picks up sdk/node_modules, which is on
// module.paths and was previously unfingerprinted, and drops ~27k files under
// integrations/ that the harness can never reach. A test keeps this list in step
// with the runner by parsing CANDIDATE_MODULE_PATHS out of conformance-runner.js.
const PROTECTED_LOAD_PATHS = [
  'integrations/receipts',
  'circuits/node_modules',
  'sdk/node_modules',
  'integrations/cli/node_modules',
];
const MAX_DIFFS = 50;

function die(msg) { process.stderr.write(`harness-integrity: ${msg}\n`); process.exit(1); }

// Streamed, so a large pack file is never buffered whole.
function sha256File(abs) {
  const h = crypto.createHash('sha256');
  const fd = fs.openSync(abs, 'r');
  const buf = Buffer.alloc(1 << 20);
  try { let n; while ((n = fs.readSync(fd, buf, 0, buf.length, null)) > 0) h.update(buf.subarray(0, n)); }
  finally { fs.closeSync(fd); }
  return h.digest('hex');
}
function fingerprint(abs) {
  const st = fs.lstatSync(abs);              // any error other than ENOENT propagates → die
  const mode = (st.mode & 0o7777).toString(8);
  if (st.isSymbolicLink()) return `symlink:${mode}:${fs.readlinkSync(abs)}`;
  if (st.isDirectory()) return `dir:${mode}:${crypto.createHash('sha256').update(fs.readdirSync(abs).sort().join('\0')).digest('hex')}`;
  if (st.isFile()) return `file:${mode}:${sha256File(abs)}`;
  return `other:${mode}`;
}
function walk(root, rel, out) {
  const abs = path.join(root, rel);
  let st;
  try { st = fs.lstatSync(abs); } catch (e) { if (e.code === 'ENOENT') return; throw e; }
  out[rel] = fingerprint(abs);
  if (st.isDirectory()) for (const name of fs.readdirSync(abs).sort()) walk(root, `${rel}/${name}`, out);
}
function snapshot(root) {
  const out = Object.create(null);                            // a file named __proto__ must not hit the setter
  // In a git worktree or submodule `.git` is a pointer FILE; walking it would
  // record 66 bytes and silently cover none of the object store. Fail loudly
  // rather than report a hollow success.
  const gitSt = fs.lstatSync(path.join(root, '.git'));
  if (!gitSt.isDirectory()) die('.git is not a directory (gitfile: worktree or submodule) — run against a full checkout');
  for (const r of PROTECTED_ROOTS) walk(root, r, out);
  for (const r of PROTECTED_LOAD_PATHS) walk(root, r, out);   // absent paths are skipped by walk()
  walk(root, '.git', out);
  for (const name of fs.readdirSync(root).sort()) {          // EVERY root entry, non-recursive
    if (name === '.git' || PROTECTED_ROOTS.includes(name)) continue;   // already walked in full
    out[name] = fingerprint(path.join(root, name));
  }
  return out;
}

const args = process.argv.slice(2);
const cmd = args[0], file = args[1];
const ri = args.indexOf('--root');
const root = ri >= 0 && args[ri + 1] ? path.resolve(args[ri + 1]) : null;
// `file.startsWith('-')` catches an omitted file argument (`snapshot --root X`),
// which would otherwise write a file literally named `--root` and exit 0.
if (!['snapshot', 'verify'].includes(cmd) || !file || file.startsWith('-') || !root) {
  die('usage: harness-integrity.js snapshot|verify <file.json> --root <workspace>');
}

try {
  if (cmd === 'snapshot') {
    const snap = snapshot(root);
    fs.writeFileSync(file, JSON.stringify(snap, null, 1)); // a null-prototype object serializes __proto__ as an ordinary key
    console.log(`harness-integrity: snapshot of ${Object.keys(snap).length} entries → ${file}`);
  } else {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) die(`${file} is not a manifest object`);
    const base = Object.assign(Object.create(null), parsed);
    const now = snapshot(root);
    const diffs = [];
    for (const p of new Set([...Object.keys(base), ...Object.keys(now)])) {
      if (base[p] !== now[p]) diffs.push(`${p}: ${base[p] || 'absent'} -> ${now[p] || 'absent'}`);
    }
    if (diffs.length) {
      const more = diffs.length > MAX_DIFFS ? `\n  … and ${diffs.length - MAX_DIFFS} more` : '';
      die(`protected tree changed:\n  ${diffs.slice(0, MAX_DIFFS).join('\n  ')}${more}`);
    }
    console.log('harness-integrity: OK');
  }
} catch (e) {
  die(e.message);   // Node's message already leads with the errno code
}
