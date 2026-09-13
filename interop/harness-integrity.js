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
// included); ALL of .git/ including objects (stored bytes are not immutable and
// objects/info/alternates can redirect lookups); and EVERY root-level entry
// non-recursively — files, directories and symlinks.
// Why this set and not the conformance runner's module paths: replay.js never
// executes the in-repo runner. It does `git archive <suite.commit> spec` into a
// tmpdir and runs THAT copy (replay.js:312,342), and the external-suite branch
// runs entirely inside a container. So the in-repo load surface during a claim is
// interop/replay.js (which requires builtins only), interop/claims.json,
// interop/adapters/*.ts (also sha256-pinned at run time) and .git/. Protecting
// sdk/node_modules et al. would hash ~33k files that nothing can reach; the
// invariant that keeps it that way is pinned by tests in replay.test.js instead.
// NOT covered, by design: the contents of unprotected root directories beyond
// their immediate entry list — so for a root node_modules/ this detects a new or
// removed package but NOT an edit inside an existing one; the host toolchain
// (node/git/docker), $HOME, scratch dirs; a symlink target outside the workspace
// (recorded by target string only); and changes restored before verification. A
// container escape or host compromise is out of scope (spec §3.5 residual).
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PROTECTED_ROOTS = ['interop', 'spec', 'landing', '.github'];
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
// A path's CONTENT is covered iff it sits under a protected root or .git (walked
// in full), or it is a root entry that is not a directory — a root-entry file or
// symlink gets a full fingerprint, whereas a root-entry DIRECTORY is recorded only
// by its listing, so its contents are not covered.
function isCovered(rel, abs) {
  if (rel === '') return false;
  const top = rel.split('/')[0];
  if (top === '.git' || PROTECTED_ROOTS.includes(top)) return true;
  if (rel.includes('/')) return false;
  return !fs.lstatSync(abs).isDirectory();
}
function walk(root, rel, out) {
  const abs = path.join(root, rel);
  let st;
  try { st = fs.lstatSync(abs); } catch (e) { if (e.code === 'ENOENT') return; throw e; }
  out[rel] = fingerprint(abs);
  // Symlinks are recorded by target string and never followed (loop safety), so a
  // link INTO uncovered repo content would leave that content unprotected — the
  // `file:`-sibling case, e.g. cli/node_modules/@bolyra/sdk -> ../../../sdk. Refuse
  // rather than record 40 bytes and report OK.
  if (st.isSymbolicLink()) {
    let target = null;
    try { target = fs.realpathSync(abs); } catch (e) { if (e.code !== 'ENOENT') throw e; }
    if (target !== null) {
      const dest = path.relative(root, target);
      const insideRepo = dest !== '' && !dest.startsWith('..') && !path.isAbsolute(dest);
      if (insideRepo && !isCovered(dest, target)) die(`symlink ${rel} points at uncovered repo content (${dest}); add it to PROTECTED_ROOTS or remove the link`);
    }
  }
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
// realpath, not just resolve: on macOS os.tmpdir() lives under /var, itself a
// symlink to /private/var, so an un-resolved root makes every in-repo symlink
// target look like it points outside the workspace.
const root = ri >= 0 && args[ri + 1] ? fs.realpathSync(path.resolve(args[ri + 1])) : null;
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
