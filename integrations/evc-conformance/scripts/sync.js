#!/usr/bin/env node
/**
 * Vendor the EVC host-conformance assets from spec/ (the source of truth).
 *
 * The package NEVER edits these files by hand: `npm run sync` regenerates
 * vendor/ from ../../spec and records SHA-256 checksums in MANIFEST.json;
 * `npm run sync:check` verifies vendor/ still matches spec/ byte-for-byte
 * (run in CI so a spec change without a package release is caught).
 *
 * v0 scope (deliberate): ONLY the host_behavior surface — the runner, the
 * reference host, the host-conformance fixtures, and a vectors file trimmed
 * to host_behavior. The full 104-vector suite stays in the monorepo.
 */

const fs = require('fs');
const path = require('path');
const { createHash } = require('crypto');

const SPEC = path.join(__dirname, '../../../spec');
const VENDOR = path.join(__dirname, '../vendor');
const MANIFEST = path.join(__dirname, '../MANIFEST.json');
const CHECK = process.argv.includes('--check');

const sha = (buf) => createHash('sha256').update(buf).digest('hex');

function listFiles(dir, base = dir) {
  const out = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...listFiles(p, base));
    else out.push(path.relative(base, p));
  }
  return out.sort();
}

function buildTrimmedVectors() {
  const src = JSON.parse(fs.readFileSync(path.join(SPEC, 'test-vectors.json'), 'utf-8'));
  const host = src.vectors.filter((v) => v.type === 'host_behavior');
  return Buffer.from(
    JSON.stringify(
      {
        version: src.version,
        note:
          'host_behavior subset vendored from spec/test-vectors.json - regenerate with npm run sync, never edit',
        source_sha256: sha(fs.readFileSync(path.join(SPEC, 'test-vectors.json'))),
        vectors: host,
      },
      null,
      2,
    ) + '\n',
  );
}

function plan() {
  const entries = [
    { out: 'conformance-runner.js', data: fs.readFileSync(path.join(SPEC, 'conformance-runner.js')) },
    { out: 'reference-host.js', data: fs.readFileSync(path.join(SPEC, 'reference-host.js')) },
    { out: 'test-vectors.json', data: buildTrimmedVectors() },
  ];
  const fixDir = path.join(SPEC, 'fixtures/host-conformance');
  for (const rel of listFiles(fixDir)) {
    entries.push({
      out: path.join('fixtures/host-conformance', rel),
      data: fs.readFileSync(path.join(fixDir, rel)),
    });
  }
  return entries;
}

function buildManifest(entries) {
  const manifest = { generated_from: 'spec/', files: {} };
  for (const e of entries) manifest.files[`vendor/${e.out}`] = sha(e.data);
  const vectors = JSON.parse(buildTrimmedVectors().toString());
  manifest.vector_set = {
    version: vectors.version,
    host_behavior_count: vectors.vectors.length,
    source_sha256: vectors.source_sha256,
  };
  return JSON.stringify(manifest, null, 2) + '\n';
}

function main() {
  const entries = plan();

  if (CHECK) {
    let bad = 0;
    const expected = new Set(entries.map((e) => e.out));
    for (const e of entries) {
      const p = path.join(VENDOR, e.out);
      if (!fs.existsSync(p)) {
        console.error(`MISSING  vendor/${e.out}`);
        bad++;
      } else if (sha(fs.readFileSync(p)) !== sha(e.data)) {
        console.error(`STALE    vendor/${e.out} (spec/ has moved - run npm run sync and release)`);
        bad++;
      }
    }
    // Reject EXTRA files: package.json packs vendor/ wholesale, so anything
    // not in the plan would ship. The whitelist is the plan, exactly.
    if (fs.existsSync(VENDOR)) {
      for (const rel of listFiles(VENDOR)) {
        if (!expected.has(rel)) {
          console.error(`EXTRA    vendor/${rel} (not produced by sync - would ship; remove it)`);
          bad++;
        }
      }
    }
    // Verify MANIFEST.json itself matches what a fresh sync would write.
    const wantManifest = buildManifest(entries);
    const haveManifest = fs.existsSync(MANIFEST) ? fs.readFileSync(MANIFEST, 'utf-8') : '';
    if (haveManifest !== wantManifest) {
      console.error('STALE    MANIFEST.json (does not match a fresh sync)');
      bad++;
    }
    if (bad) {
      console.error(`\nsync:check FAILED - ${bad} problem(s)`);
      process.exit(1);
    }
    console.log(`sync:check OK - ${entries.length} vendored files + MANIFEST match spec/, no extras`);
    return;
  }

  fs.rmSync(VENDOR, { recursive: true, force: true });
  for (const e of entries) {
    const p = path.join(VENDOR, e.out);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, e.data);
  }
  fs.writeFileSync(MANIFEST, buildManifest(entries));
  const vectors = JSON.parse(buildTrimmedVectors().toString());
  console.log(
    `synced ${entries.length} files from spec/ (vector set v${vectors.version}, ${vectors.vectors.length} host_behavior vectors)`,
  );
}

main();
