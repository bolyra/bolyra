#!/usr/bin/env node
/**
 * Interop replay harness: mechanically re-verify every published external
 * interop claim (interop/claims.json) at its exact pins.
 *
 * For each claim:
 *   1. clone the implementer's repo at its pinned commit (shallow fetch by sha)
 *   2. materialize OUR conformance suite at the claim's suite commit
 *      (git archive from this repo — requires full history, not a shallow clone)
 *   3. verify the suite's test-vectors.json sha256 against the pinned digest
 *   4. install the implementer's dependencies from its own lockfile
 *      (--ignore-scripts: no lifecycle scripts from third-party trees)
 *   5. run the pinned runner against the implementer's host via the committed
 *      HUT adapter, and compare pass/fail/skip counts to the published claim
 *
 * A red replay means INVESTIGATE — never edit the claim to match. Claims are
 * historical statements pinned to commits; if a replay breaks, either the
 * environment changed (fix the harness) or the claim was wrong (correct the
 * published record everywhere it appears, loudly).
 *
 * Usage:
 *   node interop/replay.js               # replay every claim
 *   node interop/replay.js --claim <id>  # replay one claim
 *   node interop/replay.js --check      # offline: validate registry + pins
 *   node interop/replay.js --keep       # keep workdirs for inspection
 */
'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFileSync, spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const CLAIMS = JSON.parse(fs.readFileSync(path.join(__dirname, 'claims.json'), 'utf8'));

const args = process.argv.slice(2);
const flag = (name) => args.includes(name);
const opt = (name) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : null;
};

function sh(cmd, cmdArgs, options = {}) {
  return execFileSync(cmd, cmdArgs, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], ...options });
}

function fail(msg) {
  process.stderr.write(`replay: ${msg}\n`);
  process.exitCode = 1;
}

// POSIX-shell single-quote a path for the runner's `sh -c` --host command.
function shellQuote(s) {
  return `'${String(s).replace(/'/g, "'\\''")}'`;
}

function sha256File(p) {
  return crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
}

function validateClaim(c) {
  const errors = [];
  const kind = c.kind || 'bolyra-suite';
  if (c.implementer && !/^[0-9a-f]{40}$/.test(c.implementer.commit || '')) {
    errors.push('implementer.commit must be a full 40-hex sha');
  }

  if (kind === 'external-suite') {
    // The implementer's OWN suite replayed at pins. Result is an own-corpus
    // reproduction, never Bolyra-suite conformance — claim_text must say so.
    for (const k of ['id', 'implementer', 'run']) {
      if (!c[k]) errors.push(`missing field ${k}`);
    }
    const run = c.run || {};
    if (!/@sha256:[0-9a-f]{64}$/.test(run.image || '')) {
      errors.push('run.image must be digest-pinned (image@sha256:<64-hex>)');
    }
    if (!Array.isArray(run.command) || !run.command.length) {
      errors.push('run.command must be a non-empty argv array');
    }
    if (run.network !== 'none') {
      errors.push('run.network must be "none" (third-party code executes here)');
    }
    if (!run.expect || typeof run.expect.pass !== 'number' || typeof run.expect.run !== 'number') {
      errors.push('run.expect must carry numeric pass and run counts');
    }
    return errors;
  }

  for (const k of ['id', 'implementer', 'suite', 'adapter', 'adapter_sha256', 'expected']) {
    if (!c[k]) errors.push(`missing field ${k}`);
  }
  if (c.suite && !/^[0-9a-f]{40}$/.test(c.suite.commit || '')) {
    errors.push('suite.commit must be a full 40-hex sha');
  }
  if (c.suite && !/^[0-9a-f]{64}$/.test(c.suite.test_vectors_sha256 || '')) {
    errors.push('suite.test_vectors_sha256 must be a full sha256 hex digest');
  }
  if (c.adapter) {
    const adapterPath = path.join(__dirname, c.adapter);
    if (!fs.existsSync(adapterPath)) {
      errors.push(`adapter file not found: ${c.adapter}`);
    } else if (c.adapter_sha256 && sha256File(adapterPath) !== c.adapter_sha256) {
      // The adapter is part of the claim's pin chain: what bridged the HUT
      // convention to the implementer is as load-bearing as the commits.
      errors.push(`adapter digest mismatch: ${c.adapter} does not hash to adapter_sha256`);
    }
  }
  return errors;
}

/**
 * Validate a spawnSync result from an external-suite run (the implementer's
 * OWN test command inside a network-isolated, digest-pinned container).
 * Requirements, all fail-loud: no spawn error/signal, exit status 0, a final
 * machine-readable summary line "<pass>/<run> passed, <n> explicitly scoped
 * out" whose counts equal the claim's expectation, and no FAIL-marked line
 * anywhere in the output. Returns {pass, run, scoped_out} on success.
 */
function validateExternalSuiteOutput(run, c) {
  if (run.error) throw new Error(`container spawn failed: ${run.error.message}`);
  if (run.signal) throw new Error(`suite run killed by signal ${run.signal}`);
  const out = String(run.stdout || '');
  const err = String(run.stderr || '');
  if (run.status !== 0) {
    throw new Error(`suite exited ${run.status} (expected 0); tail:\n${(out + err).slice(-2000)}`);
  }
  // Exactly one full-line summary, and it must be the final non-empty line of
  // stdout — a summary embedded in diagnostics, or an earlier green summary
  // followed by a conflicting one, is not a result.
  const summaryRe = /^(\d+)\/(\d+) passed, (\d+) explicitly scoped out.*$/gm;
  const matches = Array.from(out.matchAll(summaryRe));
  if (matches.length === 0) {
    throw new Error(`no machine-readable summary line in suite stdout; tail:\n${out.slice(-2000)}`);
  }
  if (matches.length > 1) {
    throw new Error(`multiple summary lines in suite stdout (${matches.length}); refusing to pick one`);
  }
  const lines = out.split('\n').map((l) => l.trim()).filter(Boolean);
  if (lines[lines.length - 1] !== matches[0][0].trim()) {
    throw new Error(`summary line is not the final line of suite stdout; tail:\n${out.slice(-2000)}`);
  }
  const got = { pass: Number(matches[0][1]), run: Number(matches[0][2]), scoped_out: Number(matches[0][3]) };
  const exp = c.run.expect;
  if (got.pass !== exp.pass || got.run !== exp.run || (exp.scoped_out !== undefined && got.scoped_out !== exp.scoped_out)) {
    throw new Error(
      `REPLAY MISMATCH: expected ${exp.pass}/${exp.run} passed (${exp.scoped_out} scoped out), ` +
        `got ${got.pass}/${got.run} (${got.scoped_out})`
    );
  }
  if (/^\s*FAIL\s/m.test(out) || /^\s*FAIL\s/m.test(err)) {
    throw new Error(`suite output contains FAIL-marked cases despite green summary:\n${(out + err).slice(-2000)}`);
  }
  return got;
}

function replayExternalSuite(c, keep) {
  console.log(`\n=== ${c.id} ===`);
  console.log(`claim: ${c.claim_text} (verified ${c.verified_on})`);

  const docker = spawnSync('docker', ['version', '--format', '{{.Server.Version}}'], { encoding: 'utf8' });
  if (docker.status !== 0) throw new Error('docker is required for external-suite claims and is not available');

  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'evc-replay-ext-'));
  const implDir = path.join(work, 'implementer');
  fs.mkdirSync(implDir);
  try {
    console.log(`cloning ${c.implementer.repo} @ ${c.implementer.commit.slice(0, 12)}…`);
    sh('git', ['-C', implDir, 'init', '-q']);
    sh('git', ['-C', implDir, 'remote', 'add', 'origin', c.implementer.repo]);
    sh('git', ['-C', implDir, 'fetch', '-q', '--depth', '1', 'origin', c.implementer.commit]);
    sh('git', ['-C', implDir, 'checkout', '-q', 'FETCH_HEAD']);
    const head = sh('git', ['-C', implDir, 'rev-parse', 'HEAD']).trim();
    if (head !== c.implementer.commit) throw new Error(`checked-out HEAD ${head} != pinned commit`);

    if (c.run.requires_zero_dependencies) {
      const pkg = JSON.parse(fs.readFileSync(path.join(implDir, 'package.json'), 'utf8'));
      const deps = Object.keys(pkg.dependencies || {}).concat(Object.keys(pkg.devDependencies || {}));
      if (deps.length) throw new Error(`claim requires zero dependencies but package.json declares: ${deps.join(', ')}`);
    }

    console.log(`running suite in ${c.run.image.split('@')[0]} (network ${c.run.network})…`);
    const run = spawnSync(
      'docker',
      ['run', '--rm', '--network', c.run.network, '-v', `${implDir}:/kit:ro`, '-w', '/kit', c.run.image, ...c.run.command],
      { encoding: 'utf8' }
    );
    const got = validateExternalSuiteOutput(run, c);
    console.log(`result: ${got.pass}/${got.run} passed, ${got.scoped_out} scoped out`);
    console.log(`REPLAY OK: own-corpus claim reproduces (${got.pass}/${c.run.expect.pass})`);
    return true;
  } finally {
    if (keep) console.log(`workdir kept: ${work}`);
    else fs.rmSync(work, { recursive: true, force: true });
  }
}

/**
 * Validate a spawnSync result from the pinned runner in --json mode against a
 * claim. stdout must be the runner's machine-readable summary (human progress
 * goes to stderr in --json mode, so stderr text can never fake a result), the
 * vector-set version/digest must match the claim's pins, the selected-vector
 * count must equal the claim's total, the exit status must be consistent with
 * the expected totals (runner: 0 iff no failures, 1 on failures), and the
 * totals must equal the published claim. Throws with diagnostics on any
 * mismatch; returns {pass, fail, skip} on success.
 */
function validateRunnerOutput(run, c) {
  if (run.error) throw new Error(`runner spawn failed: ${run.error.message}`);
  if (run.signal) throw new Error(`runner killed by signal ${run.signal}`);

  let parsed;
  try {
    parsed = JSON.parse(run.stdout);
  } catch {
    throw new Error(
      `runner stdout is not the --json summary (exit ${run.status}); stderr tail:\n` +
        String(run.stderr || '').slice(-2000)
    );
  }
  if (parsed.runner !== 'bolyra-conformance') {
    throw new Error(`unexpected runner identity: ${JSON.stringify(parsed.runner)}`);
  }
  const vs = parsed.vector_set || {};
  if (vs.version !== c.suite.vector_set) {
    throw new Error(`runner loaded vector set ${vs.version}, claim pins ${c.suite.vector_set}`);
  }
  if (vs.sha256 !== c.suite.test_vectors_sha256) {
    throw new Error(`runner loaded vectors with digest ${vs.sha256}, claim pins ${c.suite.test_vectors_sha256}`);
  }

  const exp = c.expected;
  const expectedTotal = exp.pass + exp.fail + exp.skip;
  if (vs.selected !== expectedTotal) {
    throw new Error(`runner selected ${vs.selected} vectors, claim covers ${expectedTotal}`);
  }

  const got = parsed.totals || {};
  const expectedStatus = exp.fail > 0 ? 1 : 0;
  if (run.status !== expectedStatus) {
    throw new Error(
      `runner exit status ${run.status}, expected ${expectedStatus} for a claim of ` +
        `${exp.pass}/${exp.fail}/${exp.skip}; totals reported: ${JSON.stringify(got)}`
    );
  }
  if (got.passed !== exp.pass || got.failed !== exp.fail || got.skipped !== exp.skip) {
    const failures = (parsed.results || []).filter((r) => r && r.status === 'FAIL');
    throw new Error(
      `REPLAY MISMATCH: expected ${exp.pass}/${exp.fail}/${exp.skip}, ` +
        `got ${got.passed}/${got.failed}/${got.skipped}\n` +
        JSON.stringify(failures.slice(0, 10), null, 1)
    );
  }
  return { pass: got.passed, fail: got.failed, skip: got.skipped };
}

// Offline pin check: the suite commit must exist locally and its
// test-vectors.json must hash to the pinned digest.
function checkSuitePin(c) {
  let raw;
  try {
    raw = execFileSync('git', ['-C', ROOT, 'show', `${c.suite.commit}:spec/test-vectors.json`]);
  } catch (e) {
    return `suite commit ${c.suite.commit.slice(0, 12)} not present locally (need full history: git fetch --unshallow)`;
  }
  const digest = crypto.createHash('sha256').update(raw).digest('hex');
  if (digest !== c.suite.test_vectors_sha256) {
    return `test-vectors.json digest mismatch at suite pin: got ${digest}`;
  }
  const version = JSON.parse(raw.toString('utf8')).version;
  if (version !== c.suite.vector_set) {
    return `vector set mismatch at suite pin: got ${version}, claim says ${c.suite.vector_set}`;
  }
  return null;
}

function replayClaim(c, keep) {
  console.log(`\n=== ${c.id} ===`);
  console.log(`claim: ${c.claim_text} (verified ${c.verified_on})`);

  const pinErr = checkSuitePin(c);
  if (pinErr) throw new Error(pinErr);
  console.log(`suite pin OK: set ${c.suite.vector_set}, digest ${c.suite.test_vectors_sha256.slice(0, 12)}…`);

  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'evc-replay-'));
  const implDir = path.join(work, 'implementer');
  const suiteDir = path.join(work, 'suite');
  fs.mkdirSync(implDir);
  fs.mkdirSync(suiteDir);

  try {
    // 1. Implementer at pin (shallow fetch by sha — works on GitHub).
    console.log(`cloning ${c.implementer.repo} @ ${c.implementer.commit.slice(0, 12)}…`);
    sh('git', ['-C', implDir, 'init', '-q']);
    sh('git', ['-C', implDir, 'remote', 'add', 'origin', c.implementer.repo]);
    sh('git', ['-C', implDir, 'fetch', '-q', '--depth', '1', 'origin', c.implementer.commit]);
    sh('git', ['-C', implDir, 'checkout', '-q', 'FETCH_HEAD']);

    // 2. Our suite at its pin.
    const tar = path.join(work, 'suite.tar');
    fs.writeFileSync(tar, execFileSync('git', ['-C', ROOT, 'archive', c.suite.commit, 'spec']));
    sh('tar', ['-x', '-f', tar, '-C', suiteDir]);

    // 3. Re-verify the digest on the materialized tree (defense in depth).
    const materialized = crypto
      .createHash('sha256')
      .update(fs.readFileSync(path.join(suiteDir, 'spec', 'test-vectors.json')))
      .digest('hex');
    if (materialized !== c.suite.test_vectors_sha256) {
      throw new Error(`materialized suite digest mismatch: ${materialized}`);
    }

    // 4. Implementer install from its own lockfile, no lifecycle scripts.
    console.log(`installing implementer deps (${c.implementer.install.join(' ')})…`);
    const install = spawnSync(c.implementer.install[0], c.implementer.install.slice(1), {
      cwd: implDir,
      encoding: 'utf8',
    });
    if (install.status !== 0) {
      throw new Error(`implementer install failed:\n${(install.stderr || '').slice(-2000)}`);
    }

    // 5. Run the pinned runner via the committed adapter, under the
    //    implementer's own tsx.
    const tsx = path.join(implDir, 'node_modules', '.bin', 'tsx');
    if (!fs.existsSync(tsx)) throw new Error('implementer install did not produce node_modules/.bin/tsx');
    const adapter = path.join(__dirname, c.adapter);
    if (sha256File(adapter) !== c.adapter_sha256) {
      throw new Error(`adapter digest mismatch at run time: ${c.adapter}`);
    }
    const runner = path.join(suiteDir, 'spec', 'conformance-runner.js');
    console.log('running pinned conformance suite against implementer host…');
    const run = spawnSync(
      process.execPath,
      [runner, ...c.suite.runner_args, '--json', '--host', `${shellQuote(tsx)} ${shellQuote(adapter)}`],
      { cwd: suiteDir, encoding: 'utf8', env: { ...process.env, EVC_IMPL_DIR: implDir } }
    );
    const got = validateRunnerOutput(run, c);
    console.log(`result: ${got.pass} passed, ${got.fail} failed, ${got.skip} skipped`);
    console.log(`REPLAY OK: published claim reproduces (${got.pass}/${c.expected.pass})`);
    return true;
  } finally {
    if (keep) console.log(`workdir kept: ${work}`);
    else fs.rmSync(work, { recursive: true, force: true });
  }
}

function main() {
  const only = opt('--claim');
  const claims = CLAIMS.claims.filter((c) => !only || c.id === only);
  if (!claims.length) {
    fail(only ? `no claim with id ${only}` : 'claims.json has no claims');
    return;
  }

  let allValid = true;
  for (const c of claims) {
    const errors = validateClaim(c);
    if (errors.length) {
      allValid = false;
      fail(`${c.id || '<no id>'}: ${errors.join('; ')}`);
    }
  }
  if (!allValid) return;

  if (flag('--check')) {
    for (const c of claims) {
      if ((c.kind || 'bolyra-suite') === 'external-suite') {
        console.log(`${c.id}: registry OK (external-suite; pins verified at replay time)`);
        continue;
      }
      const pinErr = checkSuitePin(c);
      if (pinErr) fail(`${c.id}: ${pinErr}`);
      else console.log(`${c.id}: registry + suite pin OK`);
    }
    return;
  }

  let ok = 0;
  for (const c of claims) {
    try {
      const replay = (c.kind || 'bolyra-suite') === 'external-suite' ? replayExternalSuite : replayClaim;
      if (replay(c, flag('--keep'))) ok += 1;
    } catch (e) {
      fail(`${c.id}: ${e.message}`);
    }
  }
  console.log(`\n${ok}/${claims.length} claims reproduced`);
  if (ok !== claims.length) process.exitCode = 1;
}

module.exports = { validateRunnerOutput, validateClaim, validateExternalSuiteOutput, shellQuote };

if (require.main === module) main();
