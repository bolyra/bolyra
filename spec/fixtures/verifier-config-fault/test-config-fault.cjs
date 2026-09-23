#!/usr/bin/env node
// Tests the runner's `verifier_config_fault` class against stub verifiers.
// Stubs exercise the RUNNER's assertion; the real red/green proof runs against
// an external implementation (see CONFIG-FAULT.md).
const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const RUNNER = path.join(__dirname, '..', '..', 'conformance-runner.js');
const HERE = __dirname;
const VECTOR = 'verifier-config-fault-internal-error-exits-non-zero';

function runSuite(env) {
  const res = spawnSync(process.execPath, [RUNNER, '--vector', VECTOR], {
    encoding: 'utf-8', env: { ...process.env, ...env }, timeout: 60000,
  });
  return (res.stdout || '') + (res.stderr || '');
}

function stubEnv(stub) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'evc-cf-'));
  const marker = path.join(dir, 'fault');
  return {
    dir,
    env: {
      STUB_FAULT_FILE: marker,
      VERIFIER_CMD: `STUB_FAULT_FILE=${marker} ${process.execPath} ${path.join(HERE, stub)}`,
      VERIFIER_FAULT_CMD: `printf '{ not json' > ${marker}`,
      VERIFIER_FAULT_UNDO_CMD: `rm -f ${marker}`,
      VERIFIER_VALID_REQUEST: path.join(HERE, 'valid-request.json'),
    },
  };
}

const cases = [];
function check(name, cond, detail) {
  cases.push({ name, ok: !!cond, detail });
  console.log(`${cond ? '  PASS' : '  FAIL'}  ${name}${cond ? '' : `\n        ${detail}`}`);
}

// 1. A verifier that exits 0 on internal_error must FAIL the vector.
{
  const { dir, env } = stubEnv('stub-exit0.cjs');
  const out = runSuite(env);
  check('exit-0 internal_error FAILS the vector', /1 failed|: FAIL/.test(out) && !/0 failed/.test(out), out.slice(-400));
  fs.rmSync(dir, { recursive: true, force: true });
}

// 2. A verifier that exits non-zero on internal_error must PASS the vector.
{
  const { dir, env } = stubEnv('stub-exit1.cjs');
  const out = runSuite(env);
  check('non-zero-exit internal_error PASSES the vector', /1 passed, 0 failed/.test(out), out.slice(-400));
  fs.rmSync(dir, { recursive: true, force: true });
}

// 3. No fault hooks supplied: SKIP, never FAIL. An implementation that cannot
//    express a config fault must not be reported as non-conforming.
{
  const out = runSuite({
    VERIFIER_CMD: `${process.execPath} ${path.join(HERE, 'stub-exit1.cjs')}`,
    VERIFIER_FAULT_CMD: '', VERIFIER_FAULT_UNDO_CMD: '', VERIFIER_VALID_REQUEST: '',
  });
  check('missing fault hooks SKIP rather than fail', /1 skipped/.test(out) && !/1 failed/.test(out), out.slice(-400));
}

const failed = cases.filter(c => !c.ok).length;
console.log(`\n${cases.length - failed}/${cases.length} runner checks passed`);
process.exitCode = failed ? 1 : 0;
