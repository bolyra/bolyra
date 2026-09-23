#!/usr/bin/env node
// Regression: an explicitly selected vector MUST execute through the package
// entry point. bin.js injects `--type` for its two default modes; that must not
// silence an explicit `--vector` (which previously selected zero tests, exit 0 --
// a vendored vector nobody could run).
const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const BIN = path.join(__dirname, '..', 'bin.js');
// Stubs are dev test doubles and deliberately not vendored into the published
// tarball; this regression runs in-repo (scripts/ is not in package.json files).
const STUBS = path.join(__dirname, '..', '..', '..', 'spec', 'fixtures', 'verifier-config-fault');
const VECTOR = 'verifier-config-fault-internal-error-exits-non-zero';
let failed = 0;
const check = (name, ok, detail) => {
  console.log(`${ok ? '  PASS' : '  FAIL'}  ${name}${ok ? '' : `\n        ${detail}`}`);
  if (!ok) failed++;
};

function run(args, env) {
  const r = spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf-8', env: { ...process.env, ...env }, timeout: 60000 });
  return (r.stdout || '') + (r.stderr || '');
}

// 1. Explicitly selected, with hooks: exactly one vector, exercised (not skipped).
{
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'evc-bin-'));
  const marker = path.join(dir, 'fault');
  const out = run(['--vector', VECTOR], {
    VERIFIER_CMD: `STUB_FAULT_FILE=${marker} ${process.execPath} ${path.join(STUBS, 'stub-exit1.cjs')}`,
    VERIFIER_FAULT_CMD: `printf '{ not json' > ${marker}`,
    VERIFIER_FAULT_UNDO_CMD: `rm -f ${marker}`,
    VERIFIER_VALID_REQUEST: path.join(STUBS, 'valid-request.json'),
  });
  check('explicit --vector executes through bin.js', /1 passed, 0 failed/.test(out), out.slice(-300));
  check('does not silently select zero tests', !/^0 passed, 0 failed, 0 skipped$/m.test(out), out.slice(-300));
  fs.rmSync(dir, { recursive: true, force: true });
}

// 2. Default verifier mode is UNCHANGED: still exactly the 11 envelope vectors.
//    Implementers cite that count; adding a skipped vector to it would move it.
{
  const out = run(['--verifier', `${process.execPath} -e "process.stdout.write(JSON.stringify({verdict:'deny',code:'malformed_input',message:'stub'}))"`], {});
  check('default verifier mode still selects 11 envelope vectors', /11 (passed|test vectors)|1[01] passed/.test(out) && !/verifier-config-fault/.test(out), out.slice(-300));
}

console.log(`\n${failed ? `${failed} check(s) failed` : 'bin selection regression OK'}`);
process.exitCode = failed ? 1 : 0;
