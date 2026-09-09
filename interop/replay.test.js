'use strict';
// Offline regression tests for the replay harness's runner-output validation.
// The load-bearing case: a runner that FAILED while its stderr happens to
// contain summary-shaped text must never be read as a green replay.
const test = require('node:test');
const assert = require('node:assert');
const { validateRunnerOutput, shellQuote } = require('./replay.js');

const CLAIM = {
  suite: {
    vector_set: '0.5.0',
    test_vectors_sha256: '879d1cf9647f4f42e0815e34eeb5587633dff28e8fa8ceab25c139f470bb629c',
  },
  expected: { pass: 27, fail: 0, skip: 0 },
};

function summary(overrides = {}) {
  return JSON.stringify({
    runner: 'bolyra-conformance',
    spec: 'external-verifier-contract-v1',
    vector_set: {
      version: '0.5.0',
      total: 104,
      selected: 27,
      sha256: CLAIM.suite.test_vectors_sha256,
      ...(overrides.vector_set || {}),
    },
    totals: { passed: 27, failed: 0, skipped: 0, ...(overrides.totals || {}) },
    results: overrides.results || [],
  });
}

test('clean run validates', () => {
  const got = validateRunnerOutput({ status: 0, signal: null, stdout: summary(), stderr: '' }, CLAIM);
  assert.deepStrictEqual(got, { pass: 27, fail: 0, skip: 0 });
});

test('false green: failing run with summary-shaped stderr must throw', () => {
  const run = {
    status: 1,
    signal: null,
    stdout: summary({ totals: { passed: 0, failed: 27, skipped: 0 } }),
    stderr: 'noise...\n27 passed, 0 failed, 0 skipped\n',
  };
  assert.throws(() => validateRunnerOutput(run, CLAIM), /runner exit status 1|REPLAY MISMATCH/);
});

test('non-JSON stdout must throw even when stderr contains a green summary', () => {
  const run = { status: 2, signal: null, stdout: '', stderr: '27 passed, 0 failed, 0 skipped\n' };
  assert.throws(() => validateRunnerOutput(run, CLAIM), /not the --json summary/);
});

test('exit 0 with failing totals is inconsistent and must throw', () => {
  const run = {
    status: 0,
    signal: null,
    stdout: summary({ totals: { passed: 26, failed: 1, skipped: 0 } }),
    stderr: '',
  };
  assert.throws(() => validateRunnerOutput(run, CLAIM), /REPLAY MISMATCH/);
});

test('exit 1 with green totals is inconsistent and must throw', () => {
  const run = { status: 1, signal: null, stdout: summary(), stderr: '' };
  assert.throws(() => validateRunnerOutput(run, CLAIM), /runner exit status 1/);
});

test('vector-set digest mismatch must throw', () => {
  const run = {
    status: 0,
    signal: null,
    stdout: summary({ vector_set: { sha256: 'deadbeef'.repeat(8) } }),
    stderr: '',
  };
  assert.throws(() => validateRunnerOutput(run, CLAIM), /digest/);
});

test('wrong selected-vector count must throw', () => {
  const run = { status: 0, signal: null, stdout: summary({ vector_set: { selected: 30 } }), stderr: '' };
  assert.throws(() => validateRunnerOutput(run, CLAIM), /selected 30 vectors, claim covers 27/);
});

test('killed runner must throw', () => {
  const run = { status: null, signal: 'SIGKILL', stdout: summary(), stderr: '' };
  assert.throws(() => validateRunnerOutput(run, CLAIM), /killed by signal/);
});

test('shellQuote survives spaces and single quotes', () => {
  assert.strictEqual(shellQuote('/tmp/a b'), "'/tmp/a b'");
  assert.strictEqual(shellQuote("/tmp/o'brien"), "'/tmp/o'\\''brien'");
});
