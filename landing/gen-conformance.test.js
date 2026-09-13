'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { validateRegistry, renderRegistry, checkFile, coveredClasses } = require('./gen-conformance.js');

// external-suite fixtures need no adapter on disk (validateClaim resolves
// adapters relative to interop/, so bolyra-suite fixtures must be real).
function ext(overrides = {}) {
  return {
    id: 'kit@abc/own-corpus',
    kind: 'external-suite',
    claim_text: "39/39 of the kit's own pinned corpus (NOT Bolyra-suite conformance)",
    verified_on: '2026-09-09',
    implementer: { repo: 'https://github.com/example/kit', commit: 'a'.repeat(40) },
    run: { image: 'node:20@sha256:' + 'b'.repeat(64), command: ['npm', 'test', '--silent'], network: 'none', expect: { pass: 39, run: 39, scoped_out: 9 } },
    ...overrides,
  };
}
const has = (errs, re) => errs.some((e) => re.test(e));

test('valid external-suite registry passes', () => {
  assert.deepStrictEqual(validateRegistry({ claims: [ext()] }), []);
});
test('registry-level shape errors', () => {
  assert.deepStrictEqual(validateRegistry(null), ['registry.claims must be an array']);
  assert.deepStrictEqual(validateRegistry({ claims: 'x' }), ['registry.claims must be an array']);
});
test('non-object and malformed entries are rejected without throwing', () => {
  assert.ok(has(validateRegistry({ claims: [null] }), /claim #0: not an object/));
  assert.ok(has(validateRegistry({ claims: ['str'] }), /claim #0: not an object/));
  assert.ok(has(validateRegistry({ claims: [ext({ id: 42 })] }), /id must be a non-empty string/));
  assert.ok(has(validateRegistry({ claims: [ext({ claim_text: 7 })] }), /claim_text must be a non-empty string/));
  assert.ok(has(validateRegistry({ claims: [ext({ verified_on: 20260909 })] }), /verified_on must be YYYY-MM-DD/));
  assert.ok(has(validateRegistry({ claims: [ext({ verified_on: 'yesterday' })] }), /verified_on must be YYYY-MM-DD/));
});
test('kind: absent defaults; supplied invalid (incl. falsy) is rejected', () => {
  assert.ok(has(validateRegistry({ claims: [ext({ kind: 'mystery' })] }), /unknown kind mystery/));
  assert.ok(has(validateRegistry({ claims: [ext({ kind: '' })] }), /unknown kind/));
  assert.ok(has(validateRegistry({ claims: [ext({ kind: null })] }), /unknown kind/));
});
test('duplicate ids are rejected', () => {
  assert.ok(has(validateRegistry({ claims: [ext(), ext()] }), /duplicate id kit@abc\/own-corpus/));
});
test('implementer.repo must be https://github.com/<owner>/<repo> with no dot segments', () => {
  for (const repo of ['javascript:alert(1)', 'https://evil.example/x/y', 'https://github.com/only-owner', 'http://github.com/a/b',
                      'https://github.com/./b', 'https://github.com/a/..', 'https://github.com/a/b/c', 'https://github.com/a/b?x=1']) {
    assert.ok(has(validateRegistry({ claims: [ext({ implementer: { repo, commit: 'a'.repeat(40) } })] }), /implementer\.repo/), `should reject ${repo}`);
  }
  assert.ok(has(validateRegistry({ claims: [ext({ implementer: { repo: 'https://github.com/a/b', commit: 'zz' } })] }), /implementer\.commit/));
});
test('verification_run_url is rejected in v1', () => {
  assert.ok(has(validateRegistry({ claims: [ext({ verification_run_url: 'https://github.com/bolyra/bolyra/actions/runs/1' })] }), /verification_run_url/));
});
