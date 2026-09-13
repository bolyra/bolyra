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
test('coveredClasses: from --type selectors for bolyra-suite; not applicable for external-suite', () => {
  assert.strictEqual(coveredClasses({ kind: 'bolyra-suite', suite: { runner_args: ['--type', 'host_behavior'] } }), 'host_behavior');
  assert.strictEqual(coveredClasses({ kind: 'bolyra-suite', suite: { runner_args: ['--type', 'a', '--type', 'b'] } }), 'a, b');
  assert.strictEqual(coveredClasses({ kind: 'bolyra-suite', suite: { runner_args: [] } }), 'Not specified');
  assert.strictEqual(coveredClasses({ kind: 'bolyra-suite', suite: {} }), 'Not specified');
  assert.strictEqual(coveredClasses({ kind: 'external-suite' }), 'not applicable (own corpus)');
});
test('render escapes registry strings and never interpolates markup', () => {
  const html = renderRegistry({ claims: [ext({ claim_text: '<script>alert(1)</script> & "quotes"' })] });
  assert.ok(!html.includes('<script>alert(1)</script>'));
  assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt; &amp; &quot;quotes&quot;'));
});
test('external-suite rows carry the fixed own-corpus qualifier regardless of claim_text', () => {
  const html = renderRegistry({ claims: [ext({ claim_text: 'totally conformant, trust me' })] });
  assert.ok(html.includes('Own-corpus reproduction: the implementer'));
  assert.ok(html.includes('This is NOT Bolyra-suite conformance.'));
});
test('render builds links only from validated repo + sha', () => {
  const html = renderRegistry({ claims: [ext()] });
  assert.ok(html.includes('href="https://github.com/example/kit"'));
  assert.ok(html.includes('href="https://github.com/example/kit/commit/' + 'a'.repeat(40) + '"'));
});
test('render is deterministic and ordered by verified_on desc then id (code-unit order)', () => {
  const reg = { claims: [
    ext({ id: 'b', verified_on: '2026-01-01' }), ext({ id: 'a', verified_on: '2026-01-01' }),
    ext({ id: 'c', verified_on: '2026-02-01' }), ext({ id: 'Z', verified_on: '2026-01-01' }), ext({ id: 'é', verified_on: '2026-01-01' }),
  ] };
  const html1 = renderRegistry(reg);
  const html2 = renderRegistry({ claims: [...reg.claims].reverse() });
  assert.strictEqual(html1, html2);
  const pos = (id) => html1.indexOf(`<h2 class="claim-id">${id}</h2>`);
  // 'Z' (0x5A) < 'a' (0x61) < 'b' < 'é' (0xE9): code-unit order, not locale order
  assert.ok(pos('c') < pos('Z') && pos('Z') < pos('a') && pos('a') < pos('b') && pos('b') < pos('é'));
  assert.ok(!/generated (at|on)/i.test(html1), 'no generation timestamp');
});
test('render throws on an invalid registry', () => {
  assert.throws(() => renderRegistry({ claims: [ext({ kind: 'mystery' })] }), /unknown kind/);
});
test('the real registry renders: bolyra-suite row has covered classes and suite-commit link', () => {
  const reg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'interop', 'claims.json'), 'utf8'));
  const html = renderRegistry(reg);
  assert.ok(html.includes('<th>Covered classes</th><td>host_behavior</td>'));
  assert.ok(/href="https:\/\/github\.com\/bolyra\/bolyra\/commit\/[0-9a-f]{40}"/.test(html));
  assert.ok(html.includes('This is NOT Bolyra-suite conformance.'), 'StillOS row qualifier');
});
test('checkFile: identical passes, one-byte drift fails naming the line, missing file fails', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gen-conf-'));
  const file = path.join(dir, 'conformance.html');
  const reg = { claims: [ext()] };
  fs.writeFileSync(file, renderRegistry(reg));
  assert.deepStrictEqual(checkFile(reg, file), { ok: true, diff: [] });
  fs.writeFileSync(file, renderRegistry(reg).replace('2026-09-09', '2026-09-08'));
  const r = checkFile(reg, file);
  assert.strictEqual(r.ok, false);
  assert.ok(r.diff.length >= 1 && r.diff[0].includes('2026-09-0'), r.diff.join('\n'));
  assert.strictEqual(checkFile(reg, path.join(dir, 'missing.html')).ok, false);
});
