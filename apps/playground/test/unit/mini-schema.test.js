import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { assertSupportedSchema, validate } from '../../tools/mini-schema.mjs';
import { extractEvcSpec } from '../../tools/spec-extract.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../..');
const x = extractEvcSpec(fs.readFileSync(path.join(ROOT, 'spec/external-verifier-contract-v1.md'), 'utf8'));
const cli = JSON.parse(fs.readFileSync(path.join(ROOT, 'integrations/cli/test/fixtures/verify/allow-agent-only/request.json'), 'utf8'));
const ok = (schema, inst) => assert.deepEqual(validate(schema, inst), { ok: true, errors: [] }, JSON.stringify(inst).slice(0, 80));
const bad = (schema, inst) => assert.equal(validate(schema, inst).ok, false, JSON.stringify(inst).slice(0, 80));

test('the unchanged extracted schemas are supported and every extracted example validates', () => {
  assertSupportedSchema(x.request.schema); assertSupportedSchema(x.verdict.schema);
  ok(x.request.schema, x.request.example); ok(x.request.schema, cli);
  for (const v of [x.verdict.allow, x.verdict.allowConsume, x.verdict.deny]) ok(x.verdict.schema, v);
  for (const e of x.examples) { ok(x.verdict.schema, e.verdict); if (e.request) ok(x.request.schema, e.request); }
});

test('known-bad instances are rejected', () => {
  bad(x.verdict.schema, { verdict: 'deny', code: 'scope_exceeded', message: 'm', extra: 1 });
  bad(x.verdict.schema, { verdict: 'deny', code: 'made_up', message: 'm' });
  bad(x.verdict.schema, { verdict: 'allow', consume_nonces: [] });
  bad(x.verdict.schema, { verdict: 'allow', kind: 'quantum' });
  bad(x.verdict.schema, { verdict: 'maybe' });
  bad(x.request.schema, { ...x.request.example, bundle: '' });
  bad(x.request.schema, { ...x.request.example, now_unix: 0 });
  bad(x.request.schema, { ...x.request.example, now_unix: -1 });
  bad(x.request.schema, { ...x.request.example, now_unix: '5' });
  bad(x.request.schema, { ...x.request.example, request: { ...x.request.example.request, granted_capabilities: 'x' } });
});

test('unsupported keywords anywhere in the schema tree throw; metadata keywords are accepted', () => {
  assert.throws(() => assertSupportedSchema({ type: 'object', oneOf: [{ type: 'object' }, { type: 'object', properties: { a: { type: 'string', pattern: '^x' } } }] }), /unsupported schema keyword/);
  assert.throws(() => assertSupportedSchema({ type: 'string', maxLength: 3 }), /unsupported schema keyword/);
  assert.doesNotThrow(() => assertSupportedSchema({ $schema: 'x', $id: 'y', title: 'z', type: 'string', minLength: 1 }));
});
