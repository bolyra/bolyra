import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { fencedJsonBlocks, extractEvcSpec, extractProfile42, EXPECTED_FENCES } from '../../tools/spec-extract.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../..');
const evc = fs.readFileSync(path.join(ROOT, 'spec/external-verifier-contract-v1.md'), 'utf8');
const profile = fs.readFileSync(path.join(ROOT, 'spec/x402-evc-profile-v0.md'), 'utf8');
const drift = (fn) => assert.throws(fn, (e) => /spec drift/.test(e.message), 'must throw spec drift');

test('committed EVC spec extracts with the expected contracts', () => {
  const x = extractEvcSpec(evc);
  assert.match(x.revision, /^\d{4}-\d{2}-\d{2}$/);
  assert.equal(x.request.example.version, 1); assert.equal(x.request.example.request.agent_name, 'research-bot');
  assert.equal(x.request.schema.$id, 'https://bolyra.ai/spec/external-verifier-request-v1.json');
  assert.deepEqual(x.verdict.allow, { verdict: 'allow' });
  assert.equal(x.verdict.allowConsume.consume_nonces.length, 1);
  assert.equal(x.verdict.deny.code, 'scope_exceeded');
  assert.equal(x.verdict.schema.$id, 'https://bolyra.ai/spec/external-verifier-verdict-v1.json');
  assert.equal(x.registry.length, 15);
  assert.deepEqual(x.registry.map((r) => r.code), x.verdict.schema.oneOf[1].properties.code.enum);
  assert.ok(x.registry.every((r) => r.meaning.length > 10));
  assert.deepEqual(x.kinds.map((k) => k.kind), ['classical', 'zk', 'external']);
  assert.deepEqual(x.kinds.map((k) => k.kind), x.verdict.schema.oneOf[0].properties.kind.enum);
  assert.equal(x.examples.length, 8);
  assert.deepEqual(x.examples.map((e) => e.id), ['13.1', '13.2', '13.3', '13.4', '13.5', '13.6', '13.7', '13.8']);
  assert.equal(x.examples[0].request.version, 1); assert.deepEqual(x.examples[0].verdict, { verdict: 'allow' });
  assert.equal(x.examples[5].verdict.code, 'internal_error'); assert.match(x.examples[5].notes, /non-zero exit/i);
  assert.match(x.examples[4].notes, /stdin/i);
  assert.equal(x.examples[7].verdict.kind, 'external');
  assert.equal(x.omittedKindMeans, 'zk');
  assert.equal(fencedJsonBlocks(evc).length, Object.values(EXPECTED_FENCES).reduce((a, b) => a + b, 0));
});

test('committed profile §4.2 extracts five labelled paragraphs, nine MUSTs in order, and the example', () => {
  const p = extractProfile42(profile);
  assert.match(p.applicability, /^A 402 leg whose payTo is a placeholder/);
  assert.match(p.role, /^An agent-side host is a payer-side enforcement point/);
  assert.match(p.localContext, /^The server issues no x402-evc-nonce/);
  assert.equal(p.hostMusts.length, 9);
  assert.match(p.hostMusts[0], /^Public keys are provisioned out of band/);
  assert.match(p.hostMusts[6], /^\(iss, jti\) is single-use/);
  assert.match(p.mustNotClaim, /does NOT establish/);
  assert.match(p.example, /differed on every call/);
  assert.ok(!/\*\*/.test(p.role) && !/`/.test(p.role), 'emphasis and backticks stripped');
});

test('mutations throw spec drift', () => {
  const dup = evc.replace('### 3.4 Verdict JSON Schema', '### 3.4 Verdict JSON Schema\n\ndummy\n\n### 3.4 Verdict JSON Schema');
  drift(() => extractEvcSpec(dup));
  const unterminated = evc.replace('```json\n{ "verdict": "allow" }\n```', '```json\n{ "verdict": "allow" }\n');
  drift(() => fencedJsonBlocks(unterminated));
  const rowGone = evc.replace(/\| `nonce_missing` \|[^\n]*\n/, '');
  drift(() => extractEvcSpec(rowGone));
  const enum16 = evc.replace('"internal_error"\n', '"internal_error",\n            "made_up"\n');
  drift(() => extractEvcSpec(enum16));
  const kindDiff = evc.replace('"enum": ["classical", "zk", "external"] },\n        "consume_nonces"', '"enum": ["classical", "zk"] },\n        "consume_nonces"');
  drift(() => extractEvcSpec(kindDiff));
  const brokenFence = evc.replace('{ "verdict": "allow" }', '{ "verdict": "allow" ');
  drift(() => fencedJsonBlocks(brokenFence));
  const typeChanged = evc.replace('"now_unix": 1751990400 }', '"now_unix": "1751990400" }');
  drift(() => extractEvcSpec(typeChanged));
  const exampleGone = evc.replace(/### 13\.6 Deny — `internal_error`[\s\S]*?(?=### 13\.7)/, '### 13.6 Deny — `internal_error` (fail-closed, non-zero exit)\n\nnothing here\n\n');
  drift(() => extractEvcSpec(exampleGone));
  drift(() => extractProfile42(profile.replace('(9) The extension records', 'The extension records')));
  drift(() => extractProfile42(profile.replace('(4) The token `aud`', '(3) The token `aud`')));
  drift(() => extractProfile42(profile.replace('\n\n**Role.**', ' **Role.**')));
  drift(() => extractProfile42(profile.replace('**MUST NOT claim.**', '**Must not claim.**')));
});
