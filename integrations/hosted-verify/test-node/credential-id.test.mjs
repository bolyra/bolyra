// The Node-side credential-id library (scripts/lib/credential-id.mjs) against the Worker's
// committed fixtures: every registrations.json entry's credential_id must come out of the
// library from its operator key and binding digest — both the committed digest and the one
// the installed @bolyra/mpp recomputes from the binding. scripts/verify-deploy.mjs derives
// the canary id with this library before registering, so a drift here would make it report
// every deploy as broken (or, worse, clean up the wrong id).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { credentialId } from '../scripts/lib/credential-id.mjs';

const require = createRequire(import.meta.url);
const mpp = require('@bolyra/mpp');
const registrations = JSON.parse(readFileSync(new URL('../test/fixtures/registrations.json', import.meta.url), 'utf8'));

const pointOf = (entry) => ({ x: BigInt(entry.body.operator_pubkey.x), y: BigInt(entry.body.operator_pubkey.y) });

test('credentialId reproduces every committed credential_id from the committed binding digest', () => {
  const entries = Object.entries(registrations);
  assert.ok(entries.length > 0, 'registrations.json has no entries');
  for (const [name, entry] of entries) {
    assert.equal(credentialId(pointOf(entry), BigInt('0x' + entry.binding_digest_hex)), entry.credential_id, `registrations.json "${name}"`);
  }
});

test('credentialId reproduces every committed credential_id from the installed @bolyra/mpp bindingDigest', () => {
  for (const [name, entry] of Object.entries(registrations)) {
    assert.equal(credentialId(pointOf(entry), mpp.bindingDigest(entry.body.binding)), entry.credential_id, `registrations.json "${name}"`);
  }
});

test('credentialId rejects a digest outside [0, 2^256) and emits lowercase hex', () => {
  const p = pointOf(registrations.valid);
  assert.throws(() => credentialId(p, -1n), RangeError);
  assert.throws(() => credentialId(p, 1n << 256n), RangeError);
  assert.match(credentialId(p, (1n << 256n) - 1n), /^[0-9a-f]{64}$/);
});
