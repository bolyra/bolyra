// Installed-package agreement (backlog E10). Runs under plain Node, not the workers pool:
// the pool cannot load @bolyra/mpp (node:crypto, Buffer, its own nested @bolyra/receipts).
//
// The binding digest and the capability map are implemented twice: in this Worker
// (src/verify/binding.ts; the CAPABILITY_MAP var that src/verify/capabilities.ts reads)
// and in the published @bolyra/mpp that operators issue mandates with.
// test/fixtures/*.json pin this Worker's side
// (test/fixtures.spec.ts); these tests pin the INSTALLED @bolyra/mpp to the same committed
// values, so a drift in either package fails a test instead of turning every real
// registration into "not registered".
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const mpp = require('@bolyra/mpp');
const fixture = (name) => JSON.parse(readFileSync(new URL(`../test/fixtures/${name}`, import.meta.url), 'utf8'));
const registrations = fixture('registrations.json');
const mandate = fixture('mandate.json');

test('installed @bolyra/mpp bindingDigest matches every committed binding_digest_hex', () => {
  const entries = Object.entries(registrations);
  assert.ok(entries.length > 0, 'registrations.json has no entries');
  for (const [name, entry] of entries) {
    const hex = mpp.bindingDigest(entry.body.binding).toString(16).padStart(64, '0');
    assert.equal(hex, entry.binding_digest_hex, `registrations.json "${name}": installed @bolyra/mpp bindingDigest disagrees with the committed digest`);
  }
});

test('installed @bolyra/mpp MPP_CAPABILITY_MAP equals mandate.json capability_map', () => {
  assert.deepEqual(mpp.MPP_CAPABILITY_MAP, mandate.capability_map);
});

test('installed @bolyra/mpp version equals the exact devDependency pin', () => {
  const pin = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).devDependencies?.['@bolyra/mpp'];
  assert.match(pin ?? '', /^\d+\.\d+\.\d+$/, 'package.json must pin @bolyra/mpp to an exact version');
  assert.equal(require('@bolyra/mpp/package.json').version, pin);
});
