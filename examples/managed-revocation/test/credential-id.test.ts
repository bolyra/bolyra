import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { bindingDigest, type BindingClaim } from '@bolyra/mpp';
import { credentialId } from '../src/credential-id.js';

// The Worker's committed registration fixtures (plain JSON; nothing from its install).
interface Entry { body: { binding: unknown; operator_pubkey: { x: string; y: string } }; credential_id: string; binding_digest_hex: string }
const registrations = JSON.parse(
  readFileSync(new URL('../../../integrations/hosted-verify/test/fixtures/registrations.json', import.meta.url), 'utf8'),
) as Record<string, Entry>;

test("the local credentialId reproduces every committed hosted-verify credential_id", () => {
  for (const [name, e] of Object.entries(registrations)) {
    const pub = { x: BigInt(e.body.operator_pubkey.x), y: BigInt(e.body.operator_pubkey.y) };
    assert.equal(credentialId(pub, BigInt(`0x${e.binding_digest_hex}`)), e.credential_id, `${name}: from the committed digest`);
    assert.equal(credentialId(pub, bindingDigest(e.body.binding as BindingClaim)), e.credential_id, `${name}: from the installed @bolyra/mpp digest`);
  }
});
