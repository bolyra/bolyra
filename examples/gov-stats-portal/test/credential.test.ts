import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { derivePublicKey, eddsaVerify } from '@bolyra/sdk';
import { bindingDigest } from '@bolyra/mpp';
import { OPERATOR_PRIV, GOLDEN_OPERATOR_PUBKEY, PUBLIC_STATS_BINDING, OVERREACH_BINDING, buildPresentation, loadGolden, decodeHeader } from '../src/credential';
import { GOLDEN_REQUEST_PATH } from '../src/paths';

const sigOf = (bundle: any) => ({ R8: { x: BigInt(bundle.sig.R8.x), y: BigInt(bundle.sig.R8.y) }, S: BigInt(bundle.sig.S) });
const pub = { x: BigInt(GOLDEN_OPERATOR_PUBKEY.x), y: BigInt(GOLDEN_OPERATOR_PUBKEY.y) };

test('the public test key 42n derives the operator public key the golden proof attests', async () => {
  const d = await derivePublicKey(OPERATOR_PRIV);
  assert.equal(d.x.toString(), GOLDEN_OPERATOR_PUBKEY.x);
  assert.equal(d.y.toString(), GOLDEN_OPERATOR_PUBKEY.y);
  const golden = JSON.parse(JSON.parse(fs.readFileSync(GOLDEN_REQUEST_PATH, 'utf8')).bundle);
  assert.deepEqual(golden.agent.credential.operator_pubkey, GOLDEN_OPERATOR_PUBKEY);
});

test('P1 and P2 bindings are re-signed under 42n; the proof block is byte-identical to the golden', async () => {
  const golden = loadGolden();
  for (const binding of [PUBLIC_STATS_BINDING, OVERREACH_BINDING]) {
    const p = await buildPresentation(binding);
    assert.deepEqual(p.bundle.binding, binding);
    assert.equal(JSON.stringify(p.bundle.agent), JSON.stringify(golden.agent), 'agent block (proof + credential) untouched');
    assert.equal(p.bundle.agent.credential.permission_bitmask, '3');
    assert.equal(binding.expiry, golden.agent.credential.expiry);
    assert.equal(binding.model, 'opus-4.1');
    assert.equal(await eddsaVerify(pub, bindingDigest(binding), sigOf(p.bundle)), true);
    assert.deepEqual(p.identity, { agent_name: binding.agent_name, program: binding.program, model: binding.model });
    assert.match(p.header, /^[A-Za-z0-9_-]+$/);
    assert.deepEqual(decodeHeader(p.header), p.bundle);
    assert.equal(p.bundle.bvp, 1);
  }
  assert.deepEqual(PUBLIC_STATS_BINDING.capabilities, ['read:public-stats']);
  assert.deepEqual(OVERREACH_BINDING.capabilities, ['read:public-stats', 'read:internal-files']);
  assert.equal(PUBLIC_STATS_BINDING.project_key, 'https://stats.example.gov');
});

test('the signature is live: tampering a signed field after signing breaks verification', async () => {
  const p = await buildPresentation(PUBLIC_STATS_BINDING);
  const tampered = { ...p.bundle.binding, capabilities: ['read:public-stats', 'read:internal-files'] };
  assert.equal(await eddsaVerify(pub, bindingDigest(tampered), sigOf(p.bundle)), false);
});
