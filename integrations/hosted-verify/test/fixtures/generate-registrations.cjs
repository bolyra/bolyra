// Regenerates test/fixtures/registrations.json: registration bodies signed with the
// repo's test-only operator scalars (42n = the conformance-fixture operator; 43n = an
// operator no tenant trusts; the org-b scalar from test/tenants-fixture.ts), each with
// its expected credential id computed independently with node:crypto.
//   cd integrations/hosted-verify && node test/fixtures/generate-registrations.cjs > test/fixtures/registrations.json
// Needs @bolyra/sdk in node_modules (it signs with circomlibjs, Node only).
const { createHash } = require('node:crypto');
const sdk = require('@bolyra/sdk');
const { canonicalize } = require('@bolyra/receipts');
const { BN254_FIELD_ORDER } = require('@bolyra/sdk/dist/identity.js');
const BINDING_DST = 'bolyra.external-verifier.binding.v2';
const bindingDigest = (binding) => {
  const payload = Buffer.concat([Buffer.from(BINDING_DST, 'utf8'), Buffer.from([0]), Buffer.from(canonicalize(binding), 'utf8')]);
  return BigInt('0x' + createHash('sha256').update(payload).digest('hex')) % BN254_FIELD_ORDER;
};
const ID_DST = Buffer.concat([Buffer.from('bolyra:managed-credential-id:v1', 'utf8'), Buffer.from([0])]);
const lp = (b) => { const l = Buffer.alloc(4); l.writeUInt32BE(b.length, 0); return Buffer.concat([l, b]); };
const be32 = (big) => Buffer.from(big.toString(16).padStart(64, '0'), 'hex');
const credentialId = (K, B) => createHash('sha256').update(Buffer.concat([ID_DST, lp(Buffer.from(K, 'utf8')), lp(be32(B))])).digest('hex');
const FIXTURE_KEY = '15617329766995256858590222302430068383949745072531974464084158078905448850943:20201653676552407165606319978171745645181779505176156736762229713293662347780';
const ORG_B_SCALAR = 0x6f7267622d746573742d6f6e6c792d6f70657261746f722d6b65792d30310000n;
(async () => {
  const keyOf = async (priv) => { const p = await sdk.derivePublicKey(priv); const x = Array.isArray(p) ? p[0] : p.x, y = Array.isArray(p) ? p[1] : p.y; return { x: String(x), y: String(y) }; };
  const k42 = await keyOf(42n), k43 = await keyOf(43n), kB = await keyOf(ORG_B_SCALAR);
  console.error('42n == fixture key:', `${k42.x}:${k42.y}` === FIXTURE_KEY);
  const mk = async (name, binding, priv, pub) => {
    const d = bindingDigest(binding);
    const sig = await sdk.eddsaSign(priv, d);
    const R8 = Array.isArray(sig.R8) ? { x: String(sig.R8[0]), y: String(sig.R8[1]) } : { x: String(sig.R8.x), y: String(sig.R8.y) };
    const S = String(sig.S);
    return [name, { body: { version: 1, binding, signature: { R8, S }, operator_pubkey: pub }, credential_id: credentialId(`${pub.x}:${pub.y}`, d), binding_digest_hex: d.toString(16).padStart(64, '0') }];
  };
  const base = { agent_name: 'reg-agent', project_key: 'api.merchant.example', program: 'mpp', model: 'opus-4.1', capabilities: ['fetch_inbox'], expiry: 4102444800 };
  const out = Object.fromEntries(await Promise.all([
    mk('valid', base, 42n, k42),
    mk('valid2', { ...base, agent_name: 'reg-agent-2' }, 42n, k42),
    mk('expired', { ...base, agent_name: 'reg-agent-expired', expiry: 1600000000 }, 42n, k42),
    mk('untrusted', base, 43n, k43),
    mk('orgB', { ...base, agent_name: 'reg-agent-b' }, ORG_B_SCALAR, kB),
    mk('injection', { ...base, agent_name: "'); DROP TABLE credentials;--" }, 42n, k42),
  ]));
  console.log(JSON.stringify(out, null, 2));
})().catch((e) => { console.error('ERR', e); process.exit(1); });
