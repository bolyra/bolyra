// Generates test/fixtures/mandate.json for hosted-verify: two presentations of ONE
// mpp-issued spend mandate (same signed binding, fresh nullifier each), the verifier
// request that presents it, and the registration body for the same binding.
// Run against the PUBLISHED package, never a source checkout:
//   1. copy this script to an empty directory
//   2. npm install @bolyra/mpp@0.5.0
//   3. node generate-mandate.cjs > mandate.json
//   4. copy mandate.json back to integrations/hosted-verify/test/fixtures/
// The checked-in mandate.json is the source of truth; do not regenerate it casually —
// EdDSA-Poseidon signing is deterministic but the nullifiers are random, so
// regeneration yields new presentations of the same binding.
const { issueMandate, parseBundle, MPP_CAPABILITY_MAP } = require('@bolyra/mpp');
const OPERATOR_PRIV = 42n; // the repo's test-only operator scalar (same key as the CLI fixtures)
const common = { operatorPrivateKey: OPERATOR_PRIV, agentName: 'mandate-agent', audience: 'api.merchant.example', model: 'opus-4.1', tier: 'small', expiry: 4102444800, encoding: 'json' };
(async () => {
  const a = await issueMandate(common);
  const b = await issueMandate(common);
  const pa = parseBundle(a.presentation), pb = parseBundle(b.presentation);
  if (JSON.stringify(pa.binding) !== JSON.stringify(pb.binding)) throw new Error('bindings differ');
  if (pa.agent.envelope.publicSignals[1] === pb.agent.envelope.publicSignals[1]) throw new Error('nullifiers equal');
  const request = (presentation) => ({ version: 1, bundle: presentation, request: { agent_name: common.agentName, project_key: common.audience, program: 'mpp', model: common.model, granted_capabilities: ['mpp:financial:small'] }, now_unix: 1800000000 });
  const registration = { version: 1, binding: pa.binding, signature: { R8: { x: pa.sig.R8.x, y: pa.sig.R8.y }, S: pa.sig.S }, operator_pubkey: a.operatorPublicKey };
  console.log(JSON.stringify({ capability_map: MPP_CAPABILITY_MAP, operator_key: `${a.operatorPublicKey.x}:${a.operatorPublicKey.y}`, registration, request_a: request(a.presentation), request_b: request(b.presentation) }, null, 2));
})().catch((e) => { console.error('ERR', e); process.exit(1); });
