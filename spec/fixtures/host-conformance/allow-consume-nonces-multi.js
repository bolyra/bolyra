#!/usr/bin/env node
// Host-conformance fixture: verifier returns `allow` with a TWO-entry
// `consume_nonces` (host nonce mode, §3.2/§8). Drives the "reserve EVERY entry"
// case (§7.3): when only the second nonce is already reserved, ANY conflict is a
// replay, so the host MUST deny — proving it reserves the whole list, not just
// the first entry. Offered case (5).
//
// The nonce values below are fixed so the runner can pre-seed the durable store;
// they MUST match the seeds used by the host-nonce vectors in
// spec/test-vectors.json.
const chunks = [];
process.stdin.on('data', c => chunks.push(c));
process.stdin.on('end', () => {
  const issuer_key = '15617329766995256858590222302430068383949745072531974464084158078905448850943:20201653676552407165606319978171745645181779505176156736762229713293662347780';
  const v = {
    verdict: 'allow',
    consume_nonces: [
      { issuer_key, nonce: '1000000000000000000000000000000000000001', retain_until: 4102444800 },
      { issuer_key, nonce: '2000000000000000000000000000000000000002', retain_until: 4102444800 },
    ],
  };
  process.stdout.write(JSON.stringify(v), () => process.exit(0));
});
