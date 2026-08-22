#!/usr/bin/env node
// Host-conformance fixture: verifier returns `allow` with a single-entry
// `consume_nonces` (host nonce mode, §3.2/§8). Drives the reserve-before-act
// cases (§7.3): with an empty durable store the host reserves then allows; with
// the nonce already present the host MUST deny as replay. Offered case (5).
//
// The nonce value below is fixed so the runner can pre-seed the durable store
// for the replay scenario; it MUST match the seed used by the host-nonce
// vectors in spec/test-vectors.json.
const chunks = [];
process.stdin.on('data', c => chunks.push(c));
process.stdin.on('end', () => {
  const v = {
    verdict: 'allow',
    consume_nonces: [
      {
        issuer_key: '15617329766995256858590222302430068383949745072531974464084158078905448850943:20201653676552407165606319978171745645181779505176156736762229713293662347780',
        nonce: '1000000000000000000000000000000000000001',
        retain_until: 4102444800,
      },
    ],
  };
  process.stdout.write(JSON.stringify(v), () => process.exit(0));
});
