#!/usr/bin/env node
// Host-conformance fixture: verifier writes an `allow` with an EMPTY
// `consume_nonces` array. The §3.4 schema requires minItems:1 (the key is
// omitted entirely when there is nothing to burn, §3.2), so the host MUST fail
// closed (§7.2). Offered case (1) intersecting case (5): a malformed nonce
// instruction.
process.stdin.resume();
process.stdin.on('end', () => {
  process.stdout.write(JSON.stringify({ verdict: 'allow', consume_nonces: [] }), () => process.exit(0));
});
