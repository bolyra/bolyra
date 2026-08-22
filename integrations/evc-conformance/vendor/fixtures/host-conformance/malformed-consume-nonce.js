#!/usr/bin/env node
// Host-conformance fixture: verifier writes an `allow` whose `consume_nonces`
// entry is missing the REQUIRED `issuer_key` and `retain_until` (§3.2/§3.4). A
// host MUST validate the full closed schema and fail closed (§7.2) — it MUST NOT
// reserve a partial nonce entry. Offered case (1) intersecting case (5).
process.stdin.resume();
process.stdin.on('end', () => {
  const v = { verdict: 'allow', consume_nonces: [{ nonce: '1000000000000000000000000000000000000001' }] };
  process.stdout.write(JSON.stringify(v), () => process.exit(0));
});
