#!/usr/bin/env node
// Host-conformance fixture: verifier writes an `allow` whose `consume_nonces`
// entry has a wrong-typed `retain_until` (a string, not an integer — §3.2/§3.4).
// A host MUST validate the entry field types and fail closed (§7.2). Offered
// cases (1)+(5).
process.stdin.resume();
process.stdin.on('end', () => {
  const v = {
    verdict: 'allow',
    consume_nonces: [
      {
        issuer_key: '1:2',
        nonce: '1000000000000000000000000000000000000001',
        retain_until: '4102444800',
      },
    ],
  };
  process.stdout.write(JSON.stringify(v), () => process.exit(0));
});
