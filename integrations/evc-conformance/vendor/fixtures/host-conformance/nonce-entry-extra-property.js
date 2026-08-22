#!/usr/bin/env node
// Host-conformance fixture: verifier writes an `allow` whose `consume_nonces`
// entry carries a disallowed ADDITIONAL property (§3.2/§3.4 — each entry is a
// closed object of exactly {issuer_key, nonce, retain_until}). A host MUST
// validate the entry schema and fail closed (§7.2); it MUST NOT reserve an entry
// with unrecognized fields. Offered cases (1)+(5).
process.stdin.resume();
process.stdin.on('end', () => {
  const v = {
    verdict: 'allow',
    consume_nonces: [
      {
        issuer_key: '1:2',
        nonce: '1000000000000000000000000000000000000001',
        retain_until: 4102444800,
        bogus: 'extra',
      },
    ],
  };
  process.stdout.write(JSON.stringify(v), () => process.exit(0));
});
