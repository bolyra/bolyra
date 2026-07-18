#!/usr/bin/env node
// Host-conformance fixture (positive control): a well-behaved verifier that
// self-describes as an `external`-class verifier (§3.5) and returns a valid
// `allow`. `external` is the class a third-party (non-Bolyra) verifier declares.
// A conforming host MUST accept it and relay `allow` — this catches a host that
// hard-codes acceptance of only `zk`/`classical` and would wrongly reject a valid
// `external` verdict. Acceptance counterpart to bad-kind.js.
const chunks = [];
process.stdin.on('data', c => chunks.push(c));
process.stdin.on('end', () => {
  process.stdout.write(
    JSON.stringify({ verdict: 'allow', kind: 'external' }),
    () => process.exit(0),
  );
});
