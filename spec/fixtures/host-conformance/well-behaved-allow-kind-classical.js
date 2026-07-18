#!/usr/bin/env node
// Host-conformance fixture (positive control): a well-behaved verifier that
// self-describes as a `classical`-class verifier (§3.5) and returns a valid
// `allow`. `kind` is OPTIONAL and, when present, MUST be one of
// {classical, zk, external}. This is the acceptance counterpart to bad-kind.js
// (which rejects an out-of-enum kind): a conforming host MUST accept every valid
// `kind` and relay `allow`, not just tolerate the default `zk`. Proves the host
// validates the closed `kind` enum without hard-coding a single value.
const chunks = [];
process.stdin.on('data', c => chunks.push(c));
process.stdin.on('end', () => {
  process.stdout.write(
    JSON.stringify({ verdict: 'allow', kind: 'classical' }),
    () => process.exit(0),
  );
});
