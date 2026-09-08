#!/usr/bin/env node
// Host-conformance fixture (positive control): a well-behaved verifier writes a
// schema-valid `allow` verdict carrying an explicit `"kind":"zk"` (§3.3, §3.5).
// §3.5 makes the explicit `zk` equivalent to omitting the field for a
// revision-aware host, so the host MUST relay `allow`. A host that only
// recognizes `classical` and `external` as explicit values (treating `zk` as an
// unrecognized kind under §7.2) diverges from the contract and fails this vector.
process.stdin.resume();
process.stdin.on('end', () => {
  process.stdout.write(JSON.stringify({ verdict: 'allow', kind: 'zk' }), () => process.exit(0));
});
