#!/usr/bin/env node
// Host-conformance fixture (positive control): a well-behaved verifier that
// returns a schema-valid `deny code=expired` at exit 0. A conforming host MUST
// relay the deny with the verifier's code and MUST NOT attach a host
// failure_class — this is the verifier's own decision, not a fail-closed
// override. See spec/external-verifier-contract-v1.md §16.3.
const chunks = [];
process.stdin.on('data', c => chunks.push(c));
process.stdin.on('end', () => {
  const v = { verdict: 'deny', code: 'expired', message: 'credential expired' };
  process.stdout.write(JSON.stringify(v), () => process.exit(0));
});
