#!/usr/bin/env node
// Host-conformance fixture (registry closure): a verifier that returns an
// otherwise well-formed `deny` whose `code` is NOT in the §9 registry. The §3.4
// deny schema closes `code` over the registry enum, so this verdict fails the
// schema and the host MUST fail closed with its own `schema_invalid` class
// (§7.2/§16.3). The host MUST NOT relay the unknown code as if it were a valid
// verifier decision — relaying would let a broken or hostile verifier mint
// denial semantics the contract never defined.
const chunks = [];
process.stdin.on('data', c => chunks.push(c));
process.stdin.on('end', () => {
  const v = { verdict: 'deny', code: 'quantum_flux_error', message: 'not a registry code' };
  process.stdout.write(JSON.stringify(v), () => process.exit(0));
});
