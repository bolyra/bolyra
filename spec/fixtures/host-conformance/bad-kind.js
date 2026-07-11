#!/usr/bin/env node
// Host-conformance fixture: verifier writes an `allow` verdict with a `kind`
// outside the {classical, zk, external} enum (§3.5). §7.2 requires the host to
// treat an unrecognized `kind` as a malformed verdict and fail closed. Offered
// case (1): malformed stdout (schema violation).
process.stdin.resume();
process.stdin.on('end', () => {
  process.stdout.write(JSON.stringify({ verdict: 'allow', kind: 'quantum' }), () => process.exit(0));
});
