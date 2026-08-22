#!/usr/bin/env node
// Host-conformance fixture: verifier writes an `allow` verdict carrying a
// disallowed ADDITIONAL property. The §3.4 verdict schema is closed
// (additionalProperties:false), so the host MUST fail closed (§7.2). Offered
// case (1): malformed stdout (schema violation).
process.stdin.resume();
process.stdin.on('end', () => {
  process.stdout.write(JSON.stringify({ verdict: 'allow', foo: 'bar' }), () => process.exit(0));
});
