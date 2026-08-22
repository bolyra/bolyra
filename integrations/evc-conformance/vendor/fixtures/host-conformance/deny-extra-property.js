#!/usr/bin/env node
// Host-conformance fixture: verifier writes a `deny` verdict carrying a
// disallowed ADDITIONAL property. The §3.4 deny shape is closed
// (additionalProperties:false), so the host MUST fail closed (§7.2) rather than
// relay an unrecognized field. Offered case (1): malformed stdout.
process.stdin.resume();
process.stdin.on('end', () => {
  const v = { verdict: 'deny', code: 'expired', message: 'credential expired', bogus: 1 };
  process.stdout.write(JSON.stringify(v), () => process.exit(0));
});
