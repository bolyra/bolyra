#!/usr/bin/env node
// Host-conformance fixture: verifier writes valid JSON whose `verdict` is
// neither "allow" nor "deny". Fails the §3.4 verdict schema. A conforming host
// MUST fail closed (§7.2). Offered case (1): malformed stdout.
process.stdin.resume();
process.stdin.on('end', () => {
  process.stdout.write(JSON.stringify({ verdict: 'maybe' }), () => process.exit(0));
});
