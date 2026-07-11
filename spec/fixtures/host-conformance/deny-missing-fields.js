#!/usr/bin/env node
// Host-conformance fixture: verifier writes a `deny` verdict that omits the
// REQUIRED `code` and `message` fields (§3.3/§3.4). A conforming host MUST fail
// closed (§7.2). Offered case (1): malformed stdout.
process.stdin.resume();
process.stdin.on('end', () => {
  process.stdout.write(JSON.stringify({ verdict: 'deny' }), () => process.exit(0));
});
