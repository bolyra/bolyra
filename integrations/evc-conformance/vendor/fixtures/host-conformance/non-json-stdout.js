#!/usr/bin/env node
// Host-conformance fixture: verifier writes non-JSON to stdout at exit 0.
// Violates the single-object stdout discipline (§5.2). A conforming host MUST
// fail closed (§7.2). Offered case (1): malformed stdout.
process.stdin.resume();
process.stdin.on('end', () => {
  process.stdout.write('this is not a verdict at all', () => process.exit(0));
});
