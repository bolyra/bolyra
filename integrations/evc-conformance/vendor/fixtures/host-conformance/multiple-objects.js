#!/usr/bin/env node
// Host-conformance fixture: verifier writes TWO concatenated JSON verdicts.
// Violates single-object framing (§5.2): "a lenient parser that reads only the
// first object MUST NOT be used". A conforming host MUST fail closed (§7.2).
// Offered case (1): malformed stdout.
process.stdin.resume();
process.stdin.on('end', () => {
  const two = JSON.stringify({ verdict: 'allow' }) + '\n' +
    JSON.stringify({ verdict: 'deny', code: 'expired', message: 'second object' });
  process.stdout.write(two, () => process.exit(0));
});
