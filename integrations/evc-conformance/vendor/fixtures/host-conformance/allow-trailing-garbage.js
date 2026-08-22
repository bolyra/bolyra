#!/usr/bin/env node
// Host-conformance fixture: verifier writes a valid `allow` verdict followed by
// trailing non-JSON bytes. Violates the single-object, no-trailing-bytes rule
// (§5.2): trailing bytes after the one object are a fail-closed condition. A
// conforming host MUST NOT act on the leading allow. Offered case (1).
process.stdin.resume();
process.stdin.on('end', () => {
  const s = JSON.stringify({ verdict: 'allow' }) + '\n<<< trailing garbage, not json';
  process.stdout.write(s, () => process.exit(0));
});
