#!/usr/bin/env node
// Host-conformance fixture: verifier writes a non-JSON PREFIX before an
// otherwise-valid `allow` verdict. Violates the single-object, no-surrounding-
// bytes rule (§5.2): "a leading/trailing prefix or suffix around the object" is
// a fail-closed condition. allow-trailing-garbage.js covers the trailing suffix;
// this covers the LEADING prefix. A host that skips leading noise and parses the
// embedded object would wrongly act on the allow; a conforming host MUST fail
// closed (§7.2). Offered cases (1)/(2): malformed stdout / must not extract an
// object from surrounding output.
process.stdin.resume();
process.stdin.on('end', () => {
  const s = 'leading noise, not json >>> ' + JSON.stringify({ verdict: 'allow' });
  process.stdout.write(s, () => process.exit(0));
});
