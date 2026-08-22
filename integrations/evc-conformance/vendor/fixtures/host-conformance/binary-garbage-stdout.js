#!/usr/bin/env node
// Host-conformance fixture: verifier writes raw, non-UTF-8 GARBAGE BYTES to
// stdout at exit 0 (not merely non-JSON text). Violates the single-object stdout
// discipline (§5.2). A conforming host MUST decode/parse defensively and fail
// closed (§7.2) rather than crash, hang, or mis-handle the invalid bytes.
// Offered case (1): malformed stdout — the literal "garbage bytes" variant,
// distinct from non-json-stdout.js (which writes valid UTF-8 text).
process.stdin.resume();
process.stdin.on('end', () => {
  // Bytes that are neither valid UTF-8 nor a JSON object/array start. A lossy
  // decode yields replacement characters; a strict decode errors — either way
  // this is not a parseable single verdict.
  const garbage = Buffer.from([0x00, 0xff, 0xfe, 0x80, 0x81, 0x9f, 0xc0, 0xaf]);
  process.stdout.write(garbage, () => process.exit(0));
});
