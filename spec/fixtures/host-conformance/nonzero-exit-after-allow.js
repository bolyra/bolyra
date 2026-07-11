#!/usr/bin/env node
// Host-conformance fixture: verifier prints a SYNTACTICALLY VALID `allow`
// verdict to stdout and then exits NON-ZERO. Exit status is part of the
// contract (§7.1): a non-zero exit means "no trustworthy verdict", so the host
// MUST treat this as deny and MUST NOT act on the stdout allow (§7.2, §16.4).
// Offered case (3): nonzero exit.
process.stdin.resume();
process.stdin.on('end', () => {
  process.stdout.write(JSON.stringify({ verdict: 'allow' }), () => process.exit(1));
});
