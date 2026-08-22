#!/usr/bin/env node
// Host-conformance fixture (positive control): a well-behaved verifier.
// Drains the request from stdin, writes a bare `allow` verdict to stdout, and
// exits 0. A conforming host MUST relay `allow`. See
// spec/external-verifier-contract-v1.md §16.3.
const chunks = [];
process.stdin.on('data', c => chunks.push(c));
process.stdin.on('end', () => {
  process.stdout.write(JSON.stringify({ verdict: 'allow' }), () => process.exit(0));
});
