#!/usr/bin/env node
// Host-conformance fixture: verifier floods stdout past any sane output bound.
// The host MUST bound the read, kill the process, and deny (§6/§7.2) — it MUST
// NOT buffer an unbounded verdict. Offered case (4): oversize output.
//
// Bounded by design: it streams to the stdout PIPE only (never to disk). After
// an 8 MiB burst it HANGS instead of exiting cleanly, so a host that fails to
// enforce the output bound cannot "buffer everything then observe a clean exit":
// such a host will instead hang and be caught by its own (or the runner's)
// timeout. Records its PID (via _pidfile) so the runner can prove the host
// KILLED it rather than leaking an orphan (§16.3).
require('./_pidfile');
process.stdin.resume();
const chunk = Buffer.alloc(64 * 1024, 0x41); // 64 KiB of 'A'
const CAP = 8 * 1024 * 1024; // hard safety cap on the burst
let total = 0;
(function pump() {
  while (total < CAP) {
    total += chunk.length;
    if (!process.stdout.write(chunk)) {
      process.stdout.once('drain', pump);
      return;
    }
  }
  setInterval(() => {}, 1 << 30); // burst done — hang, do NOT exit cleanly
})();
