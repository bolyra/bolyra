#!/usr/bin/env node
// Host-conformance fixture: verifier writes a PARTIAL JSON verdict then hangs
// forever. No complete object ever arrives and the process never exits, so the
// host timeout (§6) MUST fire and the host MUST deny (§7.2). Offered case (2):
// timeout / no output.
//
// Records its PID (via _pidfile) so the runner can prove the host KILLED it
// rather than leaking an orphan (§16.3).
require('./_pidfile');
process.stdin.resume();
process.stdout.write('{"verdict":"al');
setInterval(() => {}, 1 << 30); // hang after the partial write
