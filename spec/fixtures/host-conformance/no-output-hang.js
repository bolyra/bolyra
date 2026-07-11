#!/usr/bin/env node
// Host-conformance fixture: verifier reads stdin, writes NOTHING, and never
// exits. The host owns the timeout (§6) and MUST kill the process and deny
// (§7.2). Offered case (2): timeout / no output.
//
// Records its PID (via _pidfile) so the runner can prove the host actually
// KILLED it rather than leaking an orphan (§16.3).
require('./_pidfile');
process.stdin.resume();
setInterval(() => {}, 1 << 30); // keep the event loop alive forever
