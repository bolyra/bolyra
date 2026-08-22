#!/usr/bin/env node
// Host-conformance fixture: the verifier WOULD emit a syntactically valid `allow`
// at exit 0 — but only AFTER sleeping well past the host's wall-clock deadline.
// This is the sharp form of offered case (2)/(5): the host timeout (§6) is a hard
// wall-clock deadline, not merely a "hangs forever with no output" detector. A
// host that waits for the eventual (valid) output would allow; a conforming host
// MUST kill the process at the deadline and deny `timeout` (§7.2), never observing
// the late allow.
//
// Records its PID (via _pidfile) so the runner can prove the host KILLED it at the
// deadline rather than leaking an orphan that later prints its allow (§16.3).
require('./_pidfile');
process.stdin.resume();
process.stdin.on('end', () => {
  // Sleep far beyond any deadline these vectors set (timeout_ms is ~1 s), then —
  // if never killed — emit a valid allow. A conforming host never reaches this.
  setTimeout(() => {
    process.stdout.write(JSON.stringify({ verdict: 'allow' }), () => process.exit(0));
  }, 60000);
});
