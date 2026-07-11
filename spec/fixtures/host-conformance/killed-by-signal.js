#!/usr/bin/env node
// Host-conformance fixture: verifier terminates via an unsolicited fatal signal
// before producing any verdict. The host MUST treat death by signal as deny
// (§7.2). Offered case (3): killed-by-signal. SIGKILL is uncatchable, so the
// termination is unambiguous; the host distinguishes this from its own
// timeout-kill by tracking whether it initiated the kill (§16.3).
process.stdin.resume();
process.kill(process.pid, 'SIGKILL');
