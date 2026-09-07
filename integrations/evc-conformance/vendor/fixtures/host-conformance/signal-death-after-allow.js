#!/usr/bin/env node
// Host-conformance fixture: verifier emits a complete, schema-valid,
// newline-terminated `allow`, waits for the write to flush to fd 1, and is
// then killed by an unsolicited fatal signal from its own teardown. §7.2:
// death by signal is deny 'regardless of what (if anything) reached stdout'
// and MUST be classified `signal_death`, not `nonzero_exit` (§16.3). Models
// a native proof library aborting after the verdict flush (§5.1). We use
// process.abort() (SIGABRT) rather than a self-sent SIGSEGV because the V8
// wasm trap handler may intercept a kill()-delivered SIGSEGV on some
// platforms; SIGABRT is delivered unconditionally and reports code === null
// with signal 'SIGABRT' to a Node host and returncode -6 to a Python host.
// The native stack trace goes to stderr, which the host MUST ignore.
process.stdin.resume();
process.stdin.on('end', () => {
  process.stdout.write(JSON.stringify({ verdict: 'allow' }) + '\n', () => {
    process.abort();
  });
});
