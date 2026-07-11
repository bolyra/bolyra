// Shared helper for the "kill-proof" host-conformance fixtures. If the runner
// set HUT_FIXTURE_PIDFILE (inherited through the host that spawned this verifier),
// record this process's PID so the runner can verify, after the host returns,
// that the host actually KILLED the verifier rather than leaking an orphan
// (External Verifier Contract v1 §16.3). No-op when the env var is absent.
try {
  const p = process.env.HUT_FIXTURE_PIDFILE;
  if (p) require('fs').writeFileSync(p, String(process.pid));
} catch (e) { /* best effort — the pid check is a supplementary assertion */ }
