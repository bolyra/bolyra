//! Rust reference host-under-test for the External Verifier Contract v1
//! host-conformance suite (`spec/external-verifier-contract-v1.md` §16).
//!
//! HUT convention (§16.2): configuration arrives via the `HUT_*` environment,
//! the §2.1 request arrives on stdin, and this process writes EXACTLY one
//! decision object to stdout and exits 0 — the fail-closed signal is the
//! decision object, never this process's exit code. All logic lives in the
//! library (`src/lib.rs`); this binary is only the stdin/stdout/env shell.
//!
//! Run the suite against it:
//!
//! ```sh
//! cargo build --manifest-path spec/reference-host-rs/Cargo.toml
//! HOST_CMD="spec/reference-host-rs/target/debug/evc-reference-host" \
//!   node spec/conformance-runner.js --type host_behavior
//! ```

use std::io::{Read, Write};

fn main() {
    // Read the whole §2.1 request from stdin (the runner writes it and closes).
    // A read error leaves the request short; the decision still fails closed
    // downstream, and this host still exits 0 with a decision object.
    let mut request = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut request);

    let cfg = evc_reference_host::Config::from_env();
    let decision = evc_reference_host::run(&cfg, &request);

    let mut stdout = std::io::stdout();
    let _ = stdout.write_all(decision.to_json().as_bytes());
    let _ = stdout.flush();
}
