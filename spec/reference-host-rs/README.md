# evc-reference-host (Rust)

A **reference host** for the Bolyra **External Verifier Contract v1**
(`spec/external-verifier-contract-v1.md`) — the second, independent
implementation of the host-under-test (HUT) convention (§16.2), alongside the
Node reference at `spec/reference-host.js`.

## What this is (and is not)

The External Verifier Contract puts the load-bearing safety obligations on the
**host** that spawns a verifier: the wall-clock timeout, the stdout byte bound,
the strict single-object stdin/stdout framing, fail-closed handling of
non-zero exits and signal deaths, and reserve-before-act durable nonce
consumption. This crate implements exactly those obligations, in Rust, with a
minimal and auditable dependency tree (`serde_json`, plus `libc` on Unix only
for the process-group SIGKILL; std threads, no async runtime), and passes the
same `host_behavior` conformance vectors as the JS reference.

It exists to prove the contract is implementable outside Node and to give a
Rust host — for example, an MCP coordination server that gates actions on an
external verifier — a concrete shape to adapt.

**It is explicitly NOT:**

- a supported SDK — no stability promises, no semver discipline, the internal
  API may change or disappear at any time;
- published on crates.io (`publish = false`), and there is no plan to publish;
- wired into CI — the repo's CI is deliberately kept Rust-free for now; run the
  checks below locally when you touch this crate;
- a verifier — it performs **no** cryptography, proof checking, or policy
  evaluation. The verifier owns all of that; the host's job is to *distrust*
  the verifier process boundary.

## Layout

- `src/lib.rs` — all the logic, each function mapped to its spec section:
  - `spawn_and_supervise` — spawn the configured verifier in its own process
    group, feed the §2.1 request on stdin, enforce the timeout (§6) and stdout
    byte bound (§6) with a process-group SIGKILL + reap (so descendants that
    inherited the pipe die too and nothing outlives the decision), classify
    signal death and non-zero exit (§7.1–§7.2, §16.4). Bytes written by
    descendants after the verifier exits still count toward the output bound —
    overflow is checked at stdout EOF, exactly like the JS reference;
  - `parse_single_object` — strict §5.2 framing: exactly one JSON object,
    trailing garbage / concatenated values fail closed;
  - `valid_verdict` — the closed §3.4 verdict schema (including the optional
    `kind` and the exact `consume_nonces` entry shape);
  - `reserve_all` — §7.3 reserve-before-act: durably record every nonce (fsync)
    before the caller may authorize; any conflict is a replay;
  - `run` / `Decision` — the §7.2 fail-closed precedence and the §16.2
    single-decision-object envelope.
- `src/main.rs` — the thin stdin/stdout/env shell implementing the §16.2 HUT
  convention (`HUT_VERIFIER_CMD`, `HUT_TIMEOUT_MS`, `HUT_MAX_STDOUT_BYTES`,
  `HUT_NONCE_MODE`, `HUT_NONCE_STORE`, `HUT_ACTION_LOG`; `HUT_FIXTURE_PIDFILE`
  propagates via ordinary environment inheritance). It always exits 0 — the
  fail-closed signal is the decision object, never the exit code.

## Running the conformance suite against it

From the repo root:

```sh
# Build the host
cargo build --manifest-path spec/reference-host-rs/Cargo.toml

# Host-conformance vectors only (§16)
HOST_CMD="spec/reference-host-rs/target/debug/evc-reference-host" \
  node spec/conformance-runner.js --type host_behavior

# The full suite, with this host substituted as the HUT
HOST_CMD="spec/reference-host-rs/target/debug/evc-reference-host" \
  node spec/conformance-runner.js --validate-schema
```

Rust unit tests (framing, schema, reservation, and process-supervision edges,
including cases the black-box suite cannot see, such as a verifier that exits
cleanly while a grandchild holds the stdout pipe open):

```sh
cargo test --manifest-path spec/reference-host-rs/Cargo.toml
```

## Adapting the shape in a real Rust host

A production host (e.g. an MCP coordination server deciding whether to deliver
a message or execute a tool call) would keep the same skeleton and swap the
edges:

- replace `Config::from_env` with your own configuration for the verifier
  command, timeout, and output bound — the `HUT_*` variables are a test-harness
  convention (§16.2), not part of the wire contract;
- replace the newline-delimited nonce file in `reserve_all` with your durable
  store (SQLite, KV, issuer-scoped keys, expiry columns), preserving the
  invariant: **every** nonce durably reserved **before** the action is
  authorized, deny on **any** conflict;
- replace the `Decision` stdout envelope with your internal allow/deny result —
  the envelope, too, exists only for the harness;
- keep everything else byte-for-byte strict: single-object framing, the closed
  verdict schema, kill-on-timeout/overflow, and "non-zero exit beats a valid
  `allow` on stdout" (§16.4).

Two deliberate strictness notes, both in the fail-closed direction relative to
the JS reference: `retain_until` must be a JSON integer token (`1.0` is
rejected), and a verifier that exits 0 while something it spawned holds the
stdout pipe open past the wall-clock budget is classified as a `timeout` (and
the whole process group is killed) rather than waited on indefinitely.
