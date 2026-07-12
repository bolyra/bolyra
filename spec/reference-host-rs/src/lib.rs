//! Core logic for the Rust reference host for the External Verifier Contract v1
//! host-conformance suite (`spec/external-verifier-contract-v1.md` §16).
//!
//! This is a REFERENCE implementation — a second, independent implementation of
//! the Host-Under-Test (HUT) convention (§16.2), alongside the in-repo
//! `spec/reference-host.js`. It exists to prove the host obligations are
//! implementable outside Node and to give Rust hosts (e.g. an MCP coordination
//! server) a shape to adapt. It is NOT a supported SDK.
//!
//! Host obligations implemented here, mapped to the spec:
//! - spawn the configured verifier command, write the §2.1 request as one JSON
//!   object to its stdin, close stdin (§2);
//! - enforce a wall-clock timeout, killing the verifier on expiry (§6);
//! - enforce a hard stdout byte bound, killing the verifier on overflow (§6);
//! - parse EXACTLY one JSON object from stdout — trailing garbage or multiple
//!   concatenated values fail closed (§5.2);
//! - validate the verdict against the CLOSED §3.4 schema (including the
//!   optional `kind` and the `consume_nonces` entry shapes);
//! - treat a non-zero exit or death-by-signal as deny, even when a
//!   syntactically valid `allow` reached stdout (§7.1, §7.2, §16.4);
//! - in host nonce mode, durably reserve EVERY `consume_nonces` entry BEFORE
//!   authorizing the action, denying as replay on ANY conflict (§7.3, §16.5).

use serde_json::Value;
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The closed §9 denial-code registry. Kept in lockstep with
/// `spec/external-verifier-contract-v1.md` §9 and `spec/reference-host.js`.
pub const KNOWN_CODES: &[&str] = &[
    "malformed_input",
    "unsupported_version",
    "invalid_bundle",
    "invalid_proof",
    "untrusted_root",
    "delegation_invalid",
    "invalid_signature",
    "request_mismatch",
    "model_mismatch",
    "unknown_capability",
    "scope_exceeded",
    "expired",
    "nonce_missing",
    "nonce_replayed",
    "internal_error",
];

/// The closed §3.5 `kind` enumeration.
pub const KINDS: &[&str] = &["classical", "zk", "external"];

/// The single decision object the host emits on stdout (§16.2). Exactly one of
/// three closed shapes; the host always exits 0 — the fail-closed signal is the
/// decision object, not the host's exit code.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    /// `{"decision":"allow"}` — verifier allowed (and, in host nonce mode,
    /// every nonce was reserved as novel).
    Allow,
    /// `{"decision":"deny","code":...}` — a schema-valid verifier deny,
    /// relayed unchanged.
    DenyCode(String),
    /// `{"decision":"deny","failure_class":...}` — the host itself failed
    /// closed (§7.2) or rejected a replay (§7.3). §16.3 class.
    DenyClass(&'static str),
}

impl Decision {
    pub fn to_json(&self) -> String {
        match self {
            Decision::Allow => serde_json::json!({ "decision": "allow" }).to_string(),
            Decision::DenyCode(code) => {
                serde_json::json!({ "decision": "deny", "code": code }).to_string()
            }
            Decision::DenyClass(class) => {
                serde_json::json!({ "decision": "deny", "failure_class": class }).to_string()
            }
        }
    }
}

/// HUT configuration (§16.2), normally read from the `HUT_*` environment.
pub struct Config {
    /// argv of the verifier the host MUST spawn (`HUT_VERIFIER_CMD`, JSON array).
    pub verifier_cmd: Vec<String>,
    /// Wall-clock timeout the host MUST enforce (§6).
    pub timeout: Duration,
    /// stdout byte bound the host MUST enforce (§6).
    pub max_stdout_bytes: usize,
    /// `true` when `HUT_NONCE_MODE=host` (§8): the host owns nonce consumption.
    pub host_nonce_mode: bool,
    /// Durable nonce store path (§7.3; newline-delimited harness format, §16.2).
    pub nonce_store: Option<PathBuf>,
    /// Action log path (§16.5): append a marker ONLY when authorizing.
    pub action_log: Option<PathBuf>,
}

impl Config {
    /// Read the §16.2 HUT convention from the environment. Defaults mirror
    /// `spec/reference-host.js`: 10 s timeout, 1 MiB output bound, local nonce
    /// mode. An unset/unparsable `HUT_VERIFIER_CMD` leaves `verifier_cmd`
    /// empty, which `run` turns into a fail-closed `spawn_error`.
    ///
    /// Note: the spawned verifier inherits this process's environment, which
    /// satisfies the §16.2 requirement to propagate `HUT_FIXTURE_PIDFILE`.
    pub fn from_env() -> Config {
        fn env_path(name: &str) -> Option<PathBuf> {
            match std::env::var(name) {
                Ok(v) if !v.is_empty() => Some(PathBuf::from(v)),
                _ => None,
            }
        }
        let verifier_cmd = std::env::var("HUT_VERIFIER_CMD")
            .ok()
            .and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok())
            .unwrap_or_default();
        let timeout_ms = std::env::var("HUT_TIMEOUT_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(10_000);
        let max_stdout_bytes = std::env::var("HUT_MAX_STDOUT_BYTES")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(1_048_576);
        Config {
            verifier_cmd,
            timeout: Duration::from_millis(timeout_ms),
            max_stdout_bytes,
            host_nonce_mode: std::env::var("HUT_NONCE_MODE").as_deref() == Ok("host"),
            nonce_store: env_path("HUT_NONCE_STORE"),
            action_log: env_path("HUT_ACTION_LOG"),
        }
    }
}

/// Outcome of supervising one verifier run, BEFORE stdout is interpreted.
/// Ordered by the §7.2 fail-closed precedence the host applies: its own kills
/// (overflow, timeout) dominate, then an unsolicited signal death, then a
/// non-zero exit; only a clean exit 0 lets stdout be parsed.
#[derive(Debug, PartialEq, Eq)]
pub enum SpawnOutcome {
    /// The verifier could not be spawned or driven at all.
    SpawnError,
    /// stdout exceeded the byte bound (§6) — the host killed the verifier.
    Overflow,
    /// The wall-clock timeout fired (§6) — the host killed the verifier.
    Timeout,
    /// The verifier died by an unsolicited signal (§7.2).
    SignalDeath,
    /// The verifier exited non-zero (§7.1/§16.4) — stdout MUST be ignored.
    NonzeroExit,
    /// Clean exit 0: the captured stdout, ready for the §5.2 strict parse.
    Stdout(Vec<u8>),
}

/// Spawn the verifier, feed it `request` on stdin, and supervise it under the
/// timeout and output bound. Uses std threads only (one writer, one reader) —
/// the child is polled with `try_wait` and killed with SIGKILL on expiry or
/// overflow, then reaped, so no orphan is leaked (§16.3 kill-proof).
pub fn spawn_and_supervise(
    cmd: &[String],
    request: &[u8],
    timeout: Duration,
    max_bytes: usize,
) -> SpawnOutcome {
    if cmd.is_empty() {
        return SpawnOutcome::SpawnError;
    }
    let mut command = Command::new(&cmd[0]);
    command
        .args(&cmd[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Run the verifier in its own process group (pgid == its pid) so a
        // kill reaches descendants that inherited the stdout pipe, not just
        // the direct child — nothing may outlive the decision (§16.3).
        command.process_group(0);
    }
    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(_) => return SpawnOutcome::SpawnError,
    };
    let child_pgid = child.id();

    // Writer thread: feed the request and close stdin (§2). Errors (e.g. EPIPE
    // from a verifier that dies without reading stdin) are deliberately
    // swallowed — Rust ignores SIGPIPE by default, so the write just errors.
    // The handle is dropped (detached): the host never blocks on the writer,
    // and the thread unblocks (or dies with the process) once the child dies.
    let mut stdin = child.stdin.take();
    let request_owned = request.to_vec();
    drop(std::thread::spawn(move || {
        if let Some(mut pipe) = stdin.take() {
            let _ = pipe.write_all(&request_owned);
            // pipe dropped here → stdin closed
        }
    }));

    // Reader thread: drain stdout until EOF, keeping at most max_bytes + 1
    // bytes (anything past the bound is an overflow and is never parsed) while
    // counting EVERY byte so the supervisor can detect the overflow and kill.
    // The collected bytes are handed back over a channel at EOF; the
    // supervisor NEVER joins this thread, so a stray grandchild holding the
    // pipe open can delay EOF but can never wedge the host past its budget.
    let stdout = child.stdout.take();
    let total = Arc::new(AtomicUsize::new(0));
    let total_for_reader = Arc::clone(&total);
    let keep = max_bytes.saturating_add(1);
    let (out_tx, out_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    drop(std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut pipe) = stdout {
            let mut chunk = [0u8; 65536];
            loop {
                match pipe.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        total_for_reader.fetch_add(n, Ordering::Relaxed);
                        let room = keep.saturating_sub(buf.len());
                        buf.extend_from_slice(&chunk[..n.min(room)]);
                    }
                }
            }
        }
        let _ = out_tx.send(buf);
    }));

    // Supervisor loop: poll for exit; kill on overflow or timeout. The timer
    // starts after the spawn, matching spec/reference-host.js.
    let start = Instant::now();
    let mut killed_overflow = false;
    let mut killed_timeout = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait(); // reap — never leak the process
                return SpawnOutcome::SpawnError;
            }
        }
        if !killed_overflow && total.load(Ordering::Relaxed) > max_bytes {
            killed_overflow = true;
            kill_process_group(child_pgid);
            let _ = child.kill();
        } else if !killed_overflow && !killed_timeout && start.elapsed() >= timeout {
            killed_timeout = true;
            kill_process_group(child_pgid);
            let _ = child.kill();
        }
        std::thread::sleep(Duration::from_millis(2));
    };

    // Wait for stdout EOF REGARDLESS of how the verifier exited, bounded by
    // what remains of the wall-clock budget (§6 covers the whole verification)
    // plus a small pipe-drain grace. Bytes written by descendants that
    // inherited the pipe still count toward the output bound — the JS
    // reference checks overflow at stream close, and so must we, otherwise a
    // verifier could smuggle an unbounded flood behind a quick non-zero exit.
    // If something still holds the pipe open past the budget, kill the whole
    // process group: nothing outlives the decision (§16.3).
    let remaining = timeout
        .saturating_sub(start.elapsed())
        .saturating_add(Duration::from_millis(100));
    let eof = out_rx.recv_timeout(remaining);
    if eof.is_err() {
        // stdout never closed within the budget: this IS the §6 wall-clock
        // timeout firing at stream-close time (the JS reference's timer fires
        // while it waits for 'close', so timeout wins precedence there too).
        // Record it for precedence and kill the group.
        killed_timeout = true;
        kill_process_group(child_pgid);
    }

    // §7.2 fail-closed precedence (same order as spec/reference-host.js):
    // overflow, then our own timeout kill, then an unsolicited signal death,
    // then a non-zero exit; only then is stdout parsed. Overflow uses the
    // byte count observed up to EOF (or up to the bounded wait's expiry).
    if killed_overflow || total.load(Ordering::Relaxed) > max_bytes {
        return SpawnOutcome::Overflow;
    }
    if killed_timeout {
        return SpawnOutcome::Timeout;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if status.signal().is_some() {
            return SpawnOutcome::SignalDeath;
        }
    }
    if status.code() != Some(0) {
        return SpawnOutcome::NonzeroExit;
    }
    // Clean exit 0 with stdout EOF inside the budget (the expired-EOF case
    // already returned Timeout above): parse the complete captured verdict.
    SpawnOutcome::Stdout(eof.unwrap_or_default())
}

/// SIGKILL the verifier's whole process group (it was started with
/// `process_group(0)`, so its pgid is its pid). Best effort; descendants that
/// inherited the stdout pipe die with it, so no orphan outlives the decision
/// (§16.3) and the drained pipe promptly delivers EOF to the reader thread.
#[cfg(unix)]
fn kill_process_group(pgid: u32) {
    // SAFETY: plain syscall; a negative pid targets the process group. The
    // group is private to the verifier we just spawned.
    unsafe {
        libc::kill(-(pgid as libc::pid_t), libc::SIGKILL);
    }
}

#[cfg(not(unix))]
fn kill_process_group(_pgid: u32) {}

/// Strict single-object parse (§5.2). Returns the value for EXACTLY one JSON
/// object with no trailing bytes; otherwise the §16.3 failure class:
/// `multiple_objects` for a concatenated JSON stream, `unparseable_stdout` for
/// empty / non-JSON / trailing-garbage output.
pub fn parse_single_object(s: &str) -> Result<Value, &'static str> {
    let s = s.trim();
    if s.is_empty() {
        return Err("unparseable_stdout");
    }
    let end = first_value_end(s).ok_or("unparseable_stdout")?;
    let first: Value = serde_json::from_str(&s[..end]).map_err(|_| "unparseable_stdout")?;
    let rest = s[end..].trim();
    if rest.is_empty() {
        return Ok(first);
    }
    // Trailing content: a second JSON value → multi-object stream; else garbage.
    if rest.starts_with('{') || rest.starts_with('[') {
        return Err("multiple_objects");
    }
    Err("unparseable_stdout")
}

/// Byte index just past the first balanced top-level JSON object/array,
/// honoring string escapes. `None` for a non-object/array start or an
/// unbalanced value. Structural characters are ASCII, so scanning bytes is
/// UTF-8-safe and the returned index is always a char boundary.
fn first_value_end(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    if b[0] != b'{' && b[0] != b'[' {
        return None;
    }
    let (mut depth, mut in_str, mut esc) = (0i64, false, false);
    for (i, &ch) in b.iter().enumerate() {
        if in_str {
            if esc {
                esc = false;
            } else if ch == b'\\' {
                esc = true;
            } else if ch == b'"' {
                in_str = false;
            }
            continue;
        }
        match ch {
            b'"' => in_str = true,
            b'{' | b'[' => depth += 1,
            b'}' | b']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
    }
    None
}

/// The CLOSED §3.4 verdict schema as an inline validator, kept in lockstep
/// with `spec/external-verifier-contract-v1.md` §3.4 and
/// `spec/reference-host.js`:
/// - `allow` → `{ verdict, kind?, consume_nonces? }`, no other property;
/// - `deny` → `{ verdict, kind?, code, message, detail? }`, no other property,
///   `code` from the closed §9 registry, `detail` an object when present;
/// - `consume_nonces` (when present) is a non-empty array of exactly
///   `{ issuer_key: string, nonce: string, retain_until: integer }`.
///
/// `retain_until` must parse as a JSON integer (i64/u64); a float such as
/// `1.5` — or `1.0`, which serde_json keeps as f64 — is rejected. Rejecting
/// `1.0` is stricter than a JSON-Schema `type: integer` check, in the
/// fail-closed direction.
pub fn valid_verdict(v: &Value) -> bool {
    let obj = match v.as_object() {
        Some(o) => o,
        None => return false,
    };
    if let Some(kind) = obj.get("kind") {
        match kind.as_str() {
            Some(k) if KINDS.contains(&k) => {}
            _ => return false,
        }
    }
    match obj.get("verdict").and_then(Value::as_str) {
        Some("allow") => {
            if obj
                .keys()
                .any(|k| !matches!(k.as_str(), "verdict" | "kind" | "consume_nonces"))
            {
                return false;
            }
            if let Some(cn) = obj.get("consume_nonces") {
                let arr = match cn.as_array() {
                    Some(a) if !a.is_empty() => a,
                    _ => return false,
                };
                for entry in arr {
                    let e = match entry.as_object() {
                        Some(e) => e,
                        None => return false,
                    };
                    if e.len() != 3
                        || !e.get("issuer_key").is_some_and(Value::is_string)
                        || !e.get("nonce").is_some_and(Value::is_string)
                        || !e
                            .get("retain_until")
                            .is_some_and(|r| r.is_i64() || r.is_u64())
                    {
                        return false;
                    }
                }
            }
            true
        }
        Some("deny") => {
            if obj.keys().any(|k| {
                !matches!(k.as_str(), "verdict" | "kind" | "code" | "message" | "detail")
            }) {
                return false;
            }
            match obj.get("code").and_then(Value::as_str) {
                Some(c) if KNOWN_CODES.contains(&c) => {}
                _ => return false,
            }
            if !obj.get("message").is_some_and(Value::is_string) {
                return false;
            }
            if let Some(d) = obj.get("detail") {
                if !d.is_object() {
                    return false;
                }
            }
            true
        }
        _ => false, // verdict is neither "allow" nor "deny" (or absent)
    }
}

/// Reserve-before-act (§7.3): consult the durable store, then durably record
/// the novel nonces BEFORE the caller may authorize the action. Returns
/// `false` (→ `replay` deny) when ANY entry was already present, when there is
/// no store to consult, or when the reservation cannot be durably written —
/// all fail closed.
///
/// Store format is the §16.2 harness convention: newline-delimited nonce
/// strings, UTF-8. Novel entries are written (and fsync'd) even when another
/// entry conflicts, matching `spec/reference-host.js`.
pub fn reserve_all(store: Option<&Path>, entries: &[Value]) -> bool {
    let store = match store {
        Some(p) => p,
        None => return false, // host nonce mode requires a store — fail closed
    };
    let mut existing: BTreeSet<String> = match std::fs::read_to_string(store) {
        Ok(s) => s
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(String::from)
            .collect(),
        Err(_) => BTreeSet::new(), // missing store == empty
    };
    let mut conflict = false;
    let mut to_add = Vec::new();
    for entry in entries {
        let nonce = match entry.get("nonce").and_then(Value::as_str) {
            Some(n) => n,
            None => return false,
        };
        if existing.contains(nonce) {
            conflict = true;
        } else {
            to_add.push(nonce.to_string());
        }
    }
    if !to_add.is_empty() {
        existing.extend(to_add);
        let body = existing.iter().cloned().collect::<Vec<_>>().join("\n") + "\n";
        let written = std::fs::File::create(store)
            .and_then(|mut f| f.write_all(body.as_bytes()).and_then(|()| f.sync_all()));
        if written.is_err() {
            return false; // cannot durably reserve → cannot authorize
        }
    }
    !conflict
}

/// Append the "action authorized" marker (§16.5). Called ONLY on allow, after
/// every reservation succeeded. Best effort, like the JS reference.
fn record_action(log: Option<&Path>) {
    if let Some(path) = log {
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .and_then(|mut f| f.write_all(b"acted\n"));
    }
}

/// Interpret a clean-exit verifier's stdout: strict parse (§5.2), closed-schema
/// validation (§3.4), verifier-deny relay, host nonce reservation (§7.3), and
/// the reserve-before-act ordering (reservations first, THEN the action marker,
/// THEN allow).
fn decide(cfg: &Config, stdout: &[u8]) -> Decision {
    let text = String::from_utf8_lossy(stdout);
    let verdict = match parse_single_object(&text) {
        Ok(v) => v,
        Err(class) => return Decision::DenyClass(class),
    };
    if !valid_verdict(&verdict) {
        return Decision::DenyClass("schema_invalid");
    }
    if verdict["verdict"] == "deny" {
        // Relay the schema-valid verifier deny unchanged (§16.2): code only,
        // never a host failure_class.
        let code = verdict["code"].as_str().unwrap_or("internal_error");
        return Decision::DenyCode(code.to_string());
    }
    // allow
    if cfg.host_nonce_mode {
        if let Some(entries) = verdict.get("consume_nonces").and_then(Value::as_array) {
            if !reserve_all(cfg.nonce_store.as_deref(), entries) {
                return Decision::DenyClass("replay");
            }
        }
    }
    record_action(cfg.action_log.as_deref()); // reserve-before-act: only now
    Decision::Allow
}

/// One full host decision: spawn + supervise the verifier, then interpret the
/// outcome fail-closed (§7.2 precedence) and produce the §16.2 decision object.
pub fn run(cfg: &Config, request: &[u8]) -> Decision {
    match spawn_and_supervise(
        &cfg.verifier_cmd,
        request,
        cfg.timeout,
        cfg.max_stdout_bytes,
    ) {
        SpawnOutcome::SpawnError => Decision::DenyClass("spawn_error"),
        SpawnOutcome::Overflow => Decision::DenyClass("oversize_stdout"),
        SpawnOutcome::Timeout => Decision::DenyClass("timeout"),
        SpawnOutcome::SignalDeath => Decision::DenyClass("signal_death"),
        SpawnOutcome::NonzeroExit => Decision::DenyClass("nonzero_exit"),
        SpawnOutcome::Stdout(out) => decide(cfg, &out),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::AtomicU32;

    // --- helpers -----------------------------------------------------------

    static TMP_SEQ: AtomicU32 = AtomicU32::new(0);

    /// A unique per-test temp directory (std-only; no tempfile dependency).
    fn tmp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "evc-host-test-{}-{}-{}",
            tag,
            std::process::id(),
            TMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sh(script: &str) -> Vec<String> {
        vec!["/bin/sh".into(), "-c".into(), script.into()]
    }

    fn nonce_entry(nonce: &str) -> Value {
        json!({ "issuer_key": "1:2", "nonce": nonce, "retain_until": 4102444800i64 })
    }

    // --- §5.2 strict single-object framing ---------------------------------

    #[test]
    fn parse_empty_is_unparseable() {
        assert_eq!(parse_single_object(""), Err("unparseable_stdout"));
        assert_eq!(parse_single_object("  \n\t "), Err("unparseable_stdout"));
    }

    #[test]
    fn parse_non_json_is_unparseable() {
        assert_eq!(parse_single_object("verdict: allow"), Err("unparseable_stdout"));
    }

    #[test]
    fn parse_bare_scalar_is_unparseable() {
        // The strict parse only admits an object/array start (like the JS
        // reference); a bare scalar is not a verdict-shaped value.
        assert_eq!(parse_single_object("42"), Err("unparseable_stdout"));
        assert_eq!(parse_single_object("\"allow\""), Err("unparseable_stdout"));
    }

    #[test]
    fn parse_single_object_ok() {
        let v = parse_single_object(r#"{"verdict":"allow"}"#).unwrap();
        assert_eq!(v["verdict"], "allow");
    }

    #[test]
    fn parse_tolerates_surrounding_whitespace() {
        let v = parse_single_object("  \n {\"verdict\":\"allow\"} \n ").unwrap();
        assert_eq!(v["verdict"], "allow");
    }

    #[test]
    fn parse_honors_braces_and_escapes_inside_strings() {
        let v = parse_single_object(r#"{"a":"}{","b":"\"}\\"}"#).unwrap();
        assert_eq!(v["a"], "}{");
    }

    #[test]
    fn parse_trailing_garbage_is_unparseable() {
        assert_eq!(
            parse_single_object(r#"{"verdict":"allow"} trailing"#),
            Err("unparseable_stdout")
        );
    }

    #[test]
    fn parse_two_objects_is_multiple_objects() {
        assert_eq!(
            parse_single_object(r#"{"verdict":"deny"}{"verdict":"allow"}"#),
            Err("multiple_objects")
        );
        assert_eq!(
            parse_single_object("{\"verdict\":\"allow\"}\n[1,2]"),
            Err("multiple_objects")
        );
    }

    #[test]
    fn parse_unbalanced_is_unparseable() {
        assert_eq!(parse_single_object(r#"{"verdict":"allow""#), Err("unparseable_stdout"));
    }

    #[test]
    fn parse_multibyte_utf8_in_strings_ok() {
        let v = parse_single_object(r#"{"a":"héllo — 縦"}"#).unwrap();
        assert_eq!(v["a"], "héllo — 縦");
    }

    // --- §3.4 closed verdict schema -----------------------------------------

    #[test]
    fn verdict_allow_minimal_ok() {
        assert!(valid_verdict(&json!({ "verdict": "allow" })));
    }

    #[test]
    fn verdict_allow_with_kind_ok() {
        for k in KINDS {
            assert!(valid_verdict(&json!({ "verdict": "allow", "kind": k })));
        }
    }

    #[test]
    fn verdict_bad_kind_invalid() {
        assert!(!valid_verdict(&json!({ "verdict": "allow", "kind": "quantum" })));
        assert!(!valid_verdict(&json!({ "verdict": "allow", "kind": 7 })));
    }

    #[test]
    fn verdict_allow_extra_property_invalid() {
        assert!(!valid_verdict(&json!({ "verdict": "allow", "note": "hi" })));
    }

    #[test]
    fn verdict_allow_consume_nonces_ok() {
        assert!(valid_verdict(&json!({
            "verdict": "allow",
            "consume_nonces": [nonce_entry("1"), nonce_entry("2")]
        })));
    }

    #[test]
    fn verdict_empty_consume_nonces_invalid() {
        assert!(!valid_verdict(&json!({ "verdict": "allow", "consume_nonces": [] })));
    }

    #[test]
    fn verdict_consume_nonces_not_array_invalid() {
        assert!(!valid_verdict(&json!({ "verdict": "allow", "consume_nonces": {} })));
    }

    #[test]
    fn verdict_nonce_entry_missing_field_invalid() {
        assert!(!valid_verdict(&json!({
            "verdict": "allow",
            "consume_nonces": [{ "nonce": "1" }]
        })));
    }

    #[test]
    fn verdict_nonce_entry_extra_property_invalid() {
        let mut e = nonce_entry("1");
        e["extra"] = json!(true);
        assert!(!valid_verdict(&json!({ "verdict": "allow", "consume_nonces": [e] })));
    }

    #[test]
    fn verdict_nonce_entry_wrong_types_invalid() {
        let mut e = nonce_entry("1");
        e["retain_until"] = json!("4102444800"); // string, not integer
        assert!(!valid_verdict(&json!({ "verdict": "allow", "consume_nonces": [e.clone()] })));
        e["retain_until"] = json!(1.5); // fraction
        assert!(!valid_verdict(&json!({ "verdict": "allow", "consume_nonces": [e.clone()] })));
        e["retain_until"] = json!(4102444800i64);
        e["nonce"] = json!(42); // nonce must be a string
        assert!(!valid_verdict(&json!({ "verdict": "allow", "consume_nonces": [e] })));
    }

    #[test]
    fn verdict_deny_ok() {
        assert!(valid_verdict(&json!({
            "verdict": "deny", "code": "expired", "message": "credential expired"
        })));
        assert!(valid_verdict(&json!({
            "verdict": "deny", "code": "expired", "message": "m", "detail": { "at": 1 },
            "kind": "zk"
        })));
    }

    #[test]
    fn verdict_deny_unknown_code_invalid() {
        assert!(!valid_verdict(&json!({
            "verdict": "deny", "code": "not_a_registry_code", "message": "m"
        })));
    }

    #[test]
    fn verdict_deny_missing_fields_invalid() {
        assert!(!valid_verdict(&json!({ "verdict": "deny" })));
        assert!(!valid_verdict(&json!({ "verdict": "deny", "code": "expired" })));
        assert!(!valid_verdict(&json!({ "verdict": "deny", "message": "m" })));
    }

    #[test]
    fn verdict_deny_extra_property_invalid() {
        assert!(!valid_verdict(&json!({
            "verdict": "deny", "code": "expired", "message": "m", "hint": "retry"
        })));
    }

    #[test]
    fn verdict_deny_detail_must_be_object() {
        for bad in [json!(null), json!([1]), json!("d"), json!(3)] {
            assert!(!valid_verdict(&json!({
                "verdict": "deny", "code": "expired", "message": "m", "detail": bad
            })));
        }
    }

    #[test]
    fn verdict_unknown_or_missing_verdict_invalid() {
        assert!(!valid_verdict(&json!({ "verdict": "maybe" })));
        assert!(!valid_verdict(&json!({ "code": "expired" })));
        assert!(!valid_verdict(&json!([1, 2])));
        assert!(!valid_verdict(&json!(null)));
    }

    // --- §7.3 reserve-before-act --------------------------------------------

    #[test]
    fn reserve_novel_nonce_reserves_durably() {
        let dir = tmp_dir("novel");
        let store = dir.join("nonces");
        assert!(reserve_all(Some(&store), &[nonce_entry("111")]));
        let contents = std::fs::read_to_string(&store).unwrap();
        assert!(contents.lines().any(|l| l.trim() == "111"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn reserve_replayed_nonce_fails() {
        let dir = tmp_dir("replay");
        let store = dir.join("nonces");
        std::fs::write(&store, "111\n").unwrap();
        assert!(!reserve_all(Some(&store), &[nonce_entry("111")]));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn reserve_all_rejects_on_any_conflict_but_still_records_novel() {
        let dir = tmp_dir("multi");
        let store = dir.join("nonces");
        std::fs::write(&store, "222\n").unwrap();
        // First entry is novel, second is replayed → the whole reservation fails.
        assert!(!reserve_all(Some(&store), &[nonce_entry("111"), nonce_entry("222")]));
        // The novel entry is still durably recorded (matches reference-host.js).
        let contents = std::fs::read_to_string(&store).unwrap();
        assert!(contents.lines().any(|l| l.trim() == "111"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn reserve_without_store_fails_closed() {
        assert!(!reserve_all(None, &[nonce_entry("111")]));
    }

    // --- process supervision: framing / timeout / exit / signal / overflow ---

    #[test]
    fn spawn_well_behaved_verifier_yields_stdout() {
        let out = spawn_and_supervise(
            &sh(r#"cat >/dev/null; printf '{"verdict":"allow"}'"#),
            b"{}",
            Duration::from_secs(5),
            1_048_576,
        );
        assert_eq!(out, SpawnOutcome::Stdout(br#"{"verdict":"allow"}"#.to_vec()));
    }

    #[test]
    fn spawn_nonzero_exit_dominates_stdout_allow() {
        // §16.4: a valid allow on stdout followed by exit 1 MUST be NonzeroExit.
        let out = spawn_and_supervise(
            &sh(r#"printf '{"verdict":"allow"}'; exit 1"#),
            b"{}",
            Duration::from_secs(5),
            1_048_576,
        );
        assert_eq!(out, SpawnOutcome::NonzeroExit);
    }

    #[test]
    fn spawn_signal_death_detected() {
        let out = spawn_and_supervise(
            &sh("kill -KILL $$"),
            b"{}",
            Duration::from_secs(5),
            1_048_576,
        );
        assert_eq!(out, SpawnOutcome::SignalDeath);
    }

    #[test]
    fn spawn_timeout_kills_hung_verifier() {
        let start = Instant::now();
        let out = spawn_and_supervise(
            &sh("sleep 30"),
            b"{}",
            Duration::from_millis(200),
            1_048_576,
        );
        assert_eq!(out, SpawnOutcome::Timeout);
        // The verifier was killed, not waited out.
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn spawn_overflow_on_flood_then_hang() {
        let start = Instant::now();
        let out = spawn_and_supervise(
            &sh("head -c 300000 /dev/zero; sleep 30"),
            b"{}",
            Duration::from_secs(30),
            65_536,
        );
        assert_eq!(out, SpawnOutcome::Overflow);
        // Killed on overflow, well before either timeout.
        assert!(start.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn spawn_overflow_even_when_verifier_exits_cleanly() {
        // A flood that exits 0 before the supervisor kills it is still oversize
        // — the FINAL byte count classifies it; the output is never trusted.
        let out = spawn_and_supervise(
            &sh("head -c 300000 /dev/zero"),
            b"{}",
            Duration::from_secs(30),
            65_536,
        );
        assert_eq!(out, SpawnOutcome::Overflow);
    }

    #[test]
    fn spawn_overflow_by_descendant_after_nonzero_exit() {
        // Codex review finding: the parent verifier exits non-zero immediately
        // while a background descendant floods the inherited stdout pipe past
        // the bound. Overflow dominates the non-zero exit (§7.2 precedence,
        // matching reference-host.js, which checks overflow at stream close).
        let out = spawn_and_supervise(
            &sh("(sleep 0.05; head -c 300000 /dev/zero) & exit 1"),
            b"{}",
            Duration::from_secs(2),
            65_536,
        );
        assert_eq!(out, SpawnOutcome::Overflow);
    }

    #[test]
    fn spawn_overflow_by_descendant_after_signal_death() {
        // Same shape, but the parent dies by signal: overflow still dominates.
        let out = spawn_and_supervise(
            &sh("(sleep 0.05; head -c 300000 /dev/zero) & kill -KILL $$"),
            b"{}",
            Duration::from_secs(2),
            65_536,
        );
        assert_eq!(out, SpawnOutcome::Overflow);
    }

    #[test]
    fn spawn_timeout_beats_nonzero_exit_when_pipe_held_past_budget() {
        // Codex round 2: parent exits non-zero immediately, a quiet descendant
        // holds stdout open past the budget. The wall-clock timeout fires at
        // stream-close time and wins precedence over the non-zero exit,
        // matching the JS reference (its timer fires while awaiting 'close').
        let out = spawn_and_supervise(
            &sh("sleep 0.5 & exit 1"),
            b"{}",
            Duration::from_millis(100),
            1_048_576,
        );
        assert_eq!(out, SpawnOutcome::Timeout);
    }

    #[test]
    fn spawn_timeout_beats_signal_death_when_pipe_held_past_budget() {
        let out = spawn_and_supervise(
            &sh("sleep 0.5 & kill -KILL $$"),
            b"{}",
            Duration::from_millis(100),
            1_048_576,
        );
        assert_eq!(out, SpawnOutcome::Timeout);
    }

    #[test]
    fn spawn_clean_exit_with_pipe_held_open_is_timeout() {
        // The verifier exits 0 but leaves a background process holding the
        // stdout pipe, so EOF never arrives within the budget. There is no
        // complete, trustworthy verdict to parse — the host must classify this
        // as a timeout within its wall-clock budget, not wedge.
        let start = Instant::now();
        let out = spawn_and_supervise(
            &sh(r#"sleep 30 & printf '{"verdict":"allow"}'; exit 0"#),
            b"{}",
            Duration::from_millis(300),
            1_048_576,
        );
        assert_eq!(out, SpawnOutcome::Timeout);
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn spawn_missing_binary_is_spawn_error() {
        let cmd = vec!["/nonexistent/evc-no-such-verifier".to_string()];
        assert_eq!(
            spawn_and_supervise(&cmd, b"{}", Duration::from_secs(5), 1024),
            SpawnOutcome::SpawnError
        );
    }

    #[test]
    fn spawn_empty_command_is_spawn_error() {
        assert_eq!(
            spawn_and_supervise(&[], b"{}", Duration::from_secs(5), 1024),
            SpawnOutcome::SpawnError
        );
    }

    #[test]
    fn spawn_verifier_that_never_reads_stdin_does_not_wedge_host() {
        // EPIPE on the writer thread must be swallowed (§2 note in the JS ref).
        let out = spawn_and_supervise(
            &sh(r#"exec 0<&-; printf '{"verdict":"allow"}'"#),
            &vec![b'x'; 200_000], // bigger than a pipe buffer
            Duration::from_secs(5),
            1_048_576,
        );
        assert_eq!(out, SpawnOutcome::Stdout(br#"{"verdict":"allow"}"#.to_vec()));
    }

    // --- end-to-end decisions (run) ------------------------------------------

    fn cfg_with(cmd: Vec<String>, dir: &Path, host_mode: bool) -> Config {
        Config {
            verifier_cmd: cmd,
            timeout: Duration::from_secs(5),
            max_stdout_bytes: 1_048_576,
            host_nonce_mode: host_mode,
            nonce_store: Some(dir.join("nonces")),
            action_log: Some(dir.join("action-log")),
        }
    }

    fn action_taken(dir: &Path) -> bool {
        std::fs::read_to_string(dir.join("action-log"))
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false)
    }

    #[test]
    fn run_relays_verifier_deny_code_unchanged() {
        let dir = tmp_dir("relay");
        let cfg = cfg_with(
            sh(r#"cat >/dev/null; printf '{"verdict":"deny","code":"expired","message":"m"}'"#),
            &dir,
            false,
        );
        assert_eq!(run(&cfg, b"{}"), Decision::DenyCode("expired".into()));
        assert!(!action_taken(&dir)); // never act on a deny
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn run_allows_and_records_action_marker() {
        let dir = tmp_dir("allow");
        let cfg = cfg_with(sh(r#"cat >/dev/null; printf '{"verdict":"allow"}'"#), &dir, false);
        assert_eq!(run(&cfg, b"{}"), Decision::Allow);
        assert!(action_taken(&dir));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn run_schema_invalid_fails_closed_without_action() {
        let dir = tmp_dir("schema");
        let cfg = cfg_with(
            sh(r#"cat >/dev/null; printf '{"verdict":"allow","extra":1}'"#),
            &dir,
            false,
        );
        assert_eq!(run(&cfg, b"{}"), Decision::DenyClass("schema_invalid"));
        assert!(!action_taken(&dir));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn run_host_mode_reserves_then_acts() {
        let dir = tmp_dir("host-novel");
        let verdict = r#"{"verdict":"allow","consume_nonces":[{"issuer_key":"1:2","nonce":"777","retain_until":4102444800}]}"#;
        let cfg = cfg_with(sh(&format!("cat >/dev/null; printf '%s' '{verdict}'")), &dir, true);
        assert_eq!(run(&cfg, b"{}"), Decision::Allow);
        let store = std::fs::read_to_string(dir.join("nonces")).unwrap();
        assert!(store.lines().any(|l| l.trim() == "777"));
        assert!(action_taken(&dir));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn run_host_mode_replay_denies_without_action() {
        let dir = tmp_dir("host-replay");
        std::fs::write(dir.join("nonces"), "777\n").unwrap();
        let verdict = r#"{"verdict":"allow","consume_nonces":[{"issuer_key":"1:2","nonce":"777","retain_until":4102444800}]}"#;
        let cfg = cfg_with(sh(&format!("cat >/dev/null; printf '%s' '{verdict}'")), &dir, true);
        assert_eq!(run(&cfg, b"{}"), Decision::DenyClass("replay"));
        assert!(!action_taken(&dir)); // the load-bearing §16.5 assertion
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn run_local_mode_ignores_consume_nonces() {
        let dir = tmp_dir("local-mode");
        let verdict = r#"{"verdict":"allow","consume_nonces":[{"issuer_key":"1:2","nonce":"777","retain_until":4102444800}]}"#;
        let cfg = cfg_with(sh(&format!("cat >/dev/null; printf '%s' '{verdict}'")), &dir, false);
        assert_eq!(run(&cfg, b"{}"), Decision::Allow);
        assert!(!dir.join("nonces").exists()); // local mode: verifier owns nonces
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn run_empty_verifier_cmd_is_spawn_error() {
        let dir = tmp_dir("no-cmd");
        let cfg = cfg_with(vec![], &dir, false);
        assert_eq!(run(&cfg, b"{}"), Decision::DenyClass("spawn_error"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // --- decision envelope (§16.2) -------------------------------------------

    #[test]
    fn decision_json_shapes_are_closed() {
        assert_eq!(Decision::Allow.to_json(), r#"{"decision":"allow"}"#);
        let deny: Value =
            serde_json::from_str(&Decision::DenyCode("expired".into()).to_json()).unwrap();
        assert_eq!(deny, json!({ "decision": "deny", "code": "expired" }));
        let fail: Value =
            serde_json::from_str(&Decision::DenyClass("timeout").to_json()).unwrap();
        assert_eq!(fail, json!({ "decision": "deny", "failure_class": "timeout" }));
    }
}
