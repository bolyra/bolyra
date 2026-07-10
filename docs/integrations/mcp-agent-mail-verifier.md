# Integrating `bolyra verify` as an external verifier for mcp_agent_mail

This is the host integration guide for wiring Bolyra's external verifier into a
host that exposes a **pluggable, spawned-subprocess verifier slot** — the shape
[`Dicklesworthstone/mcp_agent_mail_rust#183`](https://github.com/Dicklesworthstone/mcp_agent_mail_rust/issues/183)
defined: one JSON request in on stdin, one verdict object out on stdout,
fail-closed on anything else.

> This is a **local** integration guide. It documents how a host adopts the
> contract; it does not contact the upstream repo.

The full wire contract is normative in
[`spec/external-verifier-contract-v1.md`](../../spec/external-verifier-contract-v1.md);
this document is the host-side application of it. Section references (§) below
point at that contract unless noted.

## 1. Configure the verifier

Point the host's external-verifier slot at `bolyra verify` and give it a
wall-clock timeout. The host owns the timeout (§6); the verifier does not
implement its own.

```
# mcp_agent_mail host configuration — external verifier
BOLYRA_VERIFIER_CMD="bolyra verify --nonce-mode host"
BOLYRA_VERIFIER_TIMEOUT_MS=10000
```

- `--nonce-mode host` selects **host-owned replay storage** (§8): the verifier
  stays stateless and returns a `consume_nonce` the host durably records. Use this
  mode for any multi-instance / clustered host that already owns a database. (Drop
  the flag to use the default `local` mode, where the verifier owns a file-backed
  nonce store — only correct for a single-host deployment.)
- `10000` ms (10 s) is the recommended timeout (§6): the verifier targets < 2 s
  p99, so 10 s is generous headroom for a cold start plus Groth16 verification.

The verifier also needs a **trusted-root source** and (optionally) a
**capability map**. If no trusted-root source is configured it fails closed
(`deny code=internal_error`, non-zero exit) — it never treats "no roots
configured" as "all roots trusted". A fuller command line:

```
bolyra verify --nonce-mode host \
  --roots-file /etc/bolyra/trusted-roots.json \
  --capability-map /etc/bolyra/mcp-agent-mail-capabilities.json
```

## 2. The host flow (agent registration)

On the privileged action the host guards (e.g. agent registration), the host:

1. **Builds the request** (§2.1). The host fills in its **own** capability tokens
   in `granted_capabilities` and its **own** wall clock in `now_unix`. The
   `bundle` string is opaque — the host copies it through from the agent's
   presentation without inspecting it.

   ```json
   {
     "version": 1,
     "bundle": "<opaque proof string presented by the agent>",
     "request": {
       "agent_name": "BlueLake",
       "project_key": "/data/projects/backend",
       "program": "claude-code",
       "model": "opus-4.1",
       "granted_capabilities": ["send_message", "fetch_inbox"]
     },
     "now_unix": 1751990400
   }
   ```

2. **Spawns** `bolyra verify --nonce-mode host` with the configured timeout.

3. **Writes** the request object to the child's stdin and **closes stdin**
   (EOF). Exactly one object, no trailing bytes (§2).

4. **Reads** the child's stdout as **exactly one** JSON object with no trailing
   bytes (§5.2). A lenient parser that reads only the first of several
   concatenated objects **must not** be used — multiple objects is a fail-closed
   condition.

5. **Decides, fail-closed** (§7):
   - `verdict: "allow"` → **reserve-before-act** (below), then proceed.
   - anything else — `verdict: "deny"`, a non-zero exit, a timeout, death by
     signal, or unparseable/oversized/multi-object stdout — → **reject the
     registration**.

The host **must** treat all of these as deny, regardless of what (if anything)
reached stdout: non-zero exit, timeout, signal death, empty/oversized/unparseable
stdout, an unknown `verdict` value, or a `deny` missing `code`/`message` (§7.2).

## 3. Reserve-before-act (mandatory in host nonce mode)

Under `--nonce-mode host`, an `allow` carries a `consume_nonce`:

```json
{
  "verdict": "allow",
  "consume_nonce": {
    "issuer_key": "z6Mk...",
    "nonce": "e3b0c44298fc1c14...",
    "retain_until": 1751993600
  }
}
```

The host **must reserve the nonce before acting** (§7.3):

1. **Atomically insert** `consume_nonce.nonce` into durable storage with a
   unique-insert / "on conflict reject" semantic, retaining it until
   `retain_until`.
2. If the insert is **novel**, proceed with the registration.
3. If the insert **conflicts** (the nonce was already recorded), **reject** the
   action as a replay — even though the verifier returned `allow`.

"Record after proceeding" opens a replay window and is **forbidden**. The
verifier's `allow` in host mode is *conditional* on the host's insert being novel.
`consume_nonce.issuer_key` is for host bookkeeping only; the `nonce` is already
globally unique per (credential, session-nonce).

## 4. Reference host glue (language-neutral)

```
fn verify_registration(bundle, request_ctx, now_unix) -> Decision {
    let req = json!({
        "version": 1,
        "bundle": bundle,                       // opaque passthrough
        "request": request_ctx,                 // host's capability tokens
        "now_unix": now_unix,                   // host's wall clock
    });

    // Spawn with the host-owned timeout (§6).
    let child = spawn("bolyra verify --nonce-mode host", timeout_ms = 10_000);
    write(child.stdin, req.to_string());
    close(child.stdin);
    let (status, stdout, _stderr) = wait(child);

    // Fail-closed gate (§7.2).
    if timed_out(child)            { return Decision::Reject("timeout"); }
    if status != 0                 { return Decision::Reject("non-zero exit"); }

    // Strict single-object parse (§5.2): reject trailing bytes / multiple objects.
    let verdict = match parse_single_json_object(stdout) {
        Some(v) => v,
        None    => return Decision::Reject("unparseable stdout"),
    };

    match verdict["verdict"].as_str() {
        Some("allow") => {
            if let Some(cn) = verdict.get("consume_nonce") {
                // Reserve-before-act (§7.3): atomic unique-insert.
                if !reserve_nonce_atomic(cn["nonce"], cn["retain_until"]) {
                    return Decision::Reject("nonce replay");
                }
            }
            Decision::Proceed
        }
        Some("deny")  => Decision::Reject(verdict["code"].as_str().unwrap_or("deny")),
        _             => Decision::Reject("unknown verdict"),   // §7.2
    }
}
```

Note that `internal_error` arrives as **both** `deny code=internal_error` on
stdout **and** a non-zero exit, so the `status != 0` gate above already rejects it
before the verdict is even inspected — the host fail-closes on either signal.

## 5. What the host does not need to know

The `bundle` is opaque (§2.1). The host never parses proofs, never learns the
`bvp/1` structure, and never runs cryptography itself. It only needs the four
steps above: spawn, write the request, read one verdict, fail-closed otherwise.
That is the whole point of the contract — Bolyra verification becomes a drop-in
subprocess for any host that adopts the spawn shape, and the denial-code registry
(§9) is the stable vocabulary the host can branch on for user-facing messaging.

## References

- Normative wire contract:
  [`spec/external-verifier-contract-v1.md`](../../spec/external-verifier-contract-v1.md)
- Denial-code registry and IO-contract framing:
  [`spec/CONFORMANCE.md`](../../spec/CONFORMANCE.md)
- Design and verification algorithm (PDLC design spec):
  `docs/superpowers/specs/2026-07-08-external-verifier-cli-design.md`
