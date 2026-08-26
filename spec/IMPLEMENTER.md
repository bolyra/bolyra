# Implementing an EVC host: how to prove you conform

This is the pass path for **anyone outside this repo** who has written (or wants
to write) a host that speaks the External Verifier Contract v1. You do not need
Bolyra's SDK, our circuits, our language, or our permission. You need Node 18+
to run the harness, and a host of your own.

The normative contract is [`external-verifier-contract-v1.md`](./external-verifier-contract-v1.md).
This file is the short operational path to a green run.

## 1. Run the suite (one command, no clone)

```sh
npx @bolyra/evc-conformance
```

Or from a clone of this repo (identical vectors — the npm package is a
checksummed snapshot of this directory):

```sh
git clone https://github.com/bolyra/bolyra && cd bolyra
node spec/conformance-runner.js --type host_behavior
```

Either way that runs **28 host-behavior vectors** against the bundled
reference host, with **no `npm install`** — the host suite uses only Node
builtins. Expect:

```
28 passed, 0 failed, 0 skipped
```

Exit code is `0` when everything passes and `1` on any failure, so it drops
straight into CI.

## 2. Point it at YOUR host

Set `HOST_CMD` to whatever command starts your host. Any language, as long as it
honors the convention in §3:

```sh
npx @bolyra/evc-conformance --host "/path/to/your-host --flags"
```

Add `--json` for a machine-readable result (vector-set version, count, and
SHA-256 included, so CI states exactly what it passed). From a clone, the
equivalent is `HOST_CMD="/path/to/your-host --flags" node
spec/conformance-runner.js --type host_behavior`.

Use an absolute path for your host: a relative path would resolve against the
runner's tree, not yours.

The runner spawns your host once per vector, writes one §2.1 request to its
stdin, and reads one decision from its stdout.

## 3. The Host-Under-Test contract (the whole thing)

Full normative text is §16.2. The operational summary:

**Your host reads** these environment variables and MUST honor them:

| Variable | Meaning |
|---|---|
| `HUT_VERIFIER_CMD` | JSON array (argv) you MUST spawn as your verifier — no substitutions |
| `HUT_TIMEOUT_MS` | wall-clock timeout you MUST enforce (§6) |
| `HUT_MAX_STDOUT_BYTES` | verifier stdout bound you MUST enforce; exceeding it fails closed |
| `HUT_NONCE_MODE` | `local` or `host` (§8) |
| `HUT_NONCE_STORE` | durable nonce-store path for host nonce mode; harness format is newline-delimited decimal nonces, UTF-8 |
| `HUT_ACTION_LOG` | append a non-empty marker **only** when you authorize the action — after reservation succeeds, immediately before `allow` |
| `HUT_FIXTURE_PIDFILE` | forward this to your spawned verifier so kill-proof vectors can confirm you killed it |

**Your host writes** exactly one decision object to stdout and exits `0`. The
fail-closed signal is the decision object, never your exit code. Exactly one of
three closed shapes — any extra field fails the vector:

```json
{"decision":"allow"}
{"decision":"deny","code":"<§9 denial code>"}
{"decision":"deny","failure_class":"<§16.3 class>"}
```

Use `code` when you are relaying the verifier's denial code unchanged — the
decision carries only the code, not the verifier's `message`, `kind`, or
`detail`. Use `failure_class` when *you* failed closed (broken verifier,
timeout, replay). Never both.

This decision envelope exists only for the harness. It is not part of the wire
contract (§2–§9) and constrains nothing about your production API.

## 4. Failure classes

When you fail closed, the harness asserts *why* — so an accidental deny does not
pass as a correct one:

| `failure_class` | Condition |
|---|---|
| `nonzero_exit` | verifier exited non-zero |
| `timeout` | your timeout fired and you killed the process |
| `signal_death` | verifier died by an unsolicited signal |
| `unparseable_stdout` | stdout empty, not JSON, or had trailing bytes |
| `multiple_objects` | stdout carried more than one JSON value |
| `oversize_stdout` | stdout exceeded your output bound |
| `schema_invalid` | a parsed verdict failed the §3.4 verdict schema |
| `replay` | a `consume_nonces` entry was already reserved |
| `spawn_error` | you could not spawn or drive the verifier at all |

Several conditions can co-occur for one input, so some vectors accept more than
one class (a verifier killed by a signal both dies by signal *and* leaves stdout
empty). Where a fixture triggers one unambiguous condition, the vector pins that
class — misclassifying it is flagged, because it reveals a real gap.

## 5. Troubleshooting

**Every vector fails with `decision must be "allow" or "deny", got undefined`.**
You are emitting the EVC *verdict* shape (`{"verdict":"allow"}`) instead of the
harness *decision* shape (`{"decision":"allow"}`). They are deliberately
different: the verdict is what your verifier told you, the decision is what you
did about it.

**The kill-proof vectors fail even though you kill the verifier.** You are not
forwarding `HUT_FIXTURE_PIDFILE` to the spawned verifier. A host that scrubs its
environment must still pass this one test-only variable through, or the kill
cannot be proven.

**Nonce vectors fail in host mode.** The harness pre-seeds `HUT_NONCE_STORE` to
stage replays and inspects it afterward. If your production store is SQLite or a
KV, point a thin test adapter at the file format; the format is a test
convention, not the wire contract.

**A deny passes but for the wrong reason.** Check your `failure_class` against
§16.3 — the harness asserts the specific violation you detected, not just that
you denied.

## 6. CI

A complete job for your repo — checkout, build your host, then run the suite:

```yaml
jobs:
  evc-conformance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5              # your repo
      - uses: actions/setup-node@v5
        with: { node-version: '20' }
      - run: make build                        # however your host gets built
      - uses: actions/checkout@v5              # the contract + fixtures
        with: { repository: bolyra/bolyra, path: evc }
      - run: HOST_CMD="$GITHUB_WORKSPACE/build/your-host --flags"
             node evc/spec/conformance-runner.js --type host_behavior
```

No install step for the suite itself, and a non-zero exit fails the job.

## 7. The rest of the suite

`--type host_behavior` is the part that matters for a host implementer and the
part that runs dependency-free. The full run (`npm run conformance`, 112 vectors)
also covers handshake, signature, Merkle, and delegation vectors against this
repo's circuits — those need `npm install` and are about *our* implementation,
not yours.

## 8. Tell us it passed

If your host goes green we would like to know, and we will list it. Open an issue
on this repo. If something in this path is wrong, unclear, or assumes context you
do not have, that is a bug in this document and worth an issue on its own — a
contract only one implementer can pass is not a contract.

## 9. Independent implementations

Implementations of the EVC host boundary written outside this repo, from the
normative text, listed with maintainer permission after a harness-green run at a
pinned public commit. This table records pinned conformance evidence, not every
project that has discussed or partially mapped to EVC.

Permission basis: mcp-use#1835, "Feel free to use the example repo however you
want."

| Implementation | Language / host stack | Verified | Result |
|---|---|---|---|
| [`khandrew1/mcp-use-evc-example`](https://github.com/khandrew1/mcp-use-evc-example) | TypeScript, behind mcp-use's `mcp:tools/call` middleware | commit `17642a5`, 2026-08-26 | 27/27 `host_behavior`, vector set 0.5.0 |

Per that repo's own framing: EVC is an independent third-party contract and is
not part of MCP or mcp-use. Listing here records conformance of the example's
host boundary; it does not imply endorsement of EVC by mcp-use or vice versa.
