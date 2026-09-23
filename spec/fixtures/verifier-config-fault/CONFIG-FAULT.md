# `verifier_config_fault` — testing §7.1 when no request can reach it

§7.1 and the §9 registry row bind `internal_error` to a **non-zero exit**, and it is
the only code in the registry that sets one. The `verifier_envelope` class could not
test that rule.

## Why a request cannot do it

The suite's only probe that reached an `internal_error` path was `null` on stdin, and
it worked by accident: `typeof null === 'object'` defeats the natural guard, the
subsequent property read throws, and the outer handler reports `internal_error`. Once
an implementer classifies `null` correctly as `malformed_input`, that probe is gone.

Nothing replaces it, because **a request that induces `internal_error` in a verifier is
almost always a misclassification the implementer should fix.** That is an empirical
finding from an external implementer, not a proof of impossibility: every request case
they investigated turned out to be a bug they then corrected
(`stillmarcus24/x402-authority-verifier-kit#1`, 2026-09-23).

## The portable inducer: a config fault

Corrupt the verifier's **own trust configuration**, then send a request it would
otherwise answer. Only two things about that are portable, and this vector asserts
exactly those:

1. the fault yields `deny code=internal_error`, and
2. the exit status is non-zero.

Everything else is implementation-specific and is supplied by env:

| Variable | Meaning |
|---|---|
| `VERIFIER_CMD` | the verifier command (as elsewhere) |
| `VERIFIER_FAULT_CMD` | shell command that corrupts the verifier's trust configuration |
| `VERIFIER_FAULT_UNDO_CMD` | shell command that restores it — run in a `finally` |
| `VERIFIER_VALID_REQUEST` | path to a request that reaches the trust check when healthy |

**A valid request cannot be supplied by this suite.** The trust check runs after root
recovery, so the request must carry a chain that actually verifies, and the bundle is
opaque per spec. Each implementation supplies its own.

## What is deliberately NOT a failure

- **Missing hooks → SKIP.** An implementation that cannot express a config fault is not
  thereby non-conforming.
- **A deny with some other code → SKIP.** Nothing in the contract obliges every verifier
  to classify a config fault as `internal_error`, so such a rejection is neither a
  failure nor exercised §7.1 coverage.
- **An `allow` under the fault → always FAIL.** A trust source that is present but
  unusable must never silently disable trust enforcement.

## Red/green against a real implementation

Stub verifiers (`stub-exit0.cjs`, `stub-exit1.cjs`, driven by
`test-config-fault.cjs`) exercise the runner's assertion. They are not the proof — a
stub tests the assertion, not a real failure path. The proof is two commits of one
external verifier:

| Pin | Behavior under the fault | Vector |
|---|---|---|
| `660902f6` | corrupt trust store silently became "not enforced" → `allow` | **FAIL** (fail-open) |
| `1aa9d88` | `deny code=internal_error`, exit 1 | **PASS** |

At `660902f6` the vector catches the **fail-open first** — the more severe defect — and
the exit-code violation was masked behind it. One vector, two defect classes, in
severity order.

Recipe used (`state/` is gitignored in that kit, so a cold clone has no store to
corrupt and the write fails before it reaches the verifier — `mkdir -p` is required):

```sh
VERIFIER_FAULT_CMD="mkdir -p <kit>/state && printf '{ not json' > <kit>/state/trusted-issuers.json"
VERIFIER_FAULT_UNDO_CMD="rm -f <kit>/state/trusted-issuers.json"
```

## Known gap

The registry row covers "unexpected failure, missing circuit artifacts, or **missing**
trust configuration". A trust source that is **present but unusable** is not named, and
its required behavior and error classification are not yet specified. This vector
therefore asserts the fail-open prohibition as a security property while treating the
`internal_error` classification as opt-in per implementation. Specifying it is
deferred, not decided here.
