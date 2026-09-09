# Interop replay harness

Every external interoperability claim Bolyra publishes (in
`spec/IMPLEMENTER.md`, the IETF draft's Implementation Status section, or the
landing page) must be mechanically reproducible from pins alone. This
directory is that mechanism.

```
node interop/replay.js            # replay every claim in claims.json
node interop/replay.js --check    # offline: validate registry + suite pins
node interop/replay.js --claim <id> --keep
```

## How a claim replays

`claims.json` pins four things per claim: the implementer's repo + commit,
our conformance-suite commit, the sha256 of that suite's `test-vectors.json`,
and the expected pass/fail/skip counts. `replay.js` shallow-clones the
implementer at its pin, materializes the suite via `git archive` at its pin
(so replaying needs full history — `git fetch --unshallow` on shallow
clones), verifies the vector digest, installs the implementer's dependencies
from its own lockfile with `--ignore-scripts`, and drives its host through
the pinned runner via the committed HUT adapter.

## Claim kinds

- **`bolyra-suite`** (default): our pinned conformance runner drives the
  implementer's host through a committed HUT adapter. The result is
  Bolyra-suite conformance.
- **`external-suite`**: the implementer's OWN test command replayed at its
  pin inside a digest-pinned container with networking disabled. The result
  is an **own-corpus reproduction** — it shows the implementer's published
  numbers reproduce, and says nothing about conformance to this repo's
  vectors. `claim_text` must carry that distinction.

## Rules

- **A red replay means investigate, never edit the claim.** Claims are
  historical statements about pinned commits. If a replay breaks, either the
  environment changed (fix the harness) or the published record is wrong
  (correct it everywhere it appears, loudly).
- **Adapters are pure I/O.** An adapter bridges the §16.2 HUT convention to
  the implementer's API and maps its distinct error messages 1:1 onto §16.3
  classes. It never adds behavior; an unmapped error exits non-zero and fails
  the vector rather than guessing a class.
- **Claims stay pinned.** New suite versions never retroactively apply to an
  existing claim; a re-verification at a newer set is a NEW claim row.
- **Third-party code runs here.** Installs use `--ignore-scripts` and pinned
  lockfiles, but replaying still executes the implementer's host code. Run
  in CI's ephemeral runner (the `interop-replay` workflow) or a container
  when the pin has not been run before.

## CI

`.github/workflows/interop-replay.yml` runs the full replay on
`workflow_dispatch`. It is deliberately not part of per-push CI: it needs
network access to third-party repos and its failure modes (upstream deleted
a repo, GitHub outage) are not push-regressions. Run it before citing any
claim in a new public document, and after any conformance-runner change.
