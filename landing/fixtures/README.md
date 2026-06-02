# landing/fixtures/

Pinned proof artifacts used by `landing/verify.sh` to runtime-test the
1-byte tamper-rejection claim shown on the `#zk-demo` section of
`bolyra.ai`.

These are byte-identical copies of `sdk/demo/{humanProof.json,
agentProof.json, nonce.txt}` from the `@bolyra/sdk@0.3.0` release.
They are duplicated here (not symlinked) so the deploy verifier
remains a self-contained, single-purpose gate: it does not depend on
the SDK source layout, and it does not require a fresh proof run.

The verification keys are sourced from the published
`@bolyra/payment-protocols` tarball (`vkeys/`) which `verify.sh`
installs into a tmpdir as part of the runtime symbol-resolution step.
That keeps the contract honest: the verifier runs against exactly the
artifacts a downstream consumer would pull from npm.

If `sdk/demo/` is ever regenerated, refresh these files too.
