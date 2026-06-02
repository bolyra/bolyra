# Contributing to Bolyra

Thank you for your interest in contributing. This document covers the legal,
practical, and stylistic ground rules for contributing code, documentation, or
specifications to the Bolyra project.

## License of contributions

Bolyra is licensed under the **Apache License, Version 2.0** (see `LICENSE` and
`NOTICE`). By submitting any Contribution, you agree that your Contribution is
licensed to the project and to recipients of the project's distributions under
the same Apache License 2.0, including the Section 3 patent grant.

## Developer Certificate of Origin (DCO)

Bolyra uses the **Developer Certificate of Origin (DCO) v1.1** instead of a
contributor license agreement (CLA). The DCO is a lightweight per-commit
attestation that you have the right to submit your contribution under the
project's license. The full text lives at https://developercertificate.org/
and is reproduced below for convenience:

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.
1 Letterman Drive
Suite D4700
San Francisco, CA, 94129

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

### How to sign off

Every commit must include a `Signed-off-by` line matching the author identity:

```
git commit -s -m "fix: handle empty proof input"
```

This appends:

```
Signed-off-by: Your Name <you@example.com>
```

If you forget, amend with:

```
git commit --amend -s --no-edit
```

For multi-commit branches, sign off each commit. Use `git rebase -i --signoff`
to backfill an existing branch. The DCO check on every pull request will block
merges that contain unsigned commits.

### How DCO differs from a CLA

A CLA typically grants the project owner additional rights (e.g., relicensing
authority) beyond the inbound license. The DCO does not — it only attests that
you have the right to submit your contribution under the project's existing
license. Linux, Kubernetes, GitLab, and most CNCF projects use DCO for the
same reason: it lowers contribution friction and avoids creating an asymmetric
rights pool.

## Pull request workflow

1. Fork the repository and create a feature branch from `main`.
2. Make focused, atomic commits. One logical change per commit.
3. Run the test suite locally before pushing.
4. Open a pull request with a clear description of the change and the
   motivation. Reference any related issue.
5. The DCO action will verify Signed-off-by lines on each commit.
6. CI must pass. Reviewers may request changes.

## Coding conventions

- TypeScript: strict mode, no `any` unless explicitly justified in a comment.
- Solidity: follow the project's existing style (no opinionated formatter
  configured yet — keep diffs minimal).
- Circom: keep circuit constraints minimal; document any new public input.
- Tests: write a failing test before fixing a bug.

## Signing commits and tags

DCO sign-off (the `Signed-off-by:` trailer) is a legal attestation, not a
cryptographic signature. Separate from DCO, contributors may cryptographically
sign their commits and maintainers must sign release tags. Both use the same
SSH key configuration.

### One-time setup (SSH signing)

```bash
# Tell git to sign with SSH instead of GPG
git config --global gpg.format ssh

# Point at your SSH public key (any key already on your GitHub account works)
git config --global user.signingkey ~/.ssh/id_ed25519.pub

# Auto-sign tags (maintainers — required for release tags)
git config --global tag.gpgsign true

# Optional: auto-sign every commit (contributors — recommended)
git config --global commit.gpgsign true
```

Then upload the same public key to GitHub a second time as a **signing key**:
Settings → SSH and GPG keys → New SSH key → Key type "Signing Key". The same
key can be registered for both authentication and signing — they're separate
entries. Once registered, GitHub displays a "Verified" badge next to your
commits and tags.

### Verifying signatures locally

```bash
echo "$(git config user.email) $(cat ~/.ssh/id_ed25519.pub | cut -d' ' -f1-2)" >> ~/.ssh/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.ssh/allowed_signers
```

Then `git log --show-signature` and `git tag -v <tag>` will show signature
status.

### Release tags (maintainer policy)

All cohort releases (`v0.x.0`) and per-package patches
(`@bolyra/<pkg>@0.x.N`) must carry a verified signature. Force-pushing or
rewriting a published signed tag is prohibited.

## Reporting security issues

Do not file public issues for security vulnerabilities. See `SECURITY.md` for
the responsible-disclosure process.

## Trademarks

"Bolyra" and any related marks are subject to the trademark policy in
`TRADEMARKS.md`. Forks must not use the Bolyra name in a way that implies
endorsement or origin.
