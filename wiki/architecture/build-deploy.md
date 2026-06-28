---
title: Build and Deploy Pipeline
visibility: internal
sources:
  - landing/deploy.sh
  - landing/verify.sh
  - .github/workflows/ci.yml
  - .github/workflows/release.yml
  - .github/workflows/dco.yml
  - .github/workflows/docker-gateway.yml
last-updated: 2026-06-28
staleness-threshold: 30d
tags: [architecture, ci, deploy, s3, cloudfront, github-actions]
---

The landing page deploys via a manual shell script to S3 + CloudFront. CI runs on GitHub Actions. Package releases use OIDC trusted publishing to npm and PyPI.

## Overview

There are three distinct pipelines:

1. **Landing page** (`landing/deploy.sh`) -- manual S3 upload + CloudFront invalidation + post-deploy verification gate.
2. **CI** (`.github/workflows/ci.yml`) -- automated on push/PR to `main`. Tests SDK, integrations, conformance vectors, typechecking, dependency audit, and smoke tests.
3. **Release** (`.github/workflows/release.yml`) -- tag-triggered OIDC publish to npm (10 packages) and PyPI (4 packages).

## Key Concepts

- **No auto-deploy for the landing page.** It is a manual `./landing/deploy.sh` invocation. The site is static HTML, not a build output.
- **Post-deploy verification is non-negotiable.** After deploying, `verify.sh` runs string-match checks, runtime symbol resolution against published npm tarballs, a tamper-rejection cryptographic test, and GitHub link sanity checks. This was hardened after a 14-hour X402 outage in May 2026 where string-only verification missed a missing export.
- **Circuit and contract tests are local-only.** CI skips them because they require large `.ptau` files and a circom binary that are impractical on GitHub Actions runners.
- **OIDC trusted publishing.** No `NPM_TOKEN` or `PYPI_TOKEN` secrets. The release workflow exchanges a GitHub Actions OIDC token for a short-lived credential. Each package needs a Trusted Publisher configured on npmjs.com or pypi.org.

## How It Works

### Landing Page Deploy

**Infrastructure:**
- S3 bucket: `bolyra-ai-landing`
- CloudFront distribution: `E28JZX72HEYVTP`
- Domain: `bolyra.ai`

**Process (`landing/deploy.sh`):**

1. Validates that all HTML files exist locally (index, 402, blog-1..5, video pages, playground, benchmark, agent-spend).
2. Uploads each file to S3 with `text/html; charset=utf-8` content type and `max-age=300` cache control.
3. Each page is uploaded twice: with `.html` extension and without (for clean URLs like `bolyra.ai/402`).
4. JSX files (animations, system, scenes) are uploaded as `application/javascript`.
5. Creates a CloudFront invalidation for all paths and polls until completion (up to ~200 seconds).
6. Runs `verify.sh` unless `BOLYRA_SKIP_VERIFY=1` is set.

**Verification gate (`landing/verify.sh`):**

| Check | What it does |
|---|---|
| HTTP 200 | `bolyra.ai/` and `bolyra.ai/402` return 200 |
| Body size | `/402` body must be > 10KB |
| Required strings | Checks for `PAYMENT-REQUIRED`, `@bolyra/sdk`, `createX402Authorization`, `49 vectors`, ARIA attributes |
| Forbidden strings | Rejects stale tokens like `onclick="copyPanel"` |
| npm registry | `@bolyra/payment-protocols@0.3.1` must resolve |
| Runtime symbols | `npm install` the published packages, `require()` them, and verify every advertised function exists as a function (not undefined) |
| Tamper rejection | Loads pinned proof fixtures, verifies them, then flips one digit of `agentProof.pi_a[0]` and asserts `verified === false` |
| GitHub links | All CTA links to `github.com/bolyra/bolyra` return 200 (catches accidental re-privatization) |

Emergency bypass: `BOLYRA_SKIP_VERIFY=1 ./landing/deploy.sh`

### CI Pipeline (`.github/workflows/ci.yml`)

Triggers on push/PR to `main`. Concurrency group cancels in-progress runs for the same ref.

**Jobs (all run in parallel):**

| Job | What it tests |
|---|---|
| `sdk-tests` | `npm ci && tsc --noEmit && npm test` in `sdk/` |
| `openclaw-tests` | Build SDK locally, rewrite dep to `file:../../sdk`, typecheck + test |
| `mcp-tests` | Same pattern with SDK + receipts as file deps, excludes e2e tests |
| `payment-protocols-tests` | Same file-dep pattern, typecheck + test |
| `conformance` | `node spec/conformance-runner.js` (installs circuit deps, no compile) |
| `typecheck-all` | `tsc --noEmit` across sdk, openclaw, mcp, payment-protocols |
| `dependency-audit` | `npm audit --omit=dev --audit-level=high` per published package |
| `smoke-test` | Fresh `npm install` from npm registry + Python `pip install bolyra` -- imports and validates types |

**Not tested in CI:** Circuit compilation (needs circom + ptau), contract tests (need compiled circuits).

### DCO Check (`.github/workflows/dco.yml`)

Runs on all PRs. Walks every commit in the PR range and verifies each has a `Signed-off-by:` trailer matching the commit author.

### Release Pipeline (`.github/workflows/release.yml`)

Triggered by tag push matching `@bolyra/<pkg>@<version>` (npm) or `bolyra-python@<version>` / `bolyra-langchain@<version>` / `bolyra-agents@<version>` / `bolyra-crewai@<version>` (PyPI).

**npm publish flow:**
1. Parse tag into package name + version + directory.
2. Verify `package.json` version matches tag.
3. `npm install` (not `ci` -- npm 11+ lockfile compat).
4. Build if build script exists, test if test script exists (excluding e2e/integration).
5. `npm publish --provenance --access public` (SLSA attestation attached).
6. Poll npm registry for up to 30 seconds to confirm visibility.

**PyPI publish flow:**
1. Parse tag into version.
2. Verify `pyproject.toml` version matches tag.
3. `python3 -m build`, run subset of tests.
4. Publish via `pypa/gh-action-pypi-publish@release/v1`.
5. Poll PyPI for up to 60 seconds.

### Docker Gateway (`.github/workflows/docker-gateway.yml`)

Triggered by `gateway-v*` tags or PRs touching gateway files. Builds multi-arch (`amd64` + `arm64`) Docker image, pushes to `ghcr.io/bolyra/gateway`, runs a `/healthz` smoke test.

## Current Status

- Landing page: live at bolyra.ai, manually deployed.
- CI: 8 parallel jobs on every PR.
- Release: 10 npm packages + 4 PyPI packages configured for OIDC publishing.
- Docker gateway: published to GHCR.

## See Also

- [monorepo-layout.md](monorepo-layout.md) -- repository structure
- `SECURITY.md` -- known accepted residual Dependabot alerts
- `tasks/dependabot-cleanup-plan.md` -- override triage log
