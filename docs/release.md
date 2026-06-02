# Releasing @bolyra/* packages

This is the maintainer runbook for cutting a release. Reader audience: anyone
with push access to `bolyra/bolyra` and maintainer rights on the @bolyra
npm scope. There is no manual `npm publish` step anymore — tags trigger the
[`release.yml`](../.github/workflows/release.yml) workflow, which authenticates
to npm via GitHub Actions OIDC and attaches a signed provenance attestation.

## One-time setup (already complete; reference only)

Three things had to exist before tag-driven publishing worked:

1. **GitHub environment `npm-publish`** on `bolyra/bolyra`. No protection
   rules attached. Add manual-reviewer gating later via repo Settings →
   Environments → npm-publish if you want a checkpoint between tag push and
   publish.
2. **Trusted Publisher** config on each npm package
   (`@bolyra/{sdk,payment-protocols,mcp,openclaw}`). On npmjs.com:
   package → Settings → Trusted Publisher → Add, with:
   - Publisher: GitHub Actions
   - Organization or user: `bolyra`
   - Repository: `bolyra`
   - Workflow filename: `release.yml`
   - Environment: `npm-publish`
3. **No npm tokens.** Every previously issued token at
   https://www.npmjs.com/settings/saneguy/tokens has been revoked. If you
   find yourself reaching for `NPM_TOKEN`, something is wrong — the OIDC
   flow needs no secrets.

## Per-package patch release (the common path)

Use this for hotfixes that touch one package. Versions diverge across the
cohort — see CHANGELOG cohort table for the current floor. Example below
uses `@bolyra/sdk` going from 0.3.1 → 0.3.2.

### 1. Bump the version on main

```bash
git checkout main && git pull --ff-only
cd sdk
npm version patch --no-git-tag-version    # 0.3.1 → 0.3.2
cd ..
```

For minor / major bumps, use `npm version minor` / `npm version major`.

### 2. Update CHANGELOG

Add a section above the current top entry:

```markdown
## [@bolyra/sdk 0.3.2] — YYYY-MM-DD

Single-package hotfix; cohort otherwise unchanged.

### Fixed
- ...
```

Update the cohort table at the top of the new section to reflect the new
floor for this package.

### 3. Commit + push (still on main)

```bash
git add sdk/package.json CHANGELOG.md
git commit -s -m "release: @bolyra/sdk@0.3.2 — <one-line summary>"
git push origin main
```

Wait for CI on this commit to go green. The release workflow does not run
yet — only the tag triggers it.

### 4. Tag + push the tag

```bash
git tag -a -s '@bolyra/sdk@0.3.2' -m "@bolyra/sdk v0.3.2

<release notes — usually the CHANGELOG section, lightly trimmed>

Signed-off-by: Your Name <you@example.com>"

git push origin '@bolyra/sdk@0.3.2'
```

The `-s` flag uses your SSH signing key (configured per `CONTRIBUTING.md`
"Signing commits and tags"). GitHub will display the green "Verified" badge
once your SSH signing key is registered.

### 5. Watch the workflow

```bash
gh run watch
```

Or visit the Actions tab. The workflow:

1. Parses the tag → package + version.
2. Checks out the source.
3. Verifies the tag version matches `<dir>/package.json`'s version.
4. Runs `npm ci`, `npm run build` (if present), `npm test` (if present).
5. `npm publish --provenance --access public` over OIDC.
6. Polls the registry to confirm the new version resolves.

On success the package is live and `npm view @bolyra/<pkg> version` returns
the new version. The provenance attestation is visible at
https://www.npmjs.com/package/@bolyra/<pkg> → Versions → click version →
"Provenance" tab.

## Cohort release (v0.x.0)

The cohort moves on minor/major bumps. When that happens — the active
pattern has been per-package patches for a while — extend `release.yml`
to handle `v*` tags that publish all four packages in one workflow run.
That's deferred until the cohort actually moves.

## Things that will go wrong (and what to do)

### `npm publish` fails with 401 / "needs to publish from a trusted publisher"

The Trusted Publisher config on npmjs.com is missing or mismatched for that
package. Common shapes:
- Wrong workflow filename — must be exactly `release.yml`, not
  `.github/workflows/release.yml`.
- Wrong environment — must be exactly `npm-publish`.
- Wrong org or repo — case-sensitive.

Fix on npmjs.com, re-push the tag (delete + recreate locally + force-push
the tag — see "Re-running a failed release" below).

### Version mismatch

The workflow asserts tag version === package.json version. If they diverge,
fix `package.json` on main, push a fix-up commit, delete and recreate the
tag pointed at the new commit, push the tag.

### Re-running a failed release

If the workflow failed before the publish step actually shipped to npm (the
"Verify on registry" step is the canonical check — it polls `npm view`):

```bash
# Re-trigger the workflow by deleting and re-pushing the tag.
git tag -d '@bolyra/sdk@0.3.2'
git push origin :refs/tags/'@bolyra/sdk@0.3.2'

# Fix the underlying issue, then re-create the tag at the new HEAD.
git tag -a -s '@bolyra/sdk@0.3.2' -m "..." HEAD
git push origin '@bolyra/sdk@0.3.2'
```

If the workflow failed *after* npm publish succeeded (rare — usually the
post-publish registry verify), do **not** re-publish. The version is on
npm. Move on; the next bump publishes cleanly. npm versions are immutable
within 72h, deletion-then-re-publish is not how to fix things.

### Provenance attestation fails to attach

`npm publish --provenance` requires npm CLI ≥ 9.5. The workflow pins
`actions/setup-node@v6` with `node-version: 22`, which ships a recent
enough npm. If you see provenance errors, the runner image probably
changed — pin npm explicitly with `npm install -g npm@latest` before the
publish step.

## Pre-OIDC history

Versions through 2026-06-02 were published manually via `npm publish` from
a maintainer laptop using personal access tokens. Four tokens leaked
through chat transcripts during that period; all have been revoked. From
@bolyra/sdk@0.3.2 (and the next patch of every other package) onward,
every release ships with a provenance attestation and no long-lived
credential ever touches disk.
