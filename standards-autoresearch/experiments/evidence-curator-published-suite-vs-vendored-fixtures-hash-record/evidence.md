# Evidence: registry-closure freshness record for vector set 0.6.0

**Artifact type:** third-party-reproducible run record (`registry_event`)
**Pinned commit:** `a4f546f3279706a2b28a0c15569c0040425e84c7` (`bolyra/bolyra`, `main`)
**Alignment triple under test:** spec revision `2026-08-26` · vector set `0.6.0` · npm `@bolyra/evc-conformance@0.2.0`
**Status:** procedure staged; hash values are to be recorded by whoever executes it. The loop's generator does not execute commands, so no hashes appear below as facts.

## Claims

Claim A (offline, repo-only): At commit `a4f546f3279706a2b28a0c15569c0040425e84c7`, the host-conformance fixture set under `spec/fixtures/host-conformance/` and the vendored copy inside `integrations/evc-conformance/` are byte-identical as judged by `sync:check` and by an independent sha256 manifest.

Claim B (third-party, one read-only registry fetch): The vendored fixtures inside the published `@bolyra/evc-conformance@0.2.0` tarball produce the same sha256 manifest as the spec-tree fixture set at that commit.

Neither claim says anything about correctness of the vectors. Both say only that the bytes match.

## Why this record exists

REGISTRY CLOSURE is scored on suite freshness and `sync:check` being green, but until now the only witness was CI. This record gives an outside reviewer a way to confirm, without trusting CI, that what npm serves as vector set 0.6.0 is what the spec tree defines. It also detects the stale-pin failure class described in the repo's own guidance: a gate that passes green while the artifact under test has drifted.

## Preconditions

- A local checkout of `bolyra/bolyra` that contains commit `a4f546f3279706a2b28a0c15569c0040425e84c7`.
- Node 20+, `git`, `shasum` (or `sha256sum`), `diff`, `find`, `sort`, `tar`.
- Part B additionally requires `npm` and one outbound read of the public npm registry, performed by the third party, not by the loop. If the tarball is already in the local npm cache, `npm pack --offline` avoids that fetch.

## Scratch workspace

Every step below runs inside ONE fresh temporary directory. Nothing writes to `spec/`, to the local checkout, or to any repo tree. Set it up once:

```sh
SCRATCH="$(mktemp -d)"
LOCAL_CHECKOUT="/path/to/your/bolyra/checkout"   # replace; read-only source
git clone --no-hardlinks --quiet "$LOCAL_CHECKOUT" "$SCRATCH/bolyra"
git -C "$SCRATCH/bolyra" checkout --quiet a4f546f3279706a2b28a0c15569c0040425e84c7
git -C "$SCRATCH/bolyra" rev-parse HEAD
```

Expected output of the last line, exactly:

```
a4f546f3279706a2b28a0c15569c0040425e84c7
```

If it differs, stop. Every later hash is meaningless against a different commit.

## Part A: offline record from the pinned tree

### A1. Confirm the vendored copy matches the spec tree via the repo's own gate

```sh
cd "$SCRATCH/bolyra/integrations/evc-conformance"
npm run sync:check
echo "sync:check exit=$?"
```

Expected: the script reports no differences and the final line is `sync:check exit=0`.

Notes for the executor:

- Do not run `npm install` first. The package declares zero runtime dependencies and `sync:check` is a plain Node script. If it fails because a module is missing, record that as a finding rather than installing anything.
- Read `integrations/evc-conformance/scripts/sync.js` to learn the exact vendored directory it compares against. The rest of this record refers to that directory as `VENDORED_DIR`. Do not assume its name.
- The Tier 1 judgment for this candidate reported that a read-only `sync:check` at this commit covers 31 vendored files plus a MANIFEST. Treat that count as something to confirm, not as an input.

### A2. Independent sha256 manifest of the spec-tree fixture set

```sh
cd "$SCRATCH/bolyra"
find spec/fixtures/host-conformance -type f | LC_ALL=C sort \
  | xargs shasum -a 256 > "$SCRATCH/spec-fixtures-0.6.0.sha256"
wc -l < "$SCRATCH/spec-fixtures-0.6.0.sha256"
```

Expected:

- One row per file. The vector index states 28 `host_behavior` vectors for set 0.6.0; the row count will be 28 plus index, manifest, README, or fixture-script files that live in the same directory. Record the actual count.
- Record the row for the vector index file, and, if present, a row for `test-vectors.json`. The judge's note singles out `vendor/test-vectors.json` as the vector definition that matters; fixture scripts in the same tree are helpers, not definitions.

### A3. Same manifest over the vendored directory, then compare

```sh
cd "$SCRATCH/bolyra"
VENDORED_DIR="integrations/evc-conformance/<path read from scripts/sync.js>"
( cd "$VENDORED_DIR" && find . -type f | LC_ALL=C sort | xargs shasum -a 256 ) \
  | sed 's#  \./#  #' > "$SCRATCH/vendored-0.6.0.sha256"

# Normalize the spec manifest to the same relative form before diffing.
sed 's#  spec/fixtures/host-conformance/#  #' "$SCRATCH/spec-fixtures-0.6.0.sha256" \
  > "$SCRATCH/spec-fixtures-0.6.0.rel.sha256"

diff "$SCRATCH/spec-fixtures-0.6.0.rel.sha256" "$SCRATCH/vendored-0.6.0.sha256"
echo "diff exit=$?"
```

Expected: `diff exit=0` with no output above it.

If `sync.js` vendors a subset or renames files, the two manifests will differ by design in file set but not in content hashes for shared files. In that case record the diff verbatim and compare only the intersection with:

```sh
join -j 2 <(sort -k2 "$SCRATCH/spec-fixtures-0.6.0.rel.sha256") \
          <(sort -k2 "$SCRATCH/vendored-0.6.0.sha256") \
  | awk '$2 != $3 { print "MISMATCH", $1 }'
```

Expected: no output. Any `MISMATCH` line contradicts Claim A.

### A4. Confirm the alignment triple from the pinned tree

```sh
cd "$SCRATCH/bolyra"
grep -n 'Document revision' spec/external-verifier-contract-v1.md
node -e 'console.log(require("./integrations/evc-conformance/package.json").version)'
grep -rn '"0\.6\.0"' spec/fixtures/host-conformance | head
```

Expected:

- The spec header line contains `2026-08-26`.
- The package version prints `0.2.0`.
- At least one fixture-index or manifest row pins vector set `0.6.0`.

A mismatch in any of the three is a registry-closure finding and should be recorded as such, even if the byte comparison in A3 passed.

### A5. Manifest-of-manifests (the single value a third party quotes)

```sh
shasum -a 256 "$SCRATCH/spec-fixtures-0.6.0.rel.sha256"
```

Record this one hash as `MANIFEST_SHA256`. It is the value a reviewer publishes alongside the pinned commit. Two people who obtain the same `MANIFEST_SHA256` from the same commit have compared identical fixture sets without exchanging any files.

## Part B: third-party comparison against the published tarball

This part is executed by a third party. It requires one read-only fetch of a public npm tarball. It performs no writes outside the scratch workspace.

```sh
cd "$SCRATCH"
mkdir tarball && cd tarball
npm pack @bolyra/evc-conformance@0.2.0        # add --offline if already cached
tar -xzf bolyra-evc-conformance-0.2.0.tgz
ls package
```

Expected: a `package/` directory whose layout contains the same vendored directory name found in A3.

```sh
cd "$SCRATCH/tarball/package/<VENDORED_DIR relative to package root>"
find . -type f | LC_ALL=C sort | xargs shasum -a 256 | sed 's#  \./#  #' \
  > "$SCRATCH/tarball-vendored-0.2.0.sha256"
diff "$SCRATCH/vendored-0.6.0.sha256" "$SCRATCH/tarball-vendored-0.2.0.sha256"
echo "diff exit=$?"
```

Expected: `diff exit=0`. This substantiates Claim B.

Optional provenance cross-check, also read-only:

```sh
npm view @bolyra/evc-conformance@0.2.0 dist.integrity dist.attestations.url
```

Expected: an `sha512-...` integrity string and an attestations URL. Record both. They tie the tarball you hashed to the registry's own record of the release.

## What a failure means

| Observed | Meaning |
|---|---|
| A1 non-zero | Vendored copy has drifted from `spec/` at this commit. CI's green state is not trustworthy for this version. |
| A3 mismatch, A1 zero | `sync.js` compares something narrower than the full fixture tree. Record the gap; it is a finding for the conformance package, not a spec finding. |
| A4 triple mismatch | Stale pin. The exact failure class the repo guidance warns about. |
| B mismatch, A passes | The npm release was cut from a tree other than this commit, or post-publish edits occurred. Record the tarball integrity string. |

## Cleanup

```sh
rm -rf "$SCRATCH"
```

## Ledger entry

```json
{"id": "registry-event-vector-set-0.6.0-fixture-manifest-a4f546f", "kind": "registry_event", "subject": "@bolyra/evc-conformance@0.2.0 vendored fixtures vs spec/fixtures/host-conformance at pinned commit (vector set 0.6.0, spec revision 2026-08-26)", "pinned_commit": "a4f546f3279706a2b28a0c15569c0040425e84c7", "reproduce_cmd": "SCRATCH=$(mktemp -d); git clone --no-hardlinks -q <local-checkout> $SCRATCH/bolyra; git -C $SCRATCH/bolyra checkout -q a4f546f3279706a2b28a0c15569c0040425e84c7; (cd $SCRATCH/bolyra/integrations/evc-conformance && npm run sync:check); (cd $SCRATCH/bolyra && find spec/fixtures/host-conformance -type f | LC_ALL=C sort | xargs shasum -a 256 | sed 's#  spec/fixtures/host-conformance/#  #' > $SCRATCH/m.sha256 && shasum -a 256 $SCRATCH/m.sha256)", "urls": ["https://github.com/bolyra/bolyra/tree/a4f546f3279706a2b28a0c15569c0040425e84c7/spec/fixtures/host-conformance", "https://github.com/bolyra/bolyra/tree/a4f546f3279706a2b28a0c15569c0040425e84c7/integrations/evc-conformance", "https://www.npmjs.com/package/@bolyra/evc-conformance/v/0.2.0"], "rfc7942_ready": false}
```
