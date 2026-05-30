# Dependabot Cleanup Plan (revised)

**Status:** Planning — rev 2 (2026-05-30, post-codex review)
**Trigger:** 78 open alerts on `bolyra/bolyra` default branch (34 high, 33 moderate, 11 low) — flagged on every push since v0.3.0.
**Goal:** Every remaining alert is either (a) actually exploitable in a shipped runtime path and patched in lockfile, or (b) explicitly dismissed with a documented, narrow reason. No silent noise.

**What changed vs rev 1:** Codex review caught six factual errors in the rev-1 inventory. This rev rebuilds from current lockfile state via `npm ls` + `npm explain`, not from the rev-1 inventory snapshot. Key corrections:

- `@bolyra/sdk` direct dep is `ethers ^6.13.0`, not ethers v5. The v5 path is purely transitive via `circomlibjs → ethers@5.8.0 → @ethersproject/providers`. No ethers-major-version risk.
- `ws@^7.4.6` framing was wrong. Current lockfiles resolve to `ws@8.17.1` / `ws@8.18.0` under `@ethersproject/providers@5.8.0`. Both are still in the vulnerable range (>=8.0.0, <8.20.1) — need ≥8.20.1.
- `snarkjs@0.5.0` nested resolution is **production**, not dev. Chain: `@semaphore-protocol/core` (sdk's root prod dep) → `@semaphore-protocol/proof` → `@zk-kit/artifacts` → `circomkit` → `circom_tester` → `snarkjs@0.5.0`. Cannot be dismissed as dev-only.
- Rev 1 caret overrides (`^0.2.4`, `^6.4.0`, etc.) were aimed at versions the tree already passed. Real patched versions are listed in §3.
- Root `overrides` will not propagate into `sdk/`, `integrations/*/`, etc. — this repo is not npm workspaces. Each lockfile root needs its own `overrides`.
- Sequencing: regenerate first, dismiss residuals last (so dismissed alerts don't re-fire after lockfile changes).

## §1. Ground truth (reconciliation, 2026-05-30)

Sourced from `npm ls <pkg>` per subdir and live npm registry for latest patched versions:

| Package | Vuln range (Dependabot) | Currently resolved | Latest on npm | Status |
|---|---|---|---|---|
| `tmp` | `< 0.2.6` | `0.2.5` (sdk/mcp/openclaw/payment/circuits/examples) | `0.2.7` | **vulnerable** — need 0.2.6+ |
| `tmp` | `<= 0.2.3` | `0.0.33` (contracts only — via Hardhat) | `0.2.7` | **vulnerable** — contracts only |
| `ws` | `>= 8.0.0, < 8.20.1` | `8.17.1` (sdk/mcp/openclaw/payment), `8.18.0` (transitive in same), `8.20.0` (root via puppeteer-core), `7.5.10` (contracts via Hardhat — separate 7.x range, also patched line) | `8.21.0` | **vulnerable** — need 8.20.1+ for 8.x; 7.5.10 is the patched 7.x line and may sit outside Dependabot's `>=8.0.0` range |
| `underscore` | `<= 1.13.7` | `1.13.6` everywhere | `1.13.8` | **vulnerable** — need 1.13.8 |
| `qs` | `>= 6.11.1, <= 6.15.1` | `6.15.1` (mcp/contracts/examples) | `6.15.2` | **vulnerable** — need 6.15.2 |
| `ip-address` | `<= 10.1.0` | `10.1.0` (root/mcp/examples) | `10.2.0` | **vulnerable** — need 10.1.1+ |
| `elliptic` | `<= 6.6.1` | `6.6.1` everywhere | `6.6.1` | **stuck** — no patched release yet |
| `basic-ftp` | `<= 5.3.0` | `5.3.0` (root — via puppeteer-core, dev) | `6.0.1` | **vulnerable** dev-only |
| `fast-uri` | `<= 3.1.1` | `3.1.0` (mcp/contracts/examples) | `3.1.2` | **vulnerable** — need 3.1.2 |
| `serialize-javascript` | `< 7.0.5` | `6.0.2` (contracts/circuits) | `7.0.5` | **vulnerable** — major bump |
| `hono` | `< 4.12.18` | `4.12.15` (mcp/examples) | `4.12.23` | **vulnerable** — need 4.12.18+ |
| `lodash` | `<= 4.17.23` | `4.17.21` (contracts) | `4.18.1` | **vulnerable** — major bump |
| `undici` | `< 6.24.0` | `5.29.0` (contracts) | `8.3.0` | **vulnerable** dev-only |
| `axios` | `< 1.16.0` | `1.15.0` (contracts) | `1.16.1` | **vulnerable** dev-only |
| `cookie` | `< 0.7.0` | `0.4.2` (contracts) | `1.1.1` | **vulnerable** dev-only |
| `uuid` | `< 11.1.1` | `8.3.2` (contracts) | latest | **vulnerable** dev-only |
| `snarkjs` (nested) | `<= 0.6.11` | nested `0.5.0` via prod chain in sdk/mcp/openclaw/payment/circuits/examples | `0.7.6` | **vulnerable** — see §3 Phase A for path-not-loaded analysis |

**Reality vs rev 1**: rev 1 claimed `tmp`, `qs`, `ip-address`, `elliptic`, `fast-uri`, `basic-ftp` were already patched in current locks. They are not. Every one of them is still in the vulnerable range by a single patch release. Almost the entire alert surface is real and resolvable by bumping resolutions one notch.

## §2. Distribution of alerts by manifest

| Manifest | Open alerts | Published? | Path |
|---|---|---|---|
| `sdk/package-lock.json` | 5 | yes (`@bolyra/sdk`) | runtime |
| `integrations/mcp/package-lock.json` | 13 | yes (`@bolyra/mcp`) | runtime |
| `integrations/openclaw/package-lock.json` | 5 | yes (`@bolyra/openclaw`) | runtime |
| `integrations/payment-protocols/package-lock.json` | 5 | yes (`@bolyra/payment-protocols`) | runtime |
| `package-lock.json` (root) | 3 | no | dev (puppeteer-core, gbrain tooling) |
| `contracts/package-lock.json` | 31 | no | Hardhat dev tooling |
| `examples/mcp-demo/package-lock.json` | 9 | no | example app |
| `circuits/package-lock.json` | 7 | no | local build harness |
| `delegation/package-lock.json` | 0 | yes (`@bolyra/delegation`) | jose-only — clean |

28 alerts on published-package lockfiles. 50 on dev / example / local-build manifests.

## §3. Phased plan

### Phase A — Regenerate published-package lockfiles with surgical overrides (~45 min)

For each of `sdk/`, `integrations/mcp/`, `integrations/openclaw/`, `integrations/payment-protocols/`, add `overrides` to that subdir's `package.json` (NOT root — repo is not npm workspaces). Use **exact** minimum patched versions, not carets, to avoid downgrades and to make the audit reproducible:

```json
"overrides": {
  "tmp": "0.2.7",
  "ws": "8.21.0",
  "underscore": "1.13.8",
  "fast-uri": "3.1.2",
  "qs": "6.15.2",
  "ip-address": "10.2.0",
  "hono": "4.12.23"
}
```

Subdir-specific notes:
- **sdk/, openclaw/, payment-protocols/**: only need `tmp`, `ws`, `underscore` (no qs/ip-address/hono/fast-uri in their trees per `npm ls`).
- **mcp/**: `qs`/`ip-address`/`hono`/`fast-uri` are reachable only through `@modelcontextprotocol/sdk`, which is BOTH a `devDependencies` and a `peerDependencies` of `@bolyra/mcp` (see `integrations/mcp/package.json`). Overrides will clean our lockfile, but consumers `npm install`-ing `@bolyra/mcp` resolve `@modelcontextprotocol/sdk` themselves — our override does not protect them. Still worth adding the override (it closes our Dependabot signal) but document the limit in SECURITY.md.
- **All four published packages**: do NOT override `elliptic` — latest npm is 6.6.1, same as resolved. There is no patched release to upgrade to. Leave the alert open and document it in SECURITY.md.
- **snarkjs nested 0.5.0**: do not override blindly to 0.7.6 — `circom_tester` declares `snarkjs@^0.5.0` and may break. Per-package test step below catches breakage. If tests fail, fall back to leaving the nested resolution alone and dismiss using **`tolerable_risk`** (NOT the invalid `vulnerable_code_not_in_execution_path` enum) with the following path-not-loaded argument as the dismissal comment:

  > `@semaphore-protocol/proof/src/generate-proof.ts` imports `@zk-kit/artifacts`. The `@zk-kit/artifacts/dist/index.node.js` runtime entry does NOT import `circomkit`. Only `dist/cli/index.js` imports `circomkit`, and `circomkit` is what pulls in `circom_tester` → `snarkjs@0.5.0`. Production proof generation through the runtime entry never loads the CLI entry, so the vulnerable `snarkjs@0.5.0` code path is unreachable from the published package's runtime surface.

  Verify before dismissing by grepping `@zk-kit/artifacts/dist/index.node.js` to confirm it does not import circomkit, and inspecting `@semaphore-protocol/proof/dist/generate-proof.js` to confirm its require resolves to the node entry.

Per-subdir execution:
```bash
cd <subdir>
# 1. edit package.json — add overrides block
rm -rf node_modules package-lock.json
npm install
# 2. verify the override resolved
npm ls tmp ws underscore   # expect patched versions, no duplicates
# 3. validation gate (per subdir, below)
```

Validation gates per published package:
- `sdk`: `npm run build && npm run typecheck` + `node demo/demo.js` (verifies handshake demo still passes — covers ws / circomlibjs / ethers transitive surface)
- `integrations/mcp`: `npm test` (covers hono / fast-uri / qs)
- `integrations/openclaw`: `npm run build && npm test` (if test script exists; else just build)
- `integrations/payment-protocols`: `npm test` (x402 + stripe-acp)

Then back at repo root: `npm test` (root suite — circuits fast + contracts).

If any gate fails, narrow the failing override (e.g., drop `ws` override, keep others) and re-run. Worst case: leave a single override out and accept that one alert may persist.

**Expected post-Phase-A alert count:** 28 → ≤4 on published packages (residual `elliptic` × 4, one per package; possibly `snarkjs` nested × 4 if we can't override safely).

### Phase B — Dev / build-tooling manifests (~20 min)

`contracts/`, `examples/mcp-demo/`, root `package-lock.json`, `circuits/`:

These are not published. Three options per manifest, choose by manifest:

1. **Same `overrides` approach** for cheap fixes (qs/fast-uri/hono/ip-address/tmp where it's a one-line bump). Regenerate lockfile, run that subdir's tests.
2. **Skip the override, accept the alert** for packages where the upgrade is a major version (lodash 4→4.18, undici 6→8, axios 1.15→1.16, cookie 0.7→1.x) and the manifest is dev-only.
3. **Dismiss with narrow reason** as a last step in Phase C.

**Concrete plan per manifest:**
- `contracts/`: add overrides for `tmp` (0.2.7), `ws` (8.21.0), `underscore` (1.13.8), `qs` (6.15.2), `fast-uri` (3.1.2), `serialize-javascript` (7.0.5 — try first, watch for Hardhat regression), `cookie` (1.1.1). Don't touch `lodash`/`undici`/`axios` overrides; defer to Hardhat upgrade. Run `npm test` and `cd contracts && npm test`.
- `examples/mcp-demo/`: mirror the mcp/ override set. Run `node examples/mcp-demo/dist/bolyra-proxy.js --help` smoke.
- Root `package-lock.json`: alerts are all via `puppeteer-core` (gbrain dev tooling, not used at runtime). Override `ws` (8.21.0), `basic-ftp` (6.0.1), `ip-address` (10.2.0). Verify nothing under `npm test` regresses.
- `circuits/`: overrides for `tmp` (0.2.7), `ws` (8.21.0), `underscore` (1.13.8), `serialize-javascript` (7.0.5), `snarkjs` nested → leave as-is. Verify `npm run compile:circuits` + `test:circuits:fast` pass.

**Expected post-Phase-B count:** residual high-major-version alerts in `contracts/` (lodash/undici/axios) and `elliptic` everywhere → ≤10 open.

### Phase C — Dismiss residuals with narrow, documented reasons (~10 min)

Only after Phases A + B regenerate lockfiles. Dismiss only the alerts that survive lockfile regeneration.

Valid Dependabot `dismissed_reason` enum (verified via GitHub REST docs):
- `fix_started`
- `inaccurate`
- `no_bandwidth`
- `not_used`
- `tolerable_risk`

Note: `vulnerable_code_not_in_execution_path` is NOT a valid value — rev 1 plan invented it. Use `tolerable_risk` with a free-text comment that explains the path-not-reached reasoning instead.

Mapping for residuals:

| Manifest | Dismissal reason | Comment template |
|---|---|---|
| `contracts/` major-version-blocked alerts (lodash/undici/axios) | `tolerable_risk` | "Hardhat dev tooling; contracts package not published to npm. Will be addressed in Hardhat major-version upgrade tracked separately." |
| `circuits/` residuals after regen | `tolerable_risk` | "Local build tooling; circuits/ not published to npm." |
| `examples/mcp-demo/` residuals | `tolerable_risk` | "Example app, not shipped on npm." |
| `elliptic <=6.6.1` (every manifest) | `no_bandwidth` | "Awaiting upstream patched release; current latest on npm is 6.6.1." |
| `snarkjs@0.5.0` nested via `@semaphore-protocol/core` chain (if override approach fails) | `tolerable_risk` | "Nested only via @zk-kit/artifacts CLI entry (dist/cli/index.js → circomkit → circom_tester → snarkjs@0.5.0). The runtime entry dist/index.node.js does NOT import circomkit, so production proof generation through @semaphore-protocol/proof never loads the vulnerable code path. Top-level snarkjs is 0.7.6." |

Script the dismissals via `gh api PATCH /repos/bolyra/bolyra/dependabot/alerts/{n}` with `{"state": "dismissed", "dismissed_reason": "<reason>", "dismissed_comment": "<comment>"}`. Walk `/tmp/dep-alerts.json` after refreshing it post-Phase-A/B.

**Validation:** `gh api '/repos/bolyra/bolyra/dependabot/alerts?state=open&per_page=100' | jq length` ≤ 5.

**Rollback:** `gh api PATCH .../dependabot/alerts/{n} -F state=open` per alert.

### Phase D — Process gate (~20 min, no code risk)

1. Add `npm audit --omit=dev --audit-level=high` to CI for each published package. Fails the PR before Dependabot opens the alert.

2. Update `.github/dependabot.yml`:
    - weekly schedule (not on-push)
    - `groups`: split `production-dependencies` vs `development-dependencies`
    - patch-level dev updates → auto-PR; minor/major runtime updates → manual review

3. Add a `SECURITY.md` section: "Known accepted residuals" listing the elliptic alert, snarkjs-nested situation, and any others left open with a dismissal-comment-style explanation. Link to this plan as the canonical reasoning record.

## §4. Commit pattern

```
chore(deps): pin transitive overrides to patched versions

Adds per-package overrides to published-package package.json files
(sdk + integrations/{mcp,openclaw,payment-protocols}) to pin tmp,
ws, underscore, fast-uri, qs, ip-address, hono to their currently
patched releases. Closes ~24 Dependabot transitive alerts on
runtime-reachable paths.

Repo is not npm workspaces, so each lockfile gets its own overrides
block. snarkjs nested resolution and elliptic are documented as
open residuals in SECURITY.md.

Tests pass: sdk demo + mcp + payment-protocols + openclaw + root
suite.

Signed-off-by: ...
```

One commit per phase if any phase requires iteration; otherwise single squashed commit. DCO sign-off required.

## §5. Exit criteria

- [ ] Dependabot open count: ≤5 (residual `elliptic` ×N + any snarkjs-nested if override fails)
- [ ] Every published package passes `npm audit --omit=dev --audit-level=high` clean
- [ ] All overrides use exact patched versions, not carets
- [ ] Per-package validation gates pass (sdk demo + integration tests)
- [ ] `SECURITY.md` updated with current residuals and rationale
- [ ] CI gate for `npm audit` added to PR pipeline
- [ ] Single commit (or one per phase) with DCO sign-off

## §6. Risk / blast radius

- **Phase A** (published-package overrides + lockfile regen): medium. Validation gates per subdir catch breakage. Fallback: drop the failing override and leave its alert open. snarkjs override has highest fail probability — accept the alert if `circom_tester` breaks.
- **Phase B** (dev manifests): low. `contracts/` Hardhat suite is the most likely to regress under `serialize-javascript 6→7`; have rollback ready (drop that override).
- **Phase C** (dismissals): zero code risk. Per-alert reversible.
- **Phase D** (CI / docs): zero runtime risk.

## §7. Estimated work

- Phase A: 30-60 min (4 subdirs × overrides + regen + tests, with possible 1-2 fallback iterations on ws or snarkjs)
- Phase B: 20-30 min (4 manifests, but lower test cost since most are dev-only)
- Phase C: 10 min (script + verify)
- Phase D: 20 min (CI YAML + SECURITY.md edit)

**Total: ~1.5-2 hours.** Single PR if Phase A doesn't require multiple fallback iterations.
