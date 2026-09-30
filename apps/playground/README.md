# apps/playground

Source for **bolyra.ai/playground** (`landing/playground.html`, generated and committed).

- `src/core/` — no DOM. `verify.js` wraps the published `@bolyra/receipts` verifier
  fail-closed (parse limits, envelope validation before crypto, options validation,
  one central overall-ok predicate). `simulate.js` signs real chained `bolyra.auth`
  receipts for simulated decisions with a temporary key. `tiers.js` copies the
  decimal tier semantics of `@bolyra/mpp` (differentially tested).
- `src/ui/` — React 18 views. `build.mjs` bundles everything with esbuild into one
  inline `<script id="playground-bundle">` in `template.html`; samples are read from
  repository fixtures at build time.

```
npm ci
npm test              # unit + build determinism + extracted-artifact tests (offline)
npm run check         # committed landing/playground.html == fresh build (writes nothing)
npm run build         # regenerate landing/playground.html
npx playwright install --with-deps chromium   # once
npm run test:browser  # committed page in Chromium under the production CSP; writes .playground-run/<ts>/
npm run test:cli      # the browser's download verified with npx @bolyra/cli@<config.cliVersion>
```

Pins live in `package.json`: `config.receiptsVersion` (page text, bundle constant and
the landing gate all compare against the installed version) and `config.cliVersion`.
The CSP the browser gate applies is `test/fixtures/csp.txt`; `landing/deploy.sh`
fails if the live policy differs. `PLAYGROUND_OFFLINE=1` skips `test:cli` on a
developer machine only; CI and `deploy.sh` refuse it.
