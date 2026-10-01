# apps/playground

Source for **bolyra.ai/playground** (`landing/playground.html`, generated and committed).

- `src/core/` — no DOM. `verify.js` wraps the published `@bolyra/receipts` verifier
  fail-closed (parse limits, envelope validation before crypto, options validation,
  one central overall-ok predicate). `simulate.js` signs real chained `bolyra.auth`
  receipts for simulated decisions with a temporary key. `tiers.js` copies the
  decimal tier semantics of `@bolyra/mpp` (differentially tested).
- `src/core/x402.js` — browser port of the PAYMENT-REQUIRED header/leg rules of
  `x402LocalChallenge` and the `peekHeader` peek from `@bolyra/payment-protocols`
  (pin: `config.paymentProtocolsVersion`); `test/unit/x402.diff.test.js` compares it with the
  published package on the package's own corpus (that corpus is the whole claim). The oracle's
  Node range `^20.19.0 || ^22.12.0 || >=23.0.0` is the package's `engines`; the diff test fails
  outside it. Nothing verifies a signature, mandate, or payee; quote verification is deferred.
- `src/core/evc-shapes.js` + `tools/{spec-extract,mini-schema,deny-table}.mjs` — EVC wire
  shapes extracted from `spec/external-verifier-contract-v1.md` and `spec/x402-evc-profile-v0.md`
  at build time (fence/table/paragraph contracts, every example validated against the extracted
  schemas, source sha256s), with HTTP status/title/type from `@bolyra/mpp` in a child process.
  Guarantee, stated narrowly: contracts are checked at build; `--check` rejects stale output; a
  spec edit that keeps the contracts intact changes the page on the next build.
- `src/ui/` — React 18 views (Verify receipts, Simulate spend policy, Decode a 402, EVC wire shapes). `build.mjs` bundles everything with esbuild into one
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
