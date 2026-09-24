import { configDefaults, defineConfig } from 'vitest/config';
import { cloudflareTest } from '@cloudflare/vitest-pool-workers';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { buildTestTenants } from './test/tenants-fixture';
import mandate from './test/fixtures/mandate.json';

const here = dirname(fileURLToPath(import.meta.url));

// wrangler.jsonc, comments stripped (every comment in that file is a full line), for the
// config drift test. Wrangler itself is the authority on the file; this only pins values.
const wranglerConfig = (() => {
  const stripped = readFileSync(join(here, 'wrangler.jsonc'), 'utf8')
    .split('\n')
    .filter((line) => !/^\s*\/\//.test(line))
    .join('\n');
  try {
    return JSON.parse(stripped) as Record<string, unknown>;
  } catch (e) {
    throw new Error(
      'wrangler.jsonc could not be parsed after stripping full-line // comments. This reader does not handle inline // or /* */ comments — keep every comment in wrangler.jsonc on its own line. (' +
        String(e) +
        ')',
    );
  }
})();

// Tests trust the operator key behind the conformance request fixtures.
const fixture = JSON.parse(
  readFileSync(join(here, '../cli/test/fixtures/verify/allow-agent-only/request.json'), 'utf8'),
) as { bundle: string };
const opKey = (() => {
  const { operator_pubkey } = (JSON.parse(fixture.bundle) as {
    agent: { credential: { operator_pubkey: { x: string; y: string } } };
  }).agent.credential;
  return `${operator_pubkey.x}:${operator_pubkey.y}`;
})();

export default defineConfig({
  test: {
    // test-node/ runs under plain `node --test` (npm run test:agreement): it loads the
    // installed @bolyra/mpp, which the workers pool cannot import.
    exclude: [...configDefaults.exclude, 'test-node/**'],
  },
  resolve: {
    alias: {
      // @bolyra/receipts ships CJS that requires the ESM-only
      // @noble/secp256k1 — the workers pool's interop cannot shim that, so
      // build from the package's published TypeScript source (it ships src/).
      '@bolyra/receipts': join(here, 'node_modules/@bolyra/receipts/src/index.ts'),
      // Mirror the wrangler.jsonc aliases: the classical path never runs
      // circuit crypto, and workerd cannot compile its runtime WASM anyway.
      circomlibjs: join(here, 'src/stubs/zk-not-available.ts'),
      snarkjs: join(here, 'src/stubs/zk-not-available.ts'),
    },
  },
  plugins: [
    cloudflareTest({
      wrangler: { configPath: './wrangler.jsonc' },
      miniflare: {
        bindings: {
          // Three synthetic tenants (test-only tokens, NOT real secrets):
          // org-a and org-c trust the conformance-fixture operator key,
          // org-b trusts a second test-only key. See test/tenants-fixture.ts.
          TENANTS: buildTestTenants(opKey),
          // The mandate fixture's capability vocabulary. wrangler.jsonc carries the same
          // JSON for both environments; test/wrangler-config.spec.ts pins the two together.
          CAPABILITY_MAP: JSON.stringify(mandate.capability_map),
          WRANGLER_CONFIG: JSON.stringify(wranglerConfig),
          // Deterministic test signing key (NOT a real secret).
          RECEIPT_SIGNER_KEY:
            '0x0101010101010101010101010101010101010101010101010101010101010101',
          RECEIPT_ISSUER: 'bolyra-hosted-verify-preview',
          RECEIPT_KEY_ID: 'test-key-1',
        },
      },
    }),
  ],
});
