import { defineConfig } from 'vitest/config';
import { cloudflareTest } from '@cloudflare/vitest-pool-workers';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));

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
          PREVIEW_TOKEN: 'test-preview-token',
          TRUSTED_OPERATORS: opKey,
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
