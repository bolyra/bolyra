/**
 * Parse runtime mode from process.argv.
 *
 * --dev        Mock proofs, no circuit artifacts needed.
 * --production Real ZKP proving; requires BOLYRA_CIRCUIT_DIR.
 */

import type { BolyraConfig } from '@bolyra/sdk';

export type Mode = 'dev' | 'production';

export function parseMode(): Mode {
  if (process.argv.includes('--production')) {
    const dir = process.env.BOLYRA_CIRCUIT_DIR;
    if (!dir) {
      console.error(
        'ERROR: --production requires BOLYRA_CIRCUIT_DIR env var ' +
          '(path to compiled circuit artifacts).',
      );
      process.exit(1);
    }
    return 'production';
  }
  return 'dev';
}

export function sdkConfigForMode(mode: Mode): BolyraConfig | undefined {
  if (mode === 'production') {
    const dir = process.env.BOLYRA_CIRCUIT_DIR!;
    return { circuitDir: dir, zkeyDir: dir };
  }
  return undefined;
}
