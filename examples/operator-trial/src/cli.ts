#!/usr/bin/env node
/**
 * CLI wrapper: arg parsing and exit codes only.
 *   2  config error (nothing started)
 *   1  the trial ran and did not meet expectations, or an internal error
 *   0  success
 */

import { parseArgs } from 'node:util';
import * as path from 'node:path';
import { loadTrialConfig, TrialConfigError } from './config';
import { runTrial } from './trial';

async function main(): Promise<void> {
  let values: { config?: string; 'dry-run'?: boolean; 'out-dir'?: string };
  try {
    values = parseArgs({
      options: {
        config: { type: 'string' },
        'dry-run': { type: 'boolean', default: false },
        'out-dir': { type: 'string', default: './trial-out' },
      },
      strict: true,
    }).values;
  } catch (err) {
    // Unknown options, positionals, or a missing option value: a config
    // error, exit 2, nothing started.
    throw new TrialConfigError((err as Error).message);
  }
  const dryRun = values['dry-run'] === true;
  if (!dryRun && !values.config) {
    throw new TrialConfigError('--config <trial.yaml> is required unless --dry-run is set');
  }
  const config = values.config ? loadTrialConfig(values.config) : undefined;
  const summary = await runTrial({ config, outDir: path.resolve(values['out-dir'] as string), dryRun });
  process.exitCode = summary.ok ? 0 : 1;
}

main().catch((err: unknown) => {
  if (err instanceof TrialConfigError) {
    console.error(`config error: ${err.message}`);
    process.exitCode = 2;
  } else {
    console.error(`trial error: ${(err as Error).message}`);
    process.exitCode = 1;
  }
});
