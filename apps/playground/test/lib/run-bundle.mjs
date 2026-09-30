import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
const runner = path.join(path.dirname(fileURLToPath(import.meta.url)), 'bundle-runner.mjs');

/** Run ops against a bundle file in a separate process (30 s cap). */
export function runBundle(bundlePath, ops) {
  const r = spawnSync(process.execPath, [runner, bundlePath], { input: JSON.stringify(ops), encoding: 'utf8', timeout: 30_000 });
  if (r.status !== 0) throw new Error(`bundle runner failed (status ${r.status}): ${r.stderr}`);
  return JSON.parse(r.stdout);
}
