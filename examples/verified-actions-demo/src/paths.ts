import * as fs from 'node:fs';
import * as path from 'node:path';

/**
 * Walk upward from `from` until a package.json is found. Works from both
 * src/ (ts-node) and dist/src/ (compiled) without hardcoding depth.
 */
export function pkgRoot(from: string): string {
  let dir = from;
  for (;;) {
    if (fs.existsSync(path.join(dir, 'package.json'))) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) throw new Error('package.json not found above ' + from);
    dir = parent;
  }
}
