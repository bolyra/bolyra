import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { CLI_VERSION, EXAMPLE_VERSION, PACKAGES } from '../src/versions.js';

const pkg = JSON.parse(readFileSync(fileURLToPath(new URL('../package.json', import.meta.url)), 'utf8')) as {
  version: string;
  dependencies: Record<string, string>;
  devDependencies: Record<string, string>;
};

test('the pins in src/versions.ts are the ones package.json installs', () => {
  assert.equal(pkg.dependencies['@bolyra/mpp'], PACKAGES.mpp);
  assert.equal(pkg.dependencies['mppx'], PACKAGES.mppx);
  assert.equal(pkg.devDependencies['@bolyra/cli'], CLI_VERSION);
  assert.equal(pkg.version, EXAMPLE_VERSION);
});
