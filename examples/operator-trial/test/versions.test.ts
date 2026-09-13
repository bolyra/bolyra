import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { PACKAGES, TRIAL_VERSION } from '../src/versions';

const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'package.json'), 'utf8'));

test('versions.ts mirrors package.json', () => {
  assert.equal(pkg.dependencies['@bolyra/gateway'], PACKAGES.gateway);
  assert.equal(pkg.dependencies['@bolyra/mcp'], PACKAGES.mcp);
  assert.equal(pkg.dependencies['@bolyra/receipts'], PACKAGES.receipts);
  assert.equal(pkg.version, TRIAL_VERSION);
});
