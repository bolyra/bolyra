import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { denyTable } from '../../tools/deny-table.mjs';
import { extractEvcSpec } from '../../tools/spec-extract.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(here, '../../../..');
const require = createRequire(import.meta.url);
const mpp = require('@bolyra/mpp');
const x = extractEvcSpec(fs.readFileSync(path.join(ROOT, 'spec/external-verifier-contract-v1.md'), 'utf8'));

test('deny table: registry rows in registry order + exactly one gate-local row, sourced from @bolyra/mpp', () => {
  const t = denyTable(x.registry.map((r) => r.code));
  assert.equal(t.mppVersion, require('@bolyra/mpp/package.json').version);
  assert.deepEqual(t.registry.map((r) => r.code), x.registry.map((r) => r.code));
  assert.deepEqual(t.gateLocal.map((r) => r.code), ['missing_authorization']);
  for (const row of [...t.registry, ...t.gateLocal]) {
    const p = mpp.denyProblem({ code: row.code, message: 'm' });
    assert.deepEqual({ status: row.status, title: row.title, type: row.type }, { status: p.status, title: p.title, type: p.type }, row.code);
    assert.ok([401, 403, 500].includes(row.status), row.code);
  }
  assert.deepEqual(Object.keys(mpp.DENY_STATUS).filter((c) => !x.registry.some((r) => r.code === c)), ['missing_authorization']);
});
