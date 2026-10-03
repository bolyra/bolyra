import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { FIXTURES_DIR, CLI_FIXTURES_DIR, COPIED_FIXTURES } from '../src/paths';

test('every copied fixture is byte-identical to the CLI verify fixture it came from', () => {
  assert.equal(COPIED_FIXTURES.length, 5);
  for (const [ours, theirs] of COPIED_FIXTURES) {
    const a = fs.readFileSync(path.join(FIXTURES_DIR, ours));
    const b = fs.readFileSync(path.join(CLI_FIXTURES_DIR, theirs));
    assert.ok(a.equals(b), `${ours} drifted from integrations/cli/test/fixtures/verify/${theirs}; recopy it`);
  }
});
