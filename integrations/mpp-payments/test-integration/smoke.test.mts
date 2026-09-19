import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Mppx } from 'mppx/server';
import { z } from 'mppx';   // the harness relies on this re-export; fail here, not in Task 1.2
import { bolyraGate } from '../src/gate.js';

test('harness: mppx (ESM) and @bolyra/mpp source (CJS-style TS) load in one process', () => {
  assert.equal(typeof Mppx.create, 'function');
  assert.equal(typeof z.object, 'function');
  assert.equal(typeof bolyraGate, 'function');
});
