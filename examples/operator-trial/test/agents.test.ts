import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import {
  PERMISSION_NAMES,
  CLOSED_MASK,
  requiredMask,
  withheldMask,
  withheldLabel,
  createDemoAgent,
  buildDevBundle,
} from '../src/agents';

test('closed masks match the cumulative encoding', () => {
  assert.deepEqual(
    PERMISSION_NAMES.map((n) => CLOSED_MASK[n]),
    [1n, 2n, 4n, 12n, 28n, 32n, 64n, 128n],
  );
});

test('withheld mask never satisfies the required mask (spec §3.2 soundness)', () => {
  for (const name of PERMISSION_NAMES) {
    const required = requiredMask(name);
    const withheld = withheldMask(name);
    assert.notEqual(withheld & required, required, `${name}: withheld ${withheld} would pass ${required}`);
  }
  assert.equal(withheldMask('READ_DATA'), 0n);
  assert.equal(withheldMask('FINANCIAL_UNLIMITED'), 12n);
  assert.equal(withheldLabel('READ_DATA'), 'no permissions');
  assert.equal(withheldLabel('WRITE_DATA'), 'READ_DATA only');
});

test('buildDevBundle produces a fresh nonce per call and a decodable header', () => {
  const agent = createDemoAgent('a', 2n);
  const one = buildDevBundle(agent);
  const two = buildDevBundle(agent);
  assert.notEqual(one.bundle.nonce, two.bundle.nonce);
  assert.ok(one.header.startsWith('Bolyra '));
  const decoded = JSON.parse(Buffer.from(one.header.slice(7), 'base64').toString('utf8'));
  assert.equal(decoded.credentialCommitment, agent.commitment.toString());
  assert.equal(decoded.agentProof.publicSignals[3], '2');
});
