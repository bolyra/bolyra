import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

import {
  requiredTierForUsdAmount, TIER_ORDER, tierCeilingUsd, describeTierAuthorization,
  tierBitmask, isTier, tierCovers,
} from '../../src/core/tiers.js';

const require = createRequire(import.meta.url);
const mpp = require('@bolyra/mpp');

test('boundary table matches the shipped decimal semantics', () => {
  const table = [
    ['0', 'small'], ['99.99', 'small'], ['99.99999999999999999999', 'small'], ['0099.50', 'small'],
    ['100', 'medium'], ['100.00', 'medium'], ['000100', 'medium'], ['9999.99', 'medium'],
    ['10000', 'unlimited'], ['10000.00', 'unlimited'], ['123456789.5', 'unlimited'], [' 5 ', 'small'],
  ];
  for (const [amount, tier] of table) assert.equal(requiredTierForUsdAmount(amount), tier, amount);
});

test('invalid amounts throw TypeError, never map to a tier', () => {
  for (const bad of ['-1', '', '   ', '1e3', '1.', '.5', '1.2.3', 'NaN', 'Infinity', '$5', '5,000', null, undefined, 5, {}, []]) {
    assert.throws(() => requiredTierForUsdAmount(bad), TypeError, String(bad));
  }
});

test('tier vocabulary, ceilings, bitmasks, coverage', () => {
  assert.deepEqual(TIER_ORDER, ['small', 'medium', 'unlimited']);
  assert.equal(tierCeilingUsd('small'), 100); assert.equal(tierCeilingUsd('medium'), 10000); assert.equal(tierCeilingUsd('unlimited'), null);
  assert.equal(tierBitmask('small'), '4'); assert.equal(tierBitmask('medium'), '12'); assert.equal(tierBitmask('unlimited'), '28');
  assert.match(describeTierAuthorization('small'), /under \$100/);
  assert.equal(isTier('gold'), false); assert.equal(isTier('small'), true); assert.equal(isTier(''), false); assert.equal(isTier(undefined), false);
  assert.equal(tierCovers('small', '99.99'), true); assert.equal(tierCovers('small', '100'), false);
  assert.equal(tierCovers('medium', '9999.99'), true); assert.equal(tierCovers('medium', '10000'), false);
  assert.equal(tierCovers('unlimited', '10000'), true);
  assert.throws(() => tierCovers('gold', '1'), TypeError);
});

test('differential: 40 inputs agree with the published @bolyra/mpp', () => {
  const inputs = ['0', '0.01', '1', '50', '99', '99.9', '99.99', '99.999', '100', '100.0', '100.01', '101', '999', '5000', '9999',
    '9999.9', '9999.99', '9999.999', '10000', '10000.01', '20000', '1000000', '0099.50', '000100', '00000', '1.000000000000000000001',
    '99.00000000000000000001', '  25  ', '7', '77.7', '777', '7777', '77777', '12.34', '99.5', '100.5', '9999.5', '10000.5', '3', '33'];
  for (const a of inputs) assert.equal(requiredTierForUsdAmount(a), mpp.requiredTierForUsdAmount(a), a);
  for (const bad of ['-1', '', '1e3', '1.', '.5']) {
    let ours = null, theirs = null;
    try { requiredTierForUsdAmount(bad); } catch (e) { ours = e.constructor.name; }
    try { mpp.requiredTierForUsdAmount(bad); } catch (e) { theirs = e.constructor.name; }
    assert.equal(ours, theirs, bad); assert.ok(ours, bad);
  }
  // Only requiredTierForUsdAmount / tierCapability are exported by the published package;
  // ceilings and descriptions are compared where available.
  for (const t of TIER_ORDER) {
    if (typeof mpp.tierCeilingUsd === 'function') assert.equal(tierCeilingUsd(t), mpp.tierCeilingUsd(t), t);
    if (typeof mpp.describeTierAuthorization === 'function') assert.equal(describeTierAuthorization(t), mpp.describeTierAuthorization(t), t);
    if (typeof mpp.tierCapability === 'function') assert.equal(mpp.tierCapability(t), `mpp:financial:${t}`, t);
  }
});
