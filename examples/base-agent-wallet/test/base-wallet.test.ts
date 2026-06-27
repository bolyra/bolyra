import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import { BaseAgentWallet } from '../src/base-wallet.js';
import type { WalletPolicy } from '../src/delegation.js';

function makePolicy(overrides: Partial<WalletPolicy> = {}): WalletPolicy {
  return {
    maxPerRequest: 500,       // $5.00
    dailyCap: 2000,           // $20.00
    allowedAssets: ['USDC'],
    allowedNetworks: ['base-sepolia'],
    agentDid: 'did:bolyra:test1234',
    ...overrides,
  };
}

function makeRequest(overrides: Partial<{ url: string; amount: number; asset: string; network: string }> = {}) {
  return {
    url: 'https://api.example.com/data',
    amount: 100,    // $1.00
    asset: 'USDC',
    network: 'base-sepolia',
    ...overrides,
  };
}

describe('BaseAgentWallet', () => {
  it('allows payment within limits', () => {
    const wallet = new BaseAgentWallet(makePolicy());
    const receipt = wallet.evaluatePayment(makeRequest({ amount: 100 }));

    assert.equal(receipt.decision, 'allow');
    assert.equal(receipt.amount, 100);
    assert.equal(receipt.reason, undefined);
    assert.equal(wallet.getDailySpent(), 100);
  });

  it('denies exceeding per-request cap', () => {
    const wallet = new BaseAgentWallet(makePolicy({ maxPerRequest: 200 }));
    const receipt = wallet.evaluatePayment(makeRequest({ amount: 300 }));

    assert.equal(receipt.decision, 'deny');
    assert.ok(receipt.reason?.includes('per-request cap'), `reason should mention per-request cap: ${receipt.reason}`);
    assert.equal(wallet.getDailySpent(), 0, 'denied payment must not affect daily spent');
  });

  it('denies exceeding daily cap', () => {
    const wallet = new BaseAgentWallet(makePolicy({ dailyCap: 250 }));

    // First payment: allowed (100 cents)
    const r1 = wallet.evaluatePayment(makeRequest({ amount: 100 }));
    assert.equal(r1.decision, 'allow');

    // Second payment: allowed (100 cents, total 200)
    const r2 = wallet.evaluatePayment(makeRequest({ amount: 100 }));
    assert.equal(r2.decision, 'allow');

    // Third payment: denied (would be 300, cap is 250)
    const r3 = wallet.evaluatePayment(makeRequest({ amount: 100 }));
    assert.equal(r3.decision, 'deny');
    assert.ok(r3.reason?.includes('daily'), `reason should mention daily cap: ${r3.reason}`);
  });

  it('denies wrong asset', () => {
    const wallet = new BaseAgentWallet(makePolicy({ allowedAssets: ['USDC'] }));
    const receipt = wallet.evaluatePayment(makeRequest({ asset: 'DAI' }));

    assert.equal(receipt.decision, 'deny');
    assert.ok(receipt.reason?.includes('DAI'), `reason should mention the rejected asset: ${receipt.reason}`);
  });

  it('denies wrong network', () => {
    const wallet = new BaseAgentWallet(makePolicy({ allowedNetworks: ['base-sepolia'] }));
    const receipt = wallet.evaluatePayment(makeRequest({ network: 'ethereum' }));

    assert.equal(receipt.decision, 'deny');
    assert.ok(receipt.reason?.includes('ethereum'), `reason should mention the rejected network: ${receipt.reason}`);
  });

  it('denies expired delegation', () => {
    const pastDate = new Date(Date.now() - 86400_000).toISOString(); // yesterday
    const wallet = new BaseAgentWallet(makePolicy({ expiresAt: pastDate }));
    const receipt = wallet.evaluatePayment(makeRequest());

    assert.equal(receipt.decision, 'deny');
    assert.ok(receipt.reason?.includes('expired'), `reason should mention expiry: ${receipt.reason}`);
  });

  it('tracks receipts', () => {
    const wallet = new BaseAgentWallet(makePolicy());

    wallet.evaluatePayment(makeRequest({ amount: 100 }));
    wallet.evaluatePayment(makeRequest({ amount: 200 }));
    wallet.evaluatePayment(makeRequest({ amount: 150 }));

    const receipts = wallet.getReceipts();
    assert.equal(receipts.length, 3);
    assert.equal(receipts[0].decision, 'allow');
    assert.equal(receipts[1].decision, 'allow');
    assert.equal(receipts[2].decision, 'allow');

    assert.equal(wallet.getDailySpent(), 450);
    assert.equal(wallet.getDailyRemaining(), 2000 - 450);

    // Each receipt has a unique ID
    const ids = new Set(receipts.map((r) => r.id));
    assert.equal(ids.size, 3, 'each receipt must have a unique ID');
  });
});
