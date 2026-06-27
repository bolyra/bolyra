import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import { setupDelegation } from '../src/delegation.js';
import { Permission, permissionsToBitmask } from '@bolyra/sdk';

describe('setupDelegation', () => {
  it('returns human identity with commitment', async () => {
    const result = await setupDelegation({
      permissions: [Permission.READ_DATA, Permission.FINANCIAL_SMALL],
      maxPerRequest: 500,
      dailyCap: 2000,
      allowedAssets: ['USDC'],
      allowedNetworks: ['base-sepolia'],
    });

    assert.ok(result.humanIdentity.secret > 0n, 'secret must be non-zero');
    assert.ok(result.humanIdentity.commitment > 0n, 'commitment must be non-zero');
    assert.ok(result.humanIdentity.publicKey.x > 0n, 'public key x must exist');
    assert.ok(result.humanIdentity.publicKey.y > 0n, 'public key y must exist');
  });

  it('returns agent credential with commitment and permissions', async () => {
    const perms = [Permission.READ_DATA, Permission.FINANCIAL_SMALL];
    const result = await setupDelegation({
      permissions: perms,
      maxPerRequest: 500,
      dailyCap: 2000,
      allowedAssets: ['USDC'],
      allowedNetworks: ['base-sepolia'],
    });

    assert.ok(result.agentCredential.commitment > 0n, 'agent commitment must be non-zero');
    assert.equal(
      result.agentCredential.permissionBitmask,
      permissionsToBitmask(perms),
      'bitmask must match requested permissions',
    );
  });

  it('returns wallet policy with correct limits and agent DID', async () => {
    const result = await setupDelegation({
      permissions: [Permission.READ_DATA],
      maxPerRequest: 100,
      dailyCap: 500,
      allowedAssets: ['USDC'],
      allowedNetworks: ['base'],
    });

    assert.equal(result.walletPolicy.maxPerRequest, 100);
    assert.equal(result.walletPolicy.dailyCap, 500);
    assert.deepEqual(result.walletPolicy.allowedAssets, ['USDC']);
    assert.deepEqual(result.walletPolicy.allowedNetworks, ['base']);
    assert.ok(result.walletPolicy.agentDid.startsWith('did:bolyra:'), 'agentDid must use did:bolyra: prefix');
  });

  it('enforces scope narrowing (READ_DATA only = bitmask 1)', async () => {
    const result = await setupDelegation({
      permissions: [Permission.READ_DATA],
      maxPerRequest: 100,
      dailyCap: 500,
      allowedAssets: ['USDC'],
      allowedNetworks: ['base'],
    });

    // READ_DATA = bit 0, so bitmask should be 1n
    assert.equal(result.agentCredential.permissionBitmask, 1n);
  });
});
