/**
 * P2-3: dev delegation chain preservation.
 *
 * attachDelegatedBolyraProof in dev mode must emit v=2 bundles with
 * placeholder delegation links preserving each hop's scope, commitment,
 * and expiry — not fall back to a v=1 handshake-only bundle.
 */

import { attachDelegatedBolyraProof } from '../src/client';
import type { AgentCredential, HumanIdentity } from '../src/types';

jest.mock('@bolyra/sdk', () => ({}));

const human: HumanIdentity = {
  secret: 1n,
  commitment: 100n,
  nullifier: 200n,
} as any;

const rootCredential: AgentCredential = {
  modelHash: 1n,
  operatorPublicKey: { x: 1n, y: 2n },
  permissionBitmask: 0b11111111n,
  expiryTimestamp: BigInt(Math.floor(Date.now() / 1000) + 86400),
  signature: { R8: { x: 1n, y: 2n }, S: 3n },
  commitment: 12345n,
} as any;

describe('attachDelegatedBolyraProof dev mode', () => {
  it('emits a v=2 bundle with delegation chain', async () => {
    const result = await attachDelegatedBolyraProof(
      human,
      rootCredential,
      [
        {
          delegator: rootCredential,
          delegatorOperatorPrivateKey: 999n,
          delegateeCommitment: 54321n,
          delegateeScope: 0b00001111n,
          delegateeExpiry: BigInt(Math.floor(Date.now() / 1000) + 3600),
        },
      ],
      { devMode: true },
    );

    expect(result.bundle.v).toBe(2);
    expect(result.bundle._dev).toBe(true);
    expect(result.bundle.delegationChain).toBeDefined();
    expect(result.bundle.delegationChain).toHaveLength(1);
  });

  it('preserves delegateeScope and delegateeCommitment from hops', async () => {
    const delegateeCommitment = 54321n;
    const delegateeScope = 0b00001111n;

    const result = await attachDelegatedBolyraProof(
      human,
      rootCredential,
      [
        {
          delegator: rootCredential,
          delegatorOperatorPrivateKey: 999n,
          delegateeCommitment,
          delegateeScope,
          delegateeExpiry: BigInt(Math.floor(Date.now() / 1000) + 3600),
        },
      ],
      { devMode: true },
    );

    const chain = result.bundle.delegationChain!;
    expect(chain[0].delegateeCommitment).toBe(delegateeCommitment.toString());
    expect(chain[0].delegateeScope).toBe(delegateeScope.toString());
  });

  it('preserves delegateeExpiry from hops', async () => {
    const delegateeExpiry = BigInt(Math.floor(Date.now() / 1000) + 7200);

    const result = await attachDelegatedBolyraProof(
      human,
      rootCredential,
      [
        {
          delegator: rootCredential,
          delegatorOperatorPrivateKey: 999n,
          delegateeCommitment: 54321n,
          delegateeScope: 0b00001111n,
          delegateeExpiry,
        },
      ],
      { devMode: true },
    );

    const chain = result.bundle.delegationChain!;
    expect(chain[0].delegateeExpiry).toBe(delegateeExpiry.toString());
  });

  it('builds multi-hop delegation chains', async () => {
    const result = await attachDelegatedBolyraProof(
      human,
      rootCredential,
      [
        {
          delegator: rootCredential,
          delegatorOperatorPrivateKey: 999n,
          delegateeCommitment: 54321n,
          delegateeScope: 0b00001111n,
          delegateeExpiry: BigInt(Math.floor(Date.now() / 1000) + 3600),
        },
        {
          delegator: rootCredential,
          delegatorOperatorPrivateKey: 888n,
          delegateeCommitment: 99999n,
          delegateeScope: 0b00000011n,
          delegateeExpiry: BigInt(Math.floor(Date.now() / 1000) + 1800),
        },
      ],
      { devMode: true },
    );

    expect(result.bundle.v).toBe(2);
    expect(result.bundle.delegationChain).toHaveLength(2);
    expect(result.bundle.delegationChain![0].delegateeCommitment).toBe('54321');
    expect(result.bundle.delegationChain![1].delegateeCommitment).toBe('99999');
    expect(result.bundle.delegationChain![1].delegateeScope).toBe('3');
  });

  it('falls back to v=1 handshake-only when hops is empty', async () => {
    const result = await attachDelegatedBolyraProof(
      human,
      rootCredential,
      [],
      { devMode: true },
    );

    expect(result.bundle.v).toBe(1);
    expect(result.bundle.delegationChain).toBeUndefined();
  });

  it('encodes the v=2 bundle correctly in the Authorization header', async () => {
    const result = await attachDelegatedBolyraProof(
      human,
      rootCredential,
      [
        {
          delegator: rootCredential,
          delegatorOperatorPrivateKey: 999n,
          delegateeCommitment: 54321n,
          delegateeScope: 0b00001111n,
          delegateeExpiry: BigInt(Math.floor(Date.now() / 1000) + 3600),
        },
      ],
      { devMode: true },
    );

    expect(result.headers.Authorization).toMatch(/^Bolyra /);
    const encoded = result.headers.Authorization.replace('Bolyra ', '');
    const decoded = JSON.parse(Buffer.from(encoded, 'base64').toString('utf8'));
    expect(decoded.v).toBe(2);
    expect(decoded.delegationChain).toHaveLength(1);
  });
});
