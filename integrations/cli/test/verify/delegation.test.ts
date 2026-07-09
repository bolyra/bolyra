import { promises as fs } from 'fs';
import * as os from 'os';
import * as path from 'path';

import { poseidon3 } from '@bolyra/sdk';
import type { DelegationResult, Proof, BolyraConfig } from '@bolyra/sdk';

import {
  verifyDelegationChain,
  type DelegationHop,
  type DelegationChainContext,
} from '../../src/verify/delegation';
import { VerifyDenial } from '../../src/verify/verdict';
import { loadRootSource, type RootSource } from '../../src/verify/roots';
import { FileNonceStore } from '../../src/verify/nonce-store';

// Delegatee Merkle root committed by each hop's proof (decimal field element).
const DELEGATEE_ROOT = '424242424242424242424242';
const UNTRUSTED_ROOT = '999999999999999999999999';

// Agent chain root: the delegator's scope commitment. Arbitrary field element.
const AGENT_SCOPE = 700000000000000000000001n;
const SESSION_NONCE = 12345n;
const CURRENT_TS = 1_720_000_000n;
const AGENT_EXPIRY = 2_000_000_000n;

/**
 * Build a fake `verifyFn` matching the SDK `verifyDelegation` signature. It
 * reads the crafted public signals off the proof and returns a
 * {@link DelegationResult} derived from them, WITHOUT any Groth16 work — so the
 * unit tests exercise chain semantics only.
 *
 * publicSignals order (SDK-confirmed):
 *   [0] newScopeCommitment [1] delegationNullifier [2] delegateeMerkleRoot
 *   [3] previousScopeCommitment [4] sessionNonce [5] currentTimestamp
 */
function fakeVerify(
  proof: Proof,
  _prev: bigint,
  _nonce: bigint,
  _ts: bigint,
  _config?: BolyraConfig,
): Promise<DelegationResult> {
  const s = proof.publicSignals;
  return Promise.resolve({
    newScopeCommitment: BigInt(s[0]),
    delegationNullifier: BigInt(s[1]),
    delegateeMerkleRoot: BigInt(s[2]),
    hopIndex: 0,
  });
}

/** A verifyFn that always throws — simulates a broken chain-link / escalation. */
function throwingVerify(): Promise<DelegationResult> {
  const err = Object.assign(new Error('previousScopeCommitment mismatch'), {
    code: 'VERIFICATION_ERROR',
  });
  return Promise.reject(err);
}

/** Build a hop's crafted public signals array. */
function signals(opts: {
  newScope: bigint;
  nullifier: bigint;
  root: string;
  prev: bigint;
}): string[] {
  return [
    opts.newScope.toString(),
    opts.nullifier.toString(),
    opts.root,
    opts.prev.toString(),
    SESSION_NONCE.toString(),
    CURRENT_TS.toString(),
  ];
}

describe('verifyDelegationChain', () => {
  let dir: string;
  let nonceStore: FileNonceStore;
  let rootSource: RootSource;

  beforeEach(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), 'bolyra-deleg-'));
    nonceStore = new FileNonceStore(dir);
    // Trust the delegatee root for any tree (inline pin).
    rootSource = loadRootSource({ rootPins: [DELEGATEE_ROOT], env: {} });
  });

  afterEach(async () => {
    await fs.rm(dir, { recursive: true, force: true });
  });

  function baseCtx(overrides?: Partial<DelegationChainContext>): DelegationChainContext {
    return {
      agentScopeCommitment: AGENT_SCOPE,
      sessionNonce: SESSION_NONCE,
      currentTimestamp: CURRENT_TS,
      agentExpiry: AGENT_EXPIRY,
      rootSource,
      nonceStore,
      nonceTtlSeconds: 60,
      verifyFn: fakeVerify,
      ...overrides,
    };
  }

  /**
   * Build a valid final hop whose crafted newScopeCommitment equals
   * Poseidon3(leaf) so the final-leaf recompute matches.
   */
  async function finalHop(opts: {
    prev: bigint;
    nullifier: bigint;
    scope: string;
    commitment: string;
    expiry: number;
  }): Promise<DelegationHop> {
    const newScope = await poseidon3(
      BigInt(opts.scope),
      BigInt(opts.commitment),
      BigInt(opts.expiry),
    );
    return {
      envelope: {
        proof: {},
        publicSignals: signals({
          newScope,
          nullifier: opts.nullifier,
          root: DELEGATEE_ROOT,
          prev: opts.prev,
        }),
      },
      leaf: {
        delegatee_scope: opts.scope,
        delegatee_commitment: opts.commitment,
        delegatee_expiry: opts.expiry,
      },
    };
  }

  it('verifies a valid 1-hop chain and returns effective scope + expiry', async () => {
    const hop = await finalHop({
      prev: AGENT_SCOPE,
      nullifier: 111n,
      scope: '7',
      commitment: '5555',
      expiry: 1_900_000_000,
    });

    const out = await verifyDelegationChain([hop], baseCtx());

    expect(out.effectiveScope).toBe(7n);
    // min(agentExpiry=2e9, leafExpiry=1.9e9) = 1.9e9
    expect(out.effectiveExpiry).toBe(1_900_000_000n);
  });

  it('caps effectiveExpiry at agentExpiry when the leaf outlives the agent', async () => {
    const hop = await finalHop({
      prev: AGENT_SCOPE,
      nullifier: 222n,
      scope: '3',
      commitment: '5555',
      expiry: 2_500_000_000, // beyond agentExpiry
    });

    const out = await verifyDelegationChain([hop], baseCtx());
    expect(out.effectiveScope).toBe(3n);
    expect(out.effectiveExpiry).toBe(AGENT_EXPIRY);
  });

  it('threads prev across a valid 2-hop chain, deriving effective from the final leaf', async () => {
    // Hop 1: arbitrary newScope that becomes hop 2's prev.
    const hop1NewScope = 800000000000000000000009n;
    const hop1: DelegationHop = {
      envelope: {
        proof: {},
        publicSignals: signals({
          newScope: hop1NewScope,
          nullifier: 301n,
          root: DELEGATEE_ROOT,
          prev: AGENT_SCOPE,
        }),
      },
    };
    const hop2 = await finalHop({
      prev: hop1NewScope,
      nullifier: 302n,
      scope: '1',
      commitment: '6789',
      expiry: 1_800_000_000,
    });

    const out = await verifyDelegationChain([hop1, hop2], baseCtx());
    expect(out.effectiveScope).toBe(1n);
    expect(out.effectiveExpiry).toBe(1_800_000_000n);
  });

  it('denies a 4-hop chain with delegation_invalid (hop cap, before verifyFn)', async () => {
    let called = 0;
    const countingVerify: typeof fakeVerify = (p, a, b, c, d) => {
      called += 1;
      return fakeVerify(p, a, b, c, d);
    };
    const junk: DelegationHop = {
      envelope: {
        proof: {},
        publicSignals: signals({
          newScope: 1n,
          nullifier: 1n,
          root: DELEGATEE_ROOT,
          prev: AGENT_SCOPE,
        }),
      },
    };

    await expect(
      verifyDelegationChain([junk, junk, junk, junk], baseCtx({ verifyFn: countingVerify })),
    ).rejects.toMatchObject({ code: 'delegation_invalid' });
    // Hop cap must trip before any proof is verified.
    expect(called).toBe(0);
  });

  it('maps a verifyFn throw to delegation_invalid, echoing sdk_code', async () => {
    const hop = await finalHop({
      prev: AGENT_SCOPE,
      nullifier: 400n,
      scope: '1',
      commitment: '5555',
      expiry: 1_800_000_000,
    });

    try {
      await verifyDelegationChain([hop], baseCtx({ verifyFn: throwingVerify }));
      throw new Error('expected verifyDelegationChain to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(VerifyDenial);
      const denial = err as VerifyDenial;
      expect(denial.code).toBe('delegation_invalid');
      expect(denial.detail).toEqual({ hop: 0, sdk_code: 'VERIFICATION_ERROR' });
    }
  });

  it('denies a chain whose final hop is missing its leaf', async () => {
    const hop: DelegationHop = {
      envelope: {
        proof: {},
        publicSignals: signals({
          newScope: 12345n,
          nullifier: 500n,
          root: DELEGATEE_ROOT,
          prev: AGENT_SCOPE,
        }),
      },
      // no leaf
    };

    await expect(verifyDelegationChain([hop], baseCtx())).rejects.toMatchObject({
      code: 'delegation_invalid',
      message: 'final delegation hop missing leaf',
    });
  });

  it('denies when the final leaf does not recompute to newScopeCommitment', async () => {
    // Craft a hop whose newScope is NOT Poseidon3(leaf).
    const hop: DelegationHop = {
      envelope: {
        proof: {},
        publicSignals: signals({
          newScope: 999999n, // deliberately wrong
          nullifier: 600n,
          root: DELEGATEE_ROOT,
          prev: AGENT_SCOPE,
        }),
      },
      leaf: {
        delegatee_scope: '1',
        delegatee_commitment: '5555',
        delegatee_expiry: 1_800_000_000,
      },
    };

    await expect(verifyDelegationChain([hop], baseCtx())).rejects.toMatchObject({
      code: 'delegation_invalid',
      message: 'final leaf does not match newScopeCommitment',
    });
  });

  it('denies an untrusted delegatee root with untrusted_root', async () => {
    const newScope = await poseidon3(1n, 5555n, 1_800_000_000n);
    const hop: DelegationHop = {
      envelope: {
        proof: {},
        publicSignals: signals({
          newScope,
          nullifier: 700n,
          root: UNTRUSTED_ROOT, // not in rootSource
          prev: AGENT_SCOPE,
        }),
      },
      leaf: {
        delegatee_scope: '1',
        delegatee_commitment: '5555',
        delegatee_expiry: 1_800_000_000,
      },
    };

    await expect(verifyDelegationChain([hop], baseCtx())).rejects.toMatchObject({
      code: 'untrusted_root',
    });
  });

  it('denies a replayed per-hop delegation nullifier with nonce_replayed', async () => {
    const hop = await finalHop({
      prev: AGENT_SCOPE,
      nullifier: 800n,
      scope: '1',
      commitment: '5555',
      expiry: 1_800_000_000,
    });

    // Pre-burn the nullifier in the store so the chain sees a replay.
    expect(await nonceStore.markIfFresh('800', 60)).toBe(true);

    await expect(verifyDelegationChain([hop], baseCtx())).rejects.toMatchObject({
      code: 'nonce_replayed',
      detail: { hop: 0 },
    });
  });
});
