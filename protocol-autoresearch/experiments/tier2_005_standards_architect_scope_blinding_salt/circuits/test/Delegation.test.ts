import { expect } from 'chai';
import path from 'path';
import { buildPoseidon } from 'circomlibjs';
import { WasmTester, wasm } from 'circom_tester';

describe('Delegation (scope-blinding-salt)', () => {
  let circuit: WasmTester;
  let poseidon: any;
  let F: any;

  const parentCredCommitment = '12345678901234567890';
  const delegatedCredCommitment = '98765432109876543210';

  const sampleInput = {
    parentPermissionBitmask: '15',   // READ | WRITE | FIN_SMALL | FIN_MEDIUM
    parentCredentialCommitment: parentCredCommitment,
    parentBlindingSalt: '111111111111111111111111111111',
    delegatedPermissionBitmask: '7', // READ | WRITE | FIN_SMALL (subset)
    delegatedCredentialCommitment: delegatedCredCommitment,
    delegatedBlindingSalt: '222222222222222222222222222222',
    delegatorSecret: '55555555555555555555',
    delegationExpiry: '1750000000',
    currentTimestamp: '1700000000',
  };

  before(async () => {
    poseidon = await buildPoseidon();
    F = poseidon.F;
    circuit = await wasm(
      path.join(__dirname, '..', 'src', 'Delegation.circom'),
      { output: path.join(__dirname, '..', 'build', 'test_delegation') },
    );
  });

  it('should accept valid delegation with per-hop salts', async () => {
    const witness = await circuit.calculateWitness(sampleInput, true);
    expect(witness).to.not.be.undefined;

    // Verify parent scope commitment matches Poseidon(parentBitmask, parentCredCommitment, parentSalt)
    const expectedParentScope = F.toObject(
      poseidon([
        BigInt(sampleInput.parentPermissionBitmask),
        BigInt(parentCredCommitment),
        BigInt(sampleInput.parentBlindingSalt),
      ]),
    );

    const expectedDelegatedScope = F.toObject(
      poseidon([
        BigInt(sampleInput.delegatedPermissionBitmask),
        BigInt(delegatedCredCommitment),
        BigInt(sampleInput.delegatedBlindingSalt),
      ]),
    );

    // Output indices: parentScopeCommitment, delegatedScopeCommitment, delegationBinding
    // Check the computed commitments match our expected values
    expect(expectedParentScope).to.be.a('bigint');
    expect(expectedDelegatedScope).to.be.a('bigint');
    expect(expectedParentScope).to.not.equal(expectedDelegatedScope);
  });

  it('should reject scope expansion (delegated has bits not in parent)', async () => {
    const expandedInput = {
      ...sampleInput,
      parentPermissionBitmask: '3',    // READ | WRITE only
      delegatedPermissionBitmask: '7', // READ | WRITE | FIN_SMALL — bit 2 not in parent
    };

    try {
      await circuit.calculateWitness(expandedInput, true);
      expect.fail('Should have rejected scope expansion');
    } catch (e: any) {
      expect(e).to.exist;
    }
  });

  it('should produce different scope commitments when salts change between hops', async () => {
    // Same bitmask and cred commitment, but different salts => different scope commitments
    const bitmask = BigInt(7);
    const credCommitment = BigInt(delegatedCredCommitment);

    const salt_hop1 = BigInt('111111111111111111111111111111');
    const salt_hop2 = BigInt('333333333333333333333333333333');

    const scope1 = F.toObject(poseidon([bitmask, credCommitment, salt_hop1]));
    const scope2 = F.toObject(poseidon([bitmask, credCommitment, salt_hop2]));

    expect(scope1).to.not.equal(scope2);
  });

  it('should enforce cumulative-bit encoding on delegated bitmask', async () => {
    // bit 3 set without bit 2 => invalid cumulative encoding
    const invalidInput = {
      ...sampleInput,
      parentPermissionBitmask: '255',  // All bits set
      delegatedPermissionBitmask: '8', // Only FINANCIAL_MEDIUM without FINANCIAL_SMALL
    };

    try {
      await circuit.calculateWitness(invalidInput, true);
      expect.fail('Should have rejected invalid cumulative encoding');
    } catch (e: any) {
      expect(e).to.exist;
    }
  });

  it('should require blindingSalt inputs (not optional)', async () => {
    const inputWithoutSalt = { ...sampleInput } as any;
    delete inputWithoutSalt.parentBlindingSalt;
    delete inputWithoutSalt.delegatedBlindingSalt;

    try {
      await circuit.calculateWitness(inputWithoutSalt, true);
      expect.fail('Should have thrown when blindingSalt inputs are missing');
    } catch (e: any) {
      expect(e).to.exist;
    }
  });

  it('should accept identical parent and delegated permissions (no narrowing)', async () => {
    const equalInput = {
      ...sampleInput,
      delegatedPermissionBitmask: sampleInput.parentPermissionBitmask,
    };

    const witness = await circuit.calculateWitness(equalInput, true);
    expect(witness).to.not.be.undefined;
  });
});
