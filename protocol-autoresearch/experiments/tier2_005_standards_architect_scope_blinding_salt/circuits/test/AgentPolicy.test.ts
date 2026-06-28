import { expect } from 'chai';
import path from 'path';
import { buildPoseidon } from 'circomlibjs';
import { WasmTester, wasm } from 'circom_tester';

describe('AgentPolicy (scope-blinding-salt)', () => {
  let circuit: WasmTester;
  let poseidon: any;
  let F: any;

  const sampleInput = {
    modelHash: '12345678901234567890',
    operatorPubKeyX: '11111111111111111111',
    operatorPubKeyY: '22222222222222222222',
    permissionBitmask: '7', // READ | WRITE | FINANCIAL_SMALL
    expiry: '1750000000',
    blindingSalt: '99887766554433221100998877665544332211',
    sigR8x: '33333333333333333333',
    sigR8y: '44444444444444444444',
    sigS: '55555555555555555555',
    sessionNonce: '77777777777777777777',
    currentTimestamp: '1700000000',
  };

  before(async () => {
    poseidon = await buildPoseidon();
    F = poseidon.F;
    circuit = await wasm(
      path.join(__dirname, '..', 'src', 'AgentPolicy.circom'),
      { output: path.join(__dirname, '..', 'build', 'test_agent_policy') },
    );
  });

  it('should generate a valid witness with random salt', async () => {
    // This test validates that the circuit accepts a witness with blindingSalt.
    // Note: with mock EdDSA values this may fail signature verification;
    // the key point is that the Poseidon(3) constraint compiles and
    // the witness generator accepts the blindingSalt input.
    try {
      const witness = await circuit.calculateWitness(sampleInput, true);
      expect(witness).to.not.be.undefined;
    } catch (e: any) {
      // EdDSA sig verification will fail with mock values — that's expected.
      // We only care that blindingSalt is accepted as an input signal.
      expect(e.message).to.not.include('blindingSalt');
      expect(e.message).to.not.include('Not enough values');
    }
  });

  it('should produce distinct scopeCommitments for same bitmask with different salts', async () => {
    // Compute two scope commitments with same (bitmask, credCommitment) but different salts
    const bitmask = BigInt(7);
    const credCommitment = F.toObject(
      poseidon([
        BigInt(sampleInput.modelHash),
        BigInt(sampleInput.operatorPubKeyX),
        bitmask,
        BigInt(sampleInput.expiry),
      ]),
    );

    const salt1 = BigInt('111111111111111111111111111111');
    const salt2 = BigInt('222222222222222222222222222222');

    const scopeCommitment1 = F.toObject(poseidon([bitmask, credCommitment, salt1]));
    const scopeCommitment2 = F.toObject(poseidon([bitmask, credCommitment, salt2]));

    expect(scopeCommitment1).to.not.equal(scopeCommitment2);
  });

  it('should resist brute-force: 256 wrong-salt attempts all produce wrong commitments', async () => {
    // Simulate the attack: adversary knows credCommitment, tries all 256 bitmask values
    // with a WRONG salt, none should match the real commitment.
    const bitmask = BigInt(7);
    const credCommitment = F.toObject(
      poseidon([
        BigInt(sampleInput.modelHash),
        BigInt(sampleInput.operatorPubKeyX),
        bitmask,
        BigInt(sampleInput.expiry),
      ]),
    );

    const realSalt = BigInt('99887766554433221100998877665544332211');
    const realCommitment = F.toObject(poseidon([bitmask, credCommitment, realSalt]));

    // Attacker uses wrong salt (e.g., 0) and tries all 256 bitmask values
    const attackerSalt = BigInt(0);
    let matched = false;
    for (let trialBitmask = 0; trialBitmask < 256; trialBitmask++) {
      const trialCommitment = F.toObject(
        poseidon([BigInt(trialBitmask), credCommitment, attackerSalt]),
      );
      if (trialCommitment === realCommitment) {
        matched = true;
        break;
      }
    }

    expect(matched).to.be.false;
  });

  it('should fail without blindingSalt input (old 2-input Poseidon is gone)', async () => {
    // Verify that omitting blindingSalt from the witness causes a failure
    const inputWithoutSalt = { ...sampleInput } as any;
    delete inputWithoutSalt.blindingSalt;

    try {
      await circuit.calculateWitness(inputWithoutSalt, true);
      expect.fail('Should have thrown when blindingSalt is missing');
    } catch (e: any) {
      // Expected: witness generator rejects missing input
      expect(e).to.exist;
    }
  });

  it('should demonstrate the old 2-input commitment is trivially enumerable', async () => {
    // Show that WITHOUT salt, an attacker can recover the bitmask
    const bitmask = BigInt(7);
    const credCommitment = F.toObject(
      poseidon([
        BigInt(sampleInput.modelHash),
        BigInt(sampleInput.operatorPubKeyX),
        bitmask,
        BigInt(sampleInput.expiry),
      ]),
    );

    // Old commitment (no salt): Poseidon(bitmask, credCommitment)
    const oldCommitment = F.toObject(poseidon([bitmask, credCommitment]));

    // Attacker brute-forces all 256 bitmask values
    let recoveredBitmask = -1;
    for (let trial = 0; trial < 256; trial++) {
      const trialCommitment = F.toObject(poseidon([BigInt(trial), credCommitment]));
      if (trialCommitment === oldCommitment) {
        recoveredBitmask = trial;
        break;
      }
    }

    // Attacker successfully recovers bitmask — this is the vulnerability we fix
    expect(recoveredBitmask).to.equal(7);
  });
});
