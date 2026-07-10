/**
 * snarkjs lazy-loading contract for the CLI (Bolyra Core vs Bolyra ZK split).
 *
 * `bolyra verify` legitimately needs snarkjs — but only at proof-verification
 * time (inside the spawned worker / verify run). Loading the CLI entry,
 * printing --help, and loading non-ZK command modules must never require
 * snarkjs. snarkjs is mocked with a factory that throws on load, so any eager
 * module-level import in the covered graph fails these tests.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';

const SNARKJS_BLOCKED = 'snarkjs must not be loaded outside proof verification';

describe('CLI never loads snarkjs outside proof verification', () => {
  beforeAll(() => {
    jest.resetModules();
    jest.doMock('snarkjs', () => {
      throw new Error(SNARKJS_BLOCKED);
    });
  });

  afterAll(() => {
    jest.dontMock('snarkjs');
    jest.resetModules();
  });

  it('loads the CLI entry and prints --help without snarkjs', async () => {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { main } = require('../src/main');
    const logs: string[] = [];
    const logSpy = jest.spyOn(console, 'log').mockImplementation((msg?: unknown) => {
      logs.push(String(msg));
    });
    try {
      await main(['--help']);
    } finally {
      logSpy.mockRestore();
    }
    expect(logs.join('\n')).toContain('Bolyra CLI');
  });

  it('loads non-ZK command modules (dev, doctor, receipt-verify) without snarkjs', () => {
    expect(() => require('../src/commands/dev')).not.toThrow();
    expect(() => require('../src/commands/doctor')).not.toThrow();
    expect(() => require('../src/commands/receipt-verify')).not.toThrow();
  });

  it('loads the verify command module without snarkjs (load deferred to proof verification)', () => {
    // The verify command orchestrates parsing/spawning; only verify/proofs.ts
    // touches snarkjs, and only when a proof is actually verified.
    expect(() => require('../src/commands/verify')).not.toThrow();
    expect(() => require('../src/verify/core')).not.toThrow();
  });

  it('runs a Core (non-ZK) operation via the SDK without snarkjs', async () => {
    // Non-ZK commands go through @bolyra/sdk Core paths — prove those paths
    // stay usable with snarkjs unresolvable.
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const sdk = require('@bolyra/sdk');
    const ids = await sdk.createDevIdentities();
    expect(ids.human.commitment).toBeGreaterThan(0n);
    expect(ids.agent.commitment).toBeGreaterThan(0n);
  });

  const CIRCUITS_DIR =
    process.env.BOLYRA_CIRCUITS_DIR ?? path.resolve(__dirname, '../../../circuits/build');
  const hasCircuits = fs.existsSync(path.join(CIRCUITS_DIR, 'AgentPolicy_groth16_vkey.json'));
  const maybeIt = hasCircuits ? it : it.skip;

  maybeIt('Groth16 verification is what (lazily) attempts the snarkjs load', async () => {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const proofs = require('../src/verify/proofs');
    const opts = { circuitsDir: CIRCUITS_DIR };
    const vkeyPath = proofs.resolveVkeyPath('AgentPolicy', opts);
    const vkey = JSON.parse(fs.readFileSync(vkeyPath, 'utf8')) as object;
    // Correct vkeyHash + enough public signals so we pass steps 1–2 and reach
    // step 3 (Groth16 math) — where the blocked snarkjs load must surface.
    const envelope = {
      version: '1.0.0',
      circuit: {
        name: 'AgentPolicy',
        version: '0.4.0',
        vkeyHash: proofs.computeVkeyHash(vkey),
      },
      proofType: 'groth16',
      publicSignals: ['1', '2', '3', '4', '5', '6'],
      proof: {
        pi_a: ['1', '2'],
        pi_b: [
          ['1', '2'],
          ['3', '4'],
        ],
        pi_c: ['1', '2'],
      },
    };
    await expect(proofs.verifyEnvelopeProof(envelope, 'AgentPolicy', opts)).rejects.toThrow(
      SNARKJS_BLOCKED,
    );
  });
});
