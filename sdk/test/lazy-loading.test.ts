/**
 * snarkjs lazy-loading contract (Bolyra Core vs Bolyra ZK split).
 *
 * Core (classical) paths — dev identities, identity/credential creation,
 * Poseidon/EdDSA helpers, proof-envelope handling — must NEVER load snarkjs.
 * Only ZK entry points (Groth16 prove/verify) may load it, and only at call
 * time. "Fresh install never imports snarkjs unless ZK is requested."
 *
 * Enforced two ways:
 *   1. In-process: jest.doMock replaces snarkjs with a factory that throws on
 *      load; importing the SDK entry and running Core operations must succeed,
 *      while a ZK call must surface the load attempt.
 *   2. Out-of-process: a spawned node child blocks resolution of snarkjs at
 *      the module loader, requires the BUILT dist entry, and runs the Core
 *      flow end-to-end. dist/ is compiled on demand (tsc) when absent, so the
 *      emitted-package behavior is exercised in CI too, not just locally.
 */

import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

const SNARKJS_BLOCKED = 'snarkjs must not be loaded on the Core path';

describe('Core path never loads snarkjs (in-process, snarkjs mocked to throw on load)', () => {
  let sdk: typeof import('../src/index');

  beforeAll(() => {
    jest.resetModules();
    jest.doMock('snarkjs', () => {
      throw new Error(SNARKJS_BLOCKED);
    });
    sdk = require('../src/index');
  });

  afterAll(() => {
    jest.dontMock('snarkjs');
    jest.resetModules();
  });

  it('imports the SDK entry without loading snarkjs', () => {
    // Reaching this point means the entry (and everything it re-exports)
    // loaded without touching the throwing snarkjs stub.
    expect(typeof sdk.createDevIdentities).toBe('function');
    expect(typeof sdk.proveHandshake).toBe('function');
    expect(typeof sdk.verifyHandshake).toBe('function');
    expect(typeof sdk.proveGroth16).toBe('function');
  });

  it('createDevIdentities works without snarkjs', async () => {
    const ids = await sdk.createDevIdentities();
    expect(ids.human.commitment).toBeGreaterThan(0n);
    expect(ids.agent.commitment).toBeGreaterThan(0n);
  });

  it('EdDSA-Poseidon helpers (sign/verify/derive) work without snarkjs', async () => {
    const secret = 12345678901234567890n;
    const message = 42n;
    const pub = await sdk.derivePublicKey(secret);
    const sig = await sdk.eddsaSign(secret, message);
    await expect(sdk.eddsaVerify(pub, message, sig)).resolves.toBe(true);
    await expect(sdk.eddsaVerify(pub, message + 1n, sig)).resolves.toBe(false);
  });

  it('Poseidon hashes work without snarkjs', async () => {
    await expect(sdk.poseidon2(1n, 2n)).resolves.toBeGreaterThan(0n);
    await expect(sdk.poseidon5(1n, 2n, 3n, 4n, 5n)).resolves.toBeGreaterThan(0n);
  });

  it('proof-envelope serialize/deserialize round-trips without snarkjs', () => {
    const envelope = sdk.envelopeFromSnarkjsProof(
      'AgentPolicy',
      {
        pi_a: ['1', '2', '1'],
        pi_b: [
          ['3', '4'],
          ['5', '6'],
          ['1', '0'],
        ],
        pi_c: ['7', '8', '1'],
      },
      ['9', '10'],
    );
    const wire = sdk.serializeEnvelope(envelope);
    const back = sdk.deserializeEnvelope(wire);
    expect(back.publicSignals).toEqual(['9', '10']);
  });

  it('activeProverBackend answers without loading snarkjs', () => {
    expect(sdk.activeProverBackend('snarkjs')).toBe('snarkjs');
  });

  it('a ZK entry point is what (lazily) attempts the snarkjs load', async () => {
    // proveGroth16 with the pure-JS backend must try to load snarkjs at call
    // time — proving the load is deferred to the ZK path, not the import.
    await expect(
      sdk.proveGroth16({}, '/nonexistent/circuit.wasm', '/nonexistent/circuit.zkey', 'snarkjs'),
    ).rejects.toThrow(SNARKJS_BLOCKED);
  });
});

describe('ZK path still loads real snarkjs on demand', () => {
  it('loadSnarkjs resolves the real module with groth16 API', async () => {
    jest.resetModules();
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { loadSnarkjs } = require('../src/zk');
    const snarkjs = await loadSnarkjs();
    expect(typeof snarkjs.groth16.verify).toBe('function');
    expect(typeof snarkjs.groth16.fullProve).toBe('function');
    // Cached: same in-flight promise is reused.
    expect(loadSnarkjs()).toBe(loadSnarkjs());
  });
});

describe('Core path never loads snarkjs (spawned node child, resolution blocked, built dist)', () => {
  const sdkRoot = path.join(__dirname, '..');
  const distEntry = path.join(sdkRoot, 'dist/index.js');

  // The lazy-import guarantee must hold for the EMITTED package files that
  // consumers actually require, not just for ts-jest's in-memory transform.
  // Build dist/ on demand so this runs in CI (which runs jest without a
  // build step) as well as locally.
  beforeAll(() => {
    if (!fs.existsSync(distEntry)) {
      execFileSync(
        process.execPath,
        [path.join(sdkRoot, 'node_modules', 'typescript', 'bin', 'tsc')],
        { cwd: sdkRoot, timeout: 120_000 },
      );
    }
  }, 130_000);

  it(
    'runs createDevIdentities + EdDSA sign/verify from dist with snarkjs unresolvable',
    () => {
      const script = `
        const Module = require('module');
        const origLoad = Module._load;
        Module._load = function (request) {
          if (request === 'snarkjs' || request.startsWith('snarkjs/')) {
            throw new Error('BLOCKED: snarkjs resolution attempted on the Core path');
          }
          return origLoad.apply(this, arguments);
        };
        (async () => {
          const sdk = require(${JSON.stringify(distEntry)});
          const ids = await sdk.createDevIdentities();
          if (ids.human.commitment <= 0n || ids.agent.commitment <= 0n) {
            throw new Error('dev identities failed');
          }
          const secret = 12345678901234567890n;
          const pub = await sdk.derivePublicKey(secret);
          const sig = await sdk.eddsaSign(secret, 42n);
          const ok = await sdk.eddsaVerify(pub, 42n, sig);
          if (!ok) throw new Error('eddsa verify failed');
          console.log('CORE_OK_WITHOUT_SNARKJS');
          process.exit(0);
        })().catch((err) => {
          console.error(String(err && err.stack ? err.stack : err));
          process.exit(1);
        });
      `;
      const out = execFileSync(process.execPath, ['-e', script], {
        encoding: 'utf8',
        timeout: 60_000,
      });
      expect(out).toContain('CORE_OK_WITHOUT_SNARKJS');
    },
    70_000,
  );
});
