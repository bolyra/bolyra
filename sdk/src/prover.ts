import * as snarkjs from 'snarkjs';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import { execFileSync, execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);
import { Proof } from './types';

/**
 * Prover backend selection.
 *   - 'auto'       : use rapidsnark if available, else snarkjs
 *   - 'rapidsnark' : require rapidsnark, throw if missing
 *   - 'snarkjs'    : always use snarkjs (slower, pure JS)
 */
export type ProverBackend = 'auto' | 'rapidsnark' | 'snarkjs';

let cachedRapidsnarkPath: string | null | undefined = undefined;

// Cache witness calculators by wasm path (built once, reused for all proofs).
// Caching saves ~37ms/proof by avoiding WASM re-instantiation + file re-read.
//
// The calculator is a stateful WebAssembly instance — concurrent calls on the
// same instance race. We serialize per wasm path via a promise chain.
interface WitnessCalculator {
  calculateWTNSBin(input: Record<string, unknown>, sanityCheck: number): Promise<Uint8Array>;
}
const wcCache = new Map<string, Promise<WitnessCalculator>>();
const wcQueue = new Map<string, Promise<unknown>>();

function getWitnessCalculator(wasmPath: string): Promise<WitnessCalculator> {
  const cached = wcCache.get(wasmPath);
  if (cached) return cached;
  const promise = (async () => {
    // witness_calculator.js sits next to the .wasm in circuit_js/
    const wcDir = path.dirname(wasmPath);
    const builderPath = path.join(wcDir, 'witness_calculator.js');
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const builder = require(builderPath);
    const wasmBuf = fs.readFileSync(wasmPath);
    return (await builder(wasmBuf)) as WitnessCalculator;
  })();
  wcCache.set(wasmPath, promise);
  return promise;
}

/**
 * Compute a witness using the cached calculator for `wasmPath`, serialized so
 * concurrent calls on the same wasm don't race on the shared WASM instance.
 */
async function computeWitness(
  wasmPath: string,
  input: Record<string, unknown>,
): Promise<Uint8Array> {
  const wc = await getWitnessCalculator(wasmPath);
  const prev = wcQueue.get(wasmPath) ?? Promise.resolve();
  const next = prev.then(() => wc.calculateWTNSBin(input, 0));
  // Keep the chain alive but swallow errors so a failing call doesn't poison the queue.
  wcQueue.set(
    wasmPath,
    next.catch(() => undefined),
  );
  return next;
}

/** Find the rapidsnark prover binary, or return null if not available. */
function findRapidsnarkBinary(): string | null {
  if (cachedRapidsnarkPath !== undefined) return cachedRapidsnarkPath;

  // 1) Explicit env override
  if (process.env.BOLYRA_RAPIDSNARK) {
    if (fs.existsSync(process.env.BOLYRA_RAPIDSNARK)) {
      cachedRapidsnarkPath = process.env.BOLYRA_RAPIDSNARK;
      return cachedRapidsnarkPath;
    }
  }

  // 2) Bundled in circuits/build/rapidsnark_prover (matches benchmark setup)
  const bundled = path.join(__dirname, '../../circuits/build/rapidsnark_prover');
  if (fs.existsSync(bundled)) {
    cachedRapidsnarkPath = bundled;
    return cachedRapidsnarkPath;
  }

  // 3) PATH lookup for `prover` or `rapidsnark`
  for (const name of ['rapidsnark_prover', 'rapidsnark', 'prover']) {
    try {
      const out = execFileSync('which', [name], { encoding: 'utf8' }).trim();
      if (out) {
        cachedRapidsnarkPath = out;
        return cachedRapidsnarkPath;
      }
    } catch {
      // not in PATH
    }
  }

  cachedRapidsnarkPath = null;
  return null;
}

/** Generate a Groth16 proof using rapidsnark (witness gen via snarkjs WASM). */
async function proveWithRapidsnark(
  input: Record<string, unknown>,
  wasmPath: string,
  zkeyPath: string,
  binary: string,
): Promise<Proof> {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'bolyra-rs-'));
  try {
    const wtnsPath = path.join(tmp, 'witness.wtns');
    const proofPath = path.join(tmp, 'proof.json');
    const publicPath = path.join(tmp, 'public.json');

    const wtnsBuf = await computeWitness(wasmPath, input);
    fs.writeFileSync(wtnsPath, Buffer.from(wtnsBuf));
    // Async exec so concurrent proofs (e.g., human + agent in a handshake)
    // actually run in parallel instead of serializing on the event loop.
    await execFileAsync(binary, [zkeyPath, wtnsPath, proofPath, publicPath]);

    const proof = JSON.parse(fs.readFileSync(proofPath, 'utf8'));
    const publicSignals = JSON.parse(fs.readFileSync(publicPath, 'utf8'));
    return { proof, publicSignals };
  } finally {
    try {
      fs.rmSync(tmp, { recursive: true, force: true });
    } catch {
      // best-effort cleanup
    }
  }
}

/**
 * Generate a Groth16 proof using the fastest available backend.
 * rapidsnark is ~5x faster than snarkjs but requires the native binary.
 *
 * @param input - Circuit input (string-encoded bigints)
 * @param wasmPath - Path to circuit_js/circuit.wasm (witness generator)
 * @param zkeyPath - Path to circuit_final.zkey
 * @param backend - 'auto' (default), 'rapidsnark', or 'snarkjs'
 */
export async function proveGroth16(
  input: Record<string, unknown>,
  wasmPath: string,
  zkeyPath: string,
  backend: ProverBackend = 'auto',
): Promise<Proof> {
  if (backend === 'snarkjs') {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);
    return { proof, publicSignals };
  }

  if (backend === 'rapidsnark') {
    const bin = findRapidsnarkBinary();
    if (!bin) {
      throw new Error(
        'rapidsnark requested but not found. Set BOLYRA_RAPIDSNARK=/path/to/prover, place binary at circuits/build/rapidsnark_prover, or install on PATH.',
      );
    }
    return proveWithRapidsnark(input, wasmPath, zkeyPath, bin);
  }

  // auto: try rapidsnark, fall back to snarkjs
  const bin = findRapidsnarkBinary();
  if (bin) {
    return proveWithRapidsnark(input, wasmPath, zkeyPath, bin);
  }
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);
  return { proof, publicSignals };
}

/** Returns the active backend that would be used (for diagnostics/logging). */
export function activeProverBackend(backend: ProverBackend = 'auto'): 'rapidsnark' | 'snarkjs' {
  if (backend === 'snarkjs') return 'snarkjs';
  if (backend === 'rapidsnark') return 'rapidsnark';
  return findRapidsnarkBinary() ? 'rapidsnark' : 'snarkjs';
}
