/**
 * @bolyra/circuits — Prebuilt Circom circuit artifacts for the Bolyra ZKP identity protocol.
 *
 * Provides path resolution for .wasm, .zkey, and .vkey.json artifacts
 * so consumers can prove and verify without compiling circuits themselves.
 */

import * as path from 'path';
import * as fs from 'fs';
import * as crypto from 'crypto';

/** Production circuit names in the Bolyra protocol. */
export type CircuitName = 'HumanUniqueness' | 'AgentPolicy' | 'Delegation';

/** Supported proving systems. */
export type ProvingSystem = 'groth16';

/** Resolved absolute paths to a circuit's artifacts. */
export interface CircuitArtifacts {
  /** Absolute path to the .wasm witness calculator */
  wasm: string;
  /** Absolute path to the .zkey proving key */
  zkey: string;
  /** Absolute path to the .vkey.json verification key */
  vkey: string;
}

/**
 * All available circuits. Maps circuit name to supported proving systems.
 */
export const CIRCUITS: Record<CircuitName, readonly ProvingSystem[]> = {
  HumanUniqueness: ['groth16'] as const,
  AgentPolicy: ['groth16'] as const,
  Delegation: ['groth16'] as const,
} as const;

const VALID_CIRCUITS = new Set<string>(Object.keys(CIRCUITS));

/**
 * Returns the absolute path to the artifacts/ directory.
 */
export function getArtifactsDir(): string {
  return path.resolve(__dirname, '..', 'artifacts');
}

/**
 * Returns absolute file paths to the prebuilt circuit artifacts.
 *
 * @param circuit - Which circuit (HumanUniqueness, AgentPolicy, or Delegation)
 * @param system - Which proving system (default: 'groth16')
 * @throws If the circuit name is invalid or artifacts are not found on disk
 */
export function getCircuitArtifacts(
  circuit: CircuitName,
  system: ProvingSystem = 'groth16',
): CircuitArtifacts {
  if (!VALID_CIRCUITS.has(circuit)) {
    throw new Error(
      `Unknown circuit "${circuit}". Valid circuits: ${Array.from(VALID_CIRCUITS).join(', ')}`,
    );
  }

  const systems = CIRCUITS[circuit];
  if (!systems.includes(system)) {
    throw new Error(
      `Circuit "${circuit}" does not support proving system "${system}". ` +
        `Supported: ${systems.join(', ')}`,
    );
  }

  const artifactsDir = getArtifactsDir();
  const circuitDir = path.join(artifactsDir, circuit);

  const wasm = path.join(circuitDir, `${circuit}.wasm`);
  const zkey = path.join(circuitDir, `${circuit}_${system}.zkey`);
  const vkey = path.join(circuitDir, `${circuit}_${system}_vkey.json`);

  // Validate that files exist
  for (const [label, filePath] of [
    ['wasm', wasm],
    ['zkey', zkey],
    ['vkey', vkey],
  ] as const) {
    if (!fs.existsSync(filePath)) {
      throw new Error(
        `Circuit artifact not found: ${filePath}\n` +
          `Run "bash scripts/copy-artifacts.sh" from the circuits-package directory to populate artifacts.`,
      );
    }
  }

  return { wasm, zkey, vkey };
}

/**
 * Returns the parsed verification key JSON for a circuit.
 * Reads synchronously from disk. Results are cached after first read.
 *
 * @param circuit - Which circuit
 * @param system - Which proving system (default: 'groth16')
 */
const vkeyCache = new Map<string, object>();

export function getVerificationKey(
  circuit: CircuitName,
  system: ProvingSystem = 'groth16',
): object {
  const cacheKey = `${circuit}_${system}`;
  const cached = vkeyCache.get(cacheKey);
  if (cached) {
    return cached;
  }

  const { vkey } = getCircuitArtifacts(circuit, system);
  const content = fs.readFileSync(vkey, 'utf-8');
  const parsed = JSON.parse(content) as object;
  vkeyCache.set(cacheKey, parsed);
  return parsed;
}

/**
 * Lists all available circuit + proving system combinations.
 */
export function listAvailableCircuits(): Array<{
  circuit: CircuitName;
  system: ProvingSystem;
}> {
  const result: Array<{ circuit: CircuitName; system: ProvingSystem }> = [];
  for (const [circuit, systems] of Object.entries(CIRCUITS)) {
    for (const system of systems) {
      result.push({ circuit: circuit as CircuitName, system });
    }
  }
  return result;
}

/**
 * Verifies artifact integrity by comparing SHA-256 hashes against checksums.sha256.
 *
 * @param circuit - If specified, only verify artifacts for this circuit.
 *                  If omitted, verify all artifacts listed in checksums.sha256.
 * @returns true if all hashes match
 * @throws If checksums.sha256 is missing, any referenced file is missing,
 *         or any hash does not match the expected value.
 */
export function verifyIntegrity(circuit?: CircuitName): boolean {
  const artifactsDir = getArtifactsDir();
  const checksumFile = path.join(artifactsDir, 'checksums.sha256');

  if (!fs.existsSync(checksumFile)) {
    throw new Error(`Checksum file not found: ${checksumFile}`);
  }

  const content = fs.readFileSync(checksumFile, 'utf-8');
  const lines = content
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.length > 0);

  if (lines.length === 0) {
    throw new Error('checksums.sha256 is empty');
  }

  for (const line of lines) {
    // Format: <hash>  <relative-path>  (two-space separator from shasum)
    const match = line.match(/^([0-9a-f]{64})\s+(.+)$/);
    if (!match) {
      throw new Error(`Malformed checksum line: ${line}`);
    }

    const [, expectedHash, relativePath] = match;
    const filePath = path.resolve(artifactsDir, relativePath);

    // If filtering by circuit, skip files not under that circuit's directory
    if (circuit) {
      const circuitPrefix = path.join(artifactsDir, circuit);
      if (!filePath.startsWith(circuitPrefix + path.sep)) {
        continue;
      }
    }

    if (!fs.existsSync(filePath)) {
      throw new Error(`Artifact file not found: ${filePath}`);
    }

    const fileBuffer = fs.readFileSync(filePath);
    const actualHash = crypto.createHash('sha256').update(fileBuffer).digest('hex');

    if (actualHash !== expectedHash) {
      throw new Error(
        `Integrity check failed for ${relativePath}: ` +
          `expected ${expectedHash}, got ${actualHash}`,
      );
    }
  }

  return true;
}
