import * as path from 'path';
import * as fs from 'fs';

/** Thrown when a required circuit artifact (WASM or zkey) cannot be located. */
export class ArtifactNotFoundError extends Error {
  constructor(artifactName: string, searchedPaths: string[]) {
    const paths = searchedPaths.map((p) => `  - ${p}`).join('\n');
    super(
      `Bolyra artifact "${artifactName}" not found.\n` +
        `Searched:\n${paths}\n\n` +
        `Fix: run "npm run compile:circuits" in the bolyra repo root,\n` +
        `or set BOLYRA_ARTIFACTS_DIR to a directory containing the compiled artifacts.`
    );
    this.name = 'ArtifactNotFoundError';
  }
}

export interface ResolvedArtifacts {
  humanWasm: string;
  humanZkey: string;
  agentWasm: string;
  agentZkey: string;
  delegationWasm: string;
  delegationZkey: string;
  humanVkey: string;
  agentVkey: string;
  delegationVkey: string;
}

const ARTIFACT_MAP: Record<keyof ResolvedArtifacts, string> = {
  humanWasm: 'HumanUniqueness.wasm',
  humanZkey: 'HumanUniqueness_final.zkey',
  agentWasm: 'AgentPolicy.wasm',
  agentZkey: 'AgentPolicy_final.zkey',
  delegationWasm: 'Delegation.wasm',
  delegationZkey: 'Delegation_final.zkey',
  humanVkey: 'HumanUniqueness_vkey.json',
  agentVkey: 'AgentPolicy_vkey.json',
  delegationVkey: 'Delegation_vkey.json',
};

/**
 * Resolves circuit artifact paths. Resolution order:
 *   1. Explicit `artifactsDir` constructor argument
 *   2. BOLYRA_ARTIFACTS_DIR environment variable
 *   3. Relative to the installed @bolyra/sdk package (circuits/build/)
 */
export class ArtifactResolver {
  private readonly searchDirs: string[];

  constructor(artifactsDir?: string) {
    this.searchDirs = [];

    if (artifactsDir) {
      this.searchDirs.push(artifactsDir);
    }

    const envDir = process.env.BOLYRA_ARTIFACTS_DIR;
    if (envDir) {
      this.searchDirs.push(envDir);
    }

    // Resolve relative to the SDK package — walk up to the repo root
    // and look in circuits/build/
    try {
      const sdkIndex = require.resolve('@bolyra/sdk');
      const sdkRoot = path.dirname(path.dirname(sdkIndex));
      this.searchDirs.push(path.join(sdkRoot, '..', 'circuits', 'build'));
    } catch {
      // @bolyra/sdk not installed as a package — try CWD-based fallback
      this.searchDirs.push(path.join(process.cwd(), 'circuits', 'build'));
    }
  }

  resolve(): ResolvedArtifacts {
    const result: Partial<ResolvedArtifacts> = {};

    for (const [key, filename] of Object.entries(ARTIFACT_MAP)) {
      const resolved = this.findFile(filename);
      if (!resolved) {
        throw new ArtifactNotFoundError(filename, this.searchDirs);
      }
      (result as Record<string, string>)[key] = resolved;
    }

    return result as ResolvedArtifacts;
  }

  resolveSingle(key: keyof ResolvedArtifacts): string {
    const filename = ARTIFACT_MAP[key];
    const resolved = this.findFile(filename);
    if (!resolved) {
      throw new ArtifactNotFoundError(filename, this.searchDirs);
    }
    return resolved;
  }

  private findFile(filename: string): string | null {
    for (const dir of this.searchDirs) {
      const candidate = path.join(dir, filename);
      if (fs.existsSync(candidate)) {
        return candidate;
      }
    }
    return null;
  }
}
