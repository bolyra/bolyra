// NOTE: This is a PATCH showing the artifact-resolver integration.
// The actual prover.ts has additional code — only the relevant sections are shown.
//
// Import at top of file:
import { ArtifactResolver, type ResolvedArtifacts } from '@bolyra/artifacts';

// Shared resolver instance (lazy singleton)
let _resolver: ArtifactResolver | undefined;

function getResolver(): ArtifactResolver {
  if (!_resolver) {
    _resolver = new ArtifactResolver();
  }
  return _resolver;
}

// --- Patched proveHandshake() ---

/**
 * Prove a mutual handshake between a human and an agent.
 *
 * Circuit artifacts are resolved automatically:
 *   1. If BOLYRA_ARTIFACTS_DIR is set, uses local files (CI / dev workflow).
 *   2. Otherwise, checks ~/.bolyra/artifacts/<version>/ cache.
 *   3. On cache miss, fetches from CDN with SHA-256 integrity verification.
 */
export async function proveHandshake(
  human: HumanIdentity,
  agent: AgentCredential,
  nonce?: bigint,
): Promise<HandshakeProof> {
  const resolver = getResolver();

  // Resolve artifacts for both circuits in parallel
  const [humanArtifacts, agentArtifacts] = await Promise.all([
    resolver.resolveCircuit('HumanUniqueness'),
    resolver.resolveCircuit('AgentPolicy'),
  ]);

  const sessionNonce = nonce ?? generateNonce();

  // Generate human proof
  const humanInput = buildHumanInput(human, sessionNonce);
  const { proof: humanProof, publicSignals: humanSignals } =
    await snarkjs.groth16.fullProve(
      humanInput,
      humanArtifacts.wasmPath,
      humanArtifacts.zkeyPath,
    );

  // Generate agent proof
  const agentInput = buildAgentInput(agent, sessionNonce);
  const { proof: agentProof, publicSignals: agentSignals } =
    await snarkjs.groth16.fullProve(
      agentInput,
      agentArtifacts.wasmPath,
      agentArtifacts.zkeyPath,
    );

  return {
    humanProof: { proof: humanProof, publicSignals: humanSignals },
    agentProof: { proof: agentProof, publicSignals: agentSignals },
    sessionNonce,
  };
}

// Types referenced above (defined elsewhere in the actual file):
interface HumanIdentity { secret: bigint; commitment: bigint; }
interface AgentCredential { modelHash: bigint; permissions: number; expiry: number; }
interface HandshakeProof {
  humanProof: { proof: any; publicSignals: string[] };
  agentProof: { proof: any; publicSignals: string[] };
  sessionNonce: bigint;
}
declare function generateNonce(): bigint;
declare function buildHumanInput(human: HumanIdentity, nonce: bigint): any;
declare function buildAgentInput(agent: AgentCredential, nonce: bigint): any;
declare const snarkjs: any;
