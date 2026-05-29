/**
 * @bolyra/mcp — types.
 *
 * Two transports, two right answers (per MCP spec 2025-03-26):
 *   - HTTP/SSE: caller identity travels in the Authorization header. Spec-aligned.
 *   - stdio: no transport-layer auth defined. Caller identity travels in `_meta.bolyra`.
 *
 * Both paths reduce to the same `BolyraAuthContext` attached to the request, so
 * downstream tool handlers don't care which transport was used.
 */

import type {
  HumanIdentity,
  AgentCredential,
  Proof,
  BolyraConfig,
} from '@bolyra/sdk';

/**
 * One hop in a v0.3 delegation chain. Carries the Groth16 proof produced by
 * `sdk.delegate()` plus the public inputs the verifier needs to recompute
 * `newScopeCommitment = Poseidon3(scope, commitment, expiry)` and check it
 * matches `publicSignals[0]` of the proof.
 *
 * All bigints are decimal strings for transport.
 */
export interface BolyraDelegationLink {
  /** Groth16 proof from the Delegation circuit. */
  proof: Proof;
  /** Delegatee credential commitment as decimal string. */
  delegateeCommitment: string;
  /** Delegatee scope (permission bitmask) as decimal string. */
  delegateeScope: string;
  /** Delegatee expiry (unix seconds) as decimal string. */
  delegateeExpiry: string;
  /** currentTimestamp (unix seconds) bound into the proof, as decimal string. */
  currentTimestamp: string;
}

/**
 * Wire format of a Bolyra proof bundle. This is what the client sends — either
 * base64-encoded inside `Authorization: Bolyra <base64-bundle>` (HTTP) or as
 * the value of `params._meta.bolyra` (stdio).
 *
 * All bigints are JSON-encoded as decimal strings to survive transport.
 *
 * v=1 is handshake-only. v=2 adds an optional `delegationChain` carrying the
 * scope-narrowing hops from the root credential to the agent actually calling.
 */
export interface BolyraProofBundle {
  /** Schema version. v=1: handshake only. v=2: handshake + optional delegation chain. */
  v: 1 | 2;
  /** Groth16 proof from the human's HumanUniqueness circuit. */
  humanProof: Proof;
  /** Groth16 proof from the agent's AgentPolicy circuit (root credential). */
  agentProof: Proof;
  /** Session nonce as decimal string. Verifier checks freshness. */
  nonce: string;
  /** Agent credential commitment as decimal string. Root credential — used to look up the credential. */
  credentialCommitment: string;
  /**
   * Optional delegation chain. When present, each link narrows scope from the
   * previous hop. The last link's `delegateeCommitment` is the agent actually
   * making the call; its `delegateeScope` is the effective permission bitmask.
   * v=2 only.
   */
  delegationChain?: BolyraDelegationLink[];
}

/**
 * Result of verifying a Bolyra proof bundle. Attached to the MCP request as
 * `extra.authInfo.bolyra` so per-tool handlers can read it without re-verifying.
 */
export interface BolyraAuthContext {
  /** True only if both ZKPs verified AND score met the configured floor. */
  verified: boolean;
  /** 0–100, same scoring as @bolyra/openclaw — keeps grading consistent across integrations. */
  score: number;
  /** did:bolyra:<network>:<commitment> — opaque agent identifier for logging/audit. */
  did: string;
  /**
   * Effective permission bitmask. If the bundle carried a delegation chain,
   * this is the leaf delegatee's scope (most-narrowed); otherwise it's the
   * root credential's bitmask. Per-tool policies check against this.
   */
  permissionBitmask: bigint;
  /** Human-readable warnings. Empty if all checks passed. */
  warnings: string[];
  /** Reason for failure when verified=false. Returned to the client as an MCP error. */
  reason?: string;
  /**
   * Number of delegation hops verified (0 = handshake only, N = N-hop chain).
   * Useful for per-tool policies that want to refuse delegated calls.
   */
  chainDepth: number;
  /**
   * Effective acting commitment. With no chain, equals the root
   * credentialCommitment; with a chain, equals the leaf delegateeCommitment.
   */
  effectiveCommitment: string;
}

/**
 * Per-tool permission policy. If a tool name is in the map, the caller's
 * permission bitmask must AND-cover `requireBitmask` for the call to succeed.
 *
 * Example: { "write_file": 0b10n, "delete_file": 0b110n }
 */
export type ToolPermissionPolicy = Record<string, bigint>;

/** Configuration shared by both server wrappers. */
export interface BolyraMcpConfig {
  /** Network identifier for DID construction (default: "base-sepolia"). */
  network?: string;
  /** Minimum score (0–100) required to pass. Default 70. */
  minScore?: number;
  /** Max acceptable nonce age in seconds. Default 300. */
  maxProofAge?: number;
  /**
   * Per-tool permission requirements. Tools not in the map require only that
   * the handshake itself verified — no extra permission check.
   */
  toolPolicy?: ToolPermissionPolicy;
  /**
   * Resolves a credential commitment (decimal string) to the AgentCredential
   * the verifier should check against. Backed by your credential registry —
   * a database, the on-chain registry, an in-memory map for tests.
   */
  resolveCredential: (
    credentialCommitment: string,
  ) => Promise<AgentCredential | null>;
  /** SDK config passthrough (rpc/registry/circuit dirs). */
  sdkConfig?: BolyraConfig;
  /**
   * Optional escape hatch: pass `CallToolRequestSchema` from
   * `@modelcontextprotocol/sdk/types.js` directly. Only needed when the wrapper
   * cannot synchronously `require` the SDK (e.g., bundled ESM). When omitted,
   * the wrapper resolves it via require at first call.
   */
  callToolRequestSchema?: unknown;
}

/** HTTP-transport-specific config (adds the auth scheme name). */
export interface BolyraMcpHttpConfig extends BolyraMcpConfig {
  /** Auth scheme. Default "Bolyra" → `Authorization: Bolyra <base64-bundle>`. */
  authScheme?: string;
}

/** Client-side helper return shape. */
export interface BolyraClientAuth {
  /** Header to attach for HTTP transports. */
  headers: { Authorization: string };
  /** _meta payload to attach for stdio transports. */
  meta: { bolyra: BolyraProofBundle };
  /** Raw bundle for callers that want to do something custom with it. */
  bundle: BolyraProofBundle;
}

/** Re-export the SDK types callers will need. */
export type { HumanIdentity, AgentCredential, Proof, BolyraConfig };
