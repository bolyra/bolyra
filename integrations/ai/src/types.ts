/**
 * @bolyra/ai — types.
 *
 * Configuration interfaces for the Vercel AI SDK adapter.
 * Re-exports core SDK types that callers need.
 */

import type {
  HumanIdentity,
  AgentCredential,
  Permission,
  BolyraConfig,
} from '@bolyra/sdk';

import type {
  NonceStore,
  BolyraAuthContext,
  BolyraProofBundle,
} from '@bolyra/mcp';

// ---------------------------------------------------------------------------
// withBolyraAuth — Language Model Wrapper Config
// ---------------------------------------------------------------------------

/** Auth mode: direct proof generation or gateway delegation. */
export type BolyraAuthMode = 'direct' | 'gateway';

/** Gateway configuration for proxy mode. */
export interface BolyraGatewayConfig {
  /** Gateway URL (e.g., https://gateway.example.com). */
  url: string;
  /** Optional API key for gateway authentication. */
  apiKey?: string;
}

/** Configuration for withBolyraAuth() language model wrapper. */
export interface BolyraAIConfig {
  /** Agent credential for direct proof generation. */
  credential?: AgentCredential;
  /** Operator private key (hex string or Buffer) for signing proof bundles. */
  operatorPrivateKey?: string | Buffer;
  /** Human identity for mutual handshake (optional in gateway mode). */
  humanIdentity?: HumanIdentity;

  /** Gateway mode: route tool calls through a Bolyra gateway. */
  gateway?: BolyraGatewayConfig;

  /** Per-tool permission requirements (tool name to minimum Permission). */
  toolPermissions?: Record<string, Permission>;

  /** Dev mode: use mock proofs (no circuit artifacts needed). */
  devMode?: boolean;

  /** Network identifier (default: 'base-sepolia'). */
  network?: string;

  /** SDK config passthrough (rpc/registry/circuit dirs). */
  sdkConfig?: BolyraConfig;
}

// ---------------------------------------------------------------------------
// bolyraAuthMiddleware — Server-Side Verification Config
// ---------------------------------------------------------------------------

/** Per-tool policy for server-side enforcement. */
export interface BolyraToolPolicy {
  /** Required permission bitmask (AND-cover check). */
  requireBitmask?: number;
  /** Minimum verification score (0-100). */
  minScore?: number;
  /** Maximum delegation chain depth allowed (0 = direct only). */
  maxChainDepth?: number;
}

/** Configuration for bolyraAuthMiddleware(). */
export interface BolyraServerConfig {
  /** Network identifier (default: 'base-sepolia'). */
  network?: string;
  /** Per-tool policies. */
  toolPolicy?: Record<string, BolyraToolPolicy>;
  /** Dev mode: accept mock proofs. */
  devMode?: boolean;
  /** Custom credential resolver for production verification. */
  resolveCredential?: (commitment: string) => Promise<AgentCredential | null>;
  /** Nonce store for replay protection (default: in-memory). */
  nonceStore?: NonceStore;
  /** SDK config passthrough. */
  sdkConfig?: BolyraConfig;
}

/** Result of server-side verification. */
export interface BolyraVerifyResult {
  /** Whether the request was successfully verified. */
  verified: boolean;
  /** Reason for failure (when verified=false). */
  reason?: string;
  /** Full auth context on success. */
  context?: BolyraAuthContext;
}

/** Server-side verifier object returned by bolyraAuthMiddleware(). */
export interface BolyraVerifier {
  /** Verify a Request's Bolyra authorization. */
  verify(req: Request, toolName?: string): Promise<BolyraVerifyResult>;
  /** Verify a raw authorization header value. */
  verifyHeader(authHeader: string, toolName?: string): Promise<BolyraVerifyResult>;
}

// ---------------------------------------------------------------------------
// createBolyraTools — Tool Definition Config
// ---------------------------------------------------------------------------

/** Configuration for createBolyraTools(). */
export interface BolyraToolsConfig {
  /** Agent credential for tool operations. */
  credential: AgentCredential;
  /** Operator private key for signing. */
  operatorPrivateKey?: string | Buffer;
  /** Human identity for mutual handshake. */
  humanIdentity?: HumanIdentity;
  /** Dev mode: use mock proofs. */
  devMode?: boolean;
  /** Network identifier (default: 'base-sepolia'). */
  network?: string;
}

// ---------------------------------------------------------------------------
// Re-exports for convenience
// ---------------------------------------------------------------------------

export type {
  HumanIdentity,
  AgentCredential,
  BolyraConfig,
  BolyraAuthContext,
  BolyraProofBundle,
  NonceStore,
};

export { Permission } from '@bolyra/sdk';
