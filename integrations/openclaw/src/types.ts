/**
 * OpenClaw trust verification types.
 * Based on OpenClaw RFC #49971 — TrustVerificationResult interface.
 */

/** Trust verification grade (A = highest, F = untrusted) */
export type TrustGrade = 'A' | 'B' | 'C' | 'D' | 'F';

/** Result of an OpenClaw trust verification check */
export interface TrustVerificationResult {
  /** Whether the agent passed verification */
  verified: boolean;
  /** Trust score from 0–100 */
  score: number;
  /** Letter grade derived from score */
  grade: TrustGrade;
  /** DID identifier for the verified agent (did:bolyra:<network>:<commitment>) */
  did?: string;
  /** W3C Verifiable Credentials (optional, for future VC integration) */
  credentials?: unknown[];
  /** Warnings or notes about the verification */
  warnings?: string[];
}

/** OpenClaw plugin interface — implements the onAgentVerify hook */
export interface OpenClawPlugin {
  /** Hook called at agent verification points (skill install, payment, inter-agent comm) */
  onAgentVerify?(agentId: string): Promise<TrustVerificationResult>;
}

/** Verification context passed to the adapter at each verification point */
export type VerificationPoint =
  | 'skill_installation'
  | 'payment_execution'
  | 'inter_agent_communication'
  | 'gateway_startup';

/** Configuration for the Bolyra OpenClaw adapter */
export interface BolyraOpenClawConfig {
  /** Network identifier for DID construction (default: "base-sepolia") */
  network?: string;
  /** Minimum score threshold for passing verification (default: 70) */
  minScore?: number;
  /** Maximum proof age in seconds before requiring re-verification (default: 300) */
  maxProofAge?: number;
  /** Which verification points to enforce (default: all) */
  verificationPoints?: VerificationPoint[];
  /** SDK config passthrough */
  sdkConfig?: {
    rpcUrl?: string;
    registryAddress?: string;
    circuitDir?: string;
    zkeyDir?: string;
  };
}
