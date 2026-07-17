/**
 * Operator-side spend-mandate issuance — the minting counterpart to
 * `verifyClassical`.
 *
 * WHAT THIS IS. `issueMandate` takes an operator private key the caller ALREADY
 * holds and produces one signed `bvp/1` presentation (the value carried in the
 * `X-Bolyra-Authorization` header) that authorizes a single agent to spend
 * within one financial tier, for one audience, until an expiry. The
 * cryptographically load-bearing output is the operator's EdDSA-Poseidon
 * binding signature over `{agent_name, project_key, program, model,
 * capabilities}` (classical.ts §4) — the exact fact `verifyClassical` anchors
 * an `allow` to.
 *
 * WHAT THIS IS NOT. This is issuance, not key management and not a wallet. It
 * neither generates, stores, nor rotates keys, holds funds, nor settles
 * payments — MPP moves the money; this only proves the mandate. The operator
 * key is a Baby Jubjub EdDSA scalar (bigint) or its 32-byte little-endian
 * buffer, the same shape `bolyra key generate` writes and `bolyra cred create`
 * consumes; sourcing and protecting it is the caller's job.
 *
 * CLASSICAL MODE ONLY. The emitted presentation carries a structurally-valid
 * but non-load-bearing proof envelope (the classical verifier never checks
 * proof math) — matching @bolyra/mpp's default `{ kind: 'classical' }`
 * verifier. Issuing a real Groth16 proof is out of scope here.
 *
 * CLASSICAL TRUST BOUNDARY — WHAT THE SIGNATURE ACTUALLY BINDS. The operator
 * EdDSA signature covers ONLY the request binding: `{agent_name, project_key,
 * program, model, capabilities}`. Those are the load-bearing, tamper-evident
 * fields — in particular the SPEND CEILING is enforced through the signed
 * `capabilities` tier tokens. The credential's `expiry` and `permission_bitmask`
 * are self-asserted public fields the classical verifier only cross-checks for
 * internal consistency (the scope commitment is recomputable from public
 * inputs), so classical mode does NOT cryptographically bind `expiry`: the
 * strict expiry check binds an UNMODIFIED presentation to the caller's clock,
 * but a presenter can re-anchor a later expiry and still verify `allow`.
 * Cryptographic time-bounding requires the zk-class verifier (`bolyra verify`).
 * Treat classical-mode expiry as advisory, and use short expiries plus the
 * signed capability ceiling as the real controls. (This is a property of the
 * shared classical verifier / EVC v1 binding, not of issuance — see
 * classical.ts "CLASSICAL TRUST MODEL".)
 */

import {
  derivePublicKey,
  eddsaSign,
  permissionsToBitmask,
  poseidon3,
  poseidon5,
  Permission,
} from '@bolyra/sdk';
import { randomBytes } from 'node:crypto';
import { bindingDigest, hashModel } from './classical';
import type { BindingClaim } from './bundle';
import { MPP_CAPABILITY_MAP, requiredTierForUsdAmount, tierCapability } from './tiers';
import type { FinancialTier } from './types';

/** Thrown on any invalid issuance input. Fail closed: no mandate is emitted. */
export class MandateIssueError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MandateIssueError';
  }
}

/** Financial tiers in cumulative order (each covers all lower tiers). */
const TIER_ORDER: readonly FinancialTier[] = ['small', 'medium', 'unlimited'];

/** How the issued presentation is serialized for transport. */
export type MandateEncoding = 'base64url' | 'json';

/** Inputs to {@link issueMandate}. Provide exactly one of `tier` / `maxUsd`. */
export interface IssueMandateInput {
  /**
   * Operator EdDSA private key: a Baby Jubjub scalar (bigint) or its 32-byte
   * buffer (the `bolyra key generate` / `parseKeyFile` shape). NOT generated or
   * stored here — issuance only.
   */
  operatorPrivateKey: bigint | Buffer;
  /** The acting agent identity — `binding.agent_name`. */
  agentName: string;
  /** The payee / project key this mandate is valid for — `binding.project_key`. */
  audience: string;
  /** The model the credential binds to — `binding.model`. */
  model: string;
  /** Binding `program` discriminator. Default `"mpp"`. */
  program?: string;
  /** Financial tier to delegate. Provide this OR `maxUsd`, not both. */
  tier?: FinancialTier;
  /**
   * Maximum USD spend to authorize; mapped to the smallest tier that covers it
   * (`< $100` → small, `< $10,000` → medium, otherwise unlimited). Provide this
   * OR `tier`, not both.
   */
  maxUsd?: string | number;
  /**
   * Credential expiry, unix seconds. Must be a positive integer. NOTE: in
   * classical mode this is NOT bound by the operator signature (see the file
   * header's "CLASSICAL TRUST BOUNDARY") — it is advisory against an adversarial
   * presenter. Prefer short expiries.
   */
  expiry: number;
  /**
   * Opaque mandate / delegation identifier echoed into the presentation for the
   * operator's own correlation and audit. It is UNSIGNED and UNVERIFIED — not a
   * replay nonce, and not tamper-evident: a presenter can alter it while the
   * mandate still verifies, so downstream consumers MUST treat it as untrusted
   * presentation metadata, not an authenticated mandate id. A spend mandate is
   * a standing authorization, so classical verification neither reads nor
   * consumes this value. Defaults to a random hex id.
   */
  nonce?: string;
  /** Transport encoding of the returned presentation. Default `"base64url"`. */
  encoding?: MandateEncoding;
}

/** The issued mandate: the presentation plus its resolved, echoed facts. */
export interface IssuedMandate {
  /** The `X-Bolyra-Authorization` header value (a `bvp/1` presentation). */
  presentation: string;
  /** The resolved financial tier. */
  tier: FinancialTier;
  /** The cumulative capability tokens signed into the binding. */
  capabilities: string[];
  /** The operator public key clients configure as a trusted issuer. */
  operatorPublicKey: { x: string; y: string };
  agentName: string;
  audience: string;
  model: string;
  program: string;
  expiry: number;
  nonce: string;
}

/** Capability tokens for a tier and every lower tier (cumulative). */
function cumulativeCapabilities(tier: FinancialTier): string[] {
  const idx = TIER_ORDER.indexOf(tier);
  return TIER_ORDER.slice(0, idx + 1).map(tierCapability);
}

/** The Permission bits a tier grants, cumulative — sourced from the MPP map. */
function tierPermissions(tier: FinancialTier): Permission[] {
  return MPP_CAPABILITY_MAP[tierCapability(tier)].map((name) => Permission[name]);
}

function isValidTier(value: unknown): value is FinancialTier {
  return typeof value === 'string' && (TIER_ORDER as readonly string[]).includes(value);
}

/**
 * Internal `bvp/1` assembler — the SINGLE code path that turns already-resolved
 * issuance parts into a serialized presentation. `issueMandate` (the public,
 * validated, tier-based entry point the CLI wraps) and the package's own test
 * fixtures both build through this, so there is one minting path, not two.
 *
 * The signature is over `binding` exactly as passed; the revealed credential
 * bitmask comes from `permissions`; the proof `scopeCommitment` is recomputed
 * from that revealed bitmask so the classical scope-anchor check is consistent.
 * Not exported from the package index — internal to issuance + fixtures.
 */
export async function mintPresentation(params: {
  operatorPrivateKey: bigint | Buffer;
  binding: BindingClaim;
  permissions: Permission[];
  expiry: number;
  nonce?: string;
  encoding?: MandateEncoding;
}): Promise<string> {
  const { operatorPrivateKey, binding, permissions, expiry } = params;
  const encoding = params.encoding ?? 'base64url';

  const operatorPub = await derivePublicKey(operatorPrivateKey);
  const modelHash = hashModel(binding.model);
  const bitmask = permissionsToBitmask(permissions);

  const credentialCommitment = await poseidon5(
    modelHash,
    operatorPub.x,
    operatorPub.y,
    bitmask,
    BigInt(expiry),
  );
  const scopeCommitment = await poseidon3(bitmask, credentialCommitment, BigInt(expiry));
  const sig = await eddsaSign(operatorPrivateKey, bindingDigest(binding));

  const bundle: Record<string, unknown> = {
    bvp: 1,
    agent: {
      envelope: {
        version: '1.0.0',
        circuit: { name: 'AgentPolicy', version: '1.0.0' },
        proofType: 'groth16',
        // Only publicSignals[2] (scopeCommitment) and [3] (bitmask) are read on
        // the classical path; the rest are structurally-valid placeholders —
        // classical mode carries no real Groth16 proof (see file header).
        publicSignals: [
          '1',
          '2',
          scopeCommitment.toString(),
          bitmask.toString(),
          String(expiry),
          '3',
        ],
        proof: {
          pi_a: ['1', '2'],
          pi_b: [
            ['1', '2'],
            ['3', '4'],
          ],
          pi_c: ['5', '6'],
        },
      },
      credential: {
        model_hash: modelHash.toString(),
        operator_pubkey: { x: operatorPub.x.toString(), y: operatorPub.y.toString() },
        permission_bitmask: bitmask.toString(),
        expiry,
      },
    },
    binding,
    sig: {
      R8: { x: sig.R8.x.toString(), y: sig.R8.y.toString() },
      S: sig.S.toString(),
    },
  };
  // Opaque operator-correlation id; unverified by classical mode (see header).
  if (params.nonce !== undefined) bundle.nonce = params.nonce;

  const json = JSON.stringify(bundle);
  return encoding === 'base64url' ? Buffer.from(json, 'utf8').toString('base64url') : json;
}

/**
 * Issue a delegated spend mandate: validate inputs, resolve the financial tier,
 * and mint the signed `bvp/1` presentation @bolyra/mpp's classical gate
 * consumes. Throws {@link MandateIssueError} on any bad input (fail closed —
 * never emits a partially-specified mandate).
 */
export async function issueMandate(input: IssueMandateInput): Promise<IssuedMandate> {
  const agentName = requireNonEmpty(input.agentName, 'agentName');
  const audience = requireNonEmpty(input.audience, 'audience');
  const model = requireNonEmpty(input.model, 'model');
  const program = input.program === undefined ? 'mpp' : requireNonEmpty(input.program, 'program');

  if (
    input.operatorPrivateKey === undefined ||
    input.operatorPrivateKey === null ||
    (typeof input.operatorPrivateKey !== 'bigint' && !Buffer.isBuffer(input.operatorPrivateKey))
  ) {
    throw new MandateIssueError('operatorPrivateKey must be a bigint scalar or a Buffer');
  }
  if (Buffer.isBuffer(input.operatorPrivateKey) && input.operatorPrivateKey.length !== 32) {
    throw new MandateIssueError('operatorPrivateKey Buffer must be exactly 32 bytes');
  }
  if (typeof input.operatorPrivateKey === 'bigint' && input.operatorPrivateKey <= 0n) {
    throw new MandateIssueError('operatorPrivateKey scalar must be positive');
  }

  // Exactly one of tier / maxUsd.
  const hasTier = input.tier !== undefined;
  const hasMaxUsd = input.maxUsd !== undefined;
  if (hasTier === hasMaxUsd) {
    throw new MandateIssueError('provide exactly one of `tier` or `maxUsd`');
  }

  let tier: FinancialTier;
  if (hasTier) {
    if (!isValidTier(input.tier)) {
      throw new MandateIssueError(
        `invalid tier "${String(input.tier)}" — use one of: ${TIER_ORDER.join(', ')}`,
      );
    }
    tier = input.tier;
  } else {
    try {
      tier = requiredTierForUsdAmount(input.maxUsd as string | number);
    } catch (err) {
      throw new MandateIssueError(
        `invalid maxUsd: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  if (
    typeof input.expiry !== 'number' ||
    !Number.isInteger(input.expiry) ||
    input.expiry <= 0
  ) {
    throw new MandateIssueError('expiry must be a positive integer (unix seconds)');
  }

  const encoding = input.encoding ?? 'base64url';
  if (encoding !== 'base64url' && encoding !== 'json') {
    throw new MandateIssueError(
      `invalid encoding "${String(input.encoding)}" — use "base64url" or "json"`,
    );
  }

  const nonce = input.nonce ?? randomBytes(16).toString('hex');
  const capabilities = cumulativeCapabilities(tier);
  const binding: BindingClaim = {
    agent_name: agentName,
    project_key: audience,
    program,
    model,
    capabilities,
  };

  const presentation = await mintPresentation({
    operatorPrivateKey: input.operatorPrivateKey,
    binding,
    permissions: tierPermissions(tier),
    expiry: input.expiry,
    nonce,
    encoding,
  });

  const operatorPub = await derivePublicKey(input.operatorPrivateKey);
  return {
    presentation,
    tier,
    capabilities,
    operatorPublicKey: { x: operatorPub.x.toString(), y: operatorPub.y.toString() },
    agentName,
    audience,
    model,
    program,
    expiry: input.expiry,
    nonce,
  };
}

function requireNonEmpty(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new MandateIssueError(`${label} is required and must be a non-empty string`);
  }
  return value;
}
