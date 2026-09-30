/**
 * Spend-policy simulator: local, simulated decisions signed as REAL
 * `bolyra.auth` receipts by a temporary browser-held key.
 *
 * What is real: the ES256K signature, the hash chain, the receipt schema.
 * What is simulated: the decision itself. Nothing here verifies a credential
 * or a proof, moves money, or enforces anything. The amount is not part of
 * the `bolyra.auth` schema, so it is reported alongside the receipt, not
 * inside the signed payload; the tier IS inside it (as the permission bitmask).
 *
 * Keys live in a module-private WeakMap, never on the session object, so a
 * session can be logged or serialized without leaking its private key.
 */
import { ReceiptChain, createAuthReceipt } from '@bolyra/receipts';
import * as secp256k1 from '@noble/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import { isTier, requiredTierForUsdAmount, tierCovers, tierBitmask } from './tiers.js';

export const ISSUER = 'bolyra-playground';
export const KEY_ID = 'playground-k1';
export const OPERATOR_DID = 'did:bolyra:playground:operator';
export const AGENT_DID = 'did:bolyra:playground:agent';
/** The reason code the classical verifier uses when a mandate's tier does not cover the request. */
export const DENY_REASON = 'request_mismatch';

const secrets = new WeakMap();
const toHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

function randomHex(bytes) {
  const buf = new Uint8Array(bytes);
  globalThis.crypto.getRandomValues(buf);
  return '0x' + toHex(buf);
}

function addressOf(privateKeyHex) {
  const pub = secp256k1.getPublicKey(privateKeyHex.slice(2), false); // 65 bytes, 0x04 || X || Y
  return '0x' + toHex(keccak_256(pub.slice(1)).slice(-20));
}

/**
 * Create a session. Every dependency with entropy or time is injectable so
 * tests are deterministic; production callers pass nothing.
 */
export function newSession({ privateKey, now, nonce, chainId = 1 } = {}) {
  const key = privateKey ?? '0x' + toHex(secp256k1.utils.randomPrivateKey());
  if (!/^0x[0-9a-fA-F]{64}$/.test(key)) throw new TypeError('privateKey must be 0x + 64 hex');
  const session = {
    chainId,
    signer: addressOf(key),
    receipts: [],
    /** Amounts are not inside the signed payload; keep them next to each receipt. */
    log: [],
    now: now ?? (() => Math.floor(Date.now() / 1000)),
    nonce: nonce ?? (() => randomHex(16)),
    chain: new ReceiptChain(),
    queue: Promise.resolve(),
    inFlight: 0,
  };
  secrets.set(session, key);
  return session;
}

function decideSync(session, { tier, amount }) {
  if (!isTier(tier)) return { outcome: 'invalid', reason: `unknown tier ${JSON.stringify(tier)}; expected small, medium or unlimited` };
  let requiredTier;
  try { requiredTier = requiredTierForUsdAmount(amount); } catch (err) {
    return { outcome: 'invalid', reason: err instanceof Error ? err.message : String(err) };
  }
  const allowed = tierCovers(tier, amount);
  const payload = createAuthReceipt({
    rootDid: OPERATOR_DID,
    actingDid: AGENT_DID,
    credentialCommitment: 'playground:simulated',
    effectiveCommitment: 'playground:simulated',
    allowed,
    ...(allowed ? {} : { reasonCode: DENY_REASON }),
    score: 0,
    permissionBitmask: tierBitmask(tier),
    chainDepth: 0,
    humanProof: { proof: null },
    agentProof: { proof: null },
    humanPublicSignals: [],
    agentPublicSignals: [],
    bundleVersion: 2,
    nonce: session.nonce(),
  }, { issuer: ISSUER, keyId: KEY_ID, issuedAt: session.now() });
  const receipt = session.chain.sign(payload, { issuer: ISSUER, keyId: KEY_ID, privateKey: secrets.get(session) });
  session.receipts.push(receipt);
  session.log.push({ seq: receipt.payload.chain.seq, tier, amount: String(amount).trim(), requiredTier, outcome: allowed ? 'allow' : 'deny' });
  return { outcome: allowed ? 'allow' : 'deny', requiredTier, tier, amount: String(amount).trim(), receipt, seq: receipt.payload.chain.seq };
}

/** Serialized: overlapping calls run one at a time so the chain stays consistent. */
export function decide(session, request) {
  session.inFlight += 1;
  const run = session.queue.then(() => {
    try { return decideSync(session, request); } finally { session.inFlight -= 1; }
  });
  session.queue = run.catch(() => undefined);
  return run;
}

/** New key, new chain, next chain id. Refused while a decision is running. */
export function resetSession(session) {
  if (session.inFlight > 0) throw new Error('reset refused: a decision is still in flight');
  return newSession({ now: session.now, nonce: session.nonce, chainId: session.chainId + 1 });
}

export function chainInfo(session) {
  const last = session.receipts[session.receipts.length - 1];
  return { chainId: session.chainId, seq: session.receipts.length, headHash: last ? last.receiptHash : null };
}

export function exportJsonl(session) {
  return session.receipts.length === 0 ? '' : session.receipts.map((r) => JSON.stringify(r)).join('\n') + '\n';
}

export function signerDoc(session) {
  return { issuer: ISSUER, keyId: KEY_ID, alg: 'ES256K', signer: session.signer, ephemeral: true };
}
