import * as secp256k1 from '@noble/secp256k1';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { keccak_256 } from '@noble/hashes/sha3';
import { bytesToHex } from '@noble/hashes/utils';
import { canonicalize } from './canonical';
import type { ReceiptPayload, ReceiptSignerConfig, SignedReceipt } from './types';

// @noble/secp256k1 v2 requires hmacSha256Sync to be set for synchronous signing.
secp256k1.etc.hmacSha256Sync = (k: Uint8Array, ...m: Uint8Array[]) => {
  const h = hmac.create(sha256, k);
  for (const msg of m) h.update(msg);
  return h.digest();
};

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function utf8ToBytes(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

function deriveAddress(publicKeyBytes: Uint8Array): string {
  // Uncompressed public key is 65 bytes (04 || x || y).
  // For Ethereum address we hash the 64-byte x||y (skip the 04 prefix).
  const uncompressed = publicKeyBytes.length === 65
    ? publicKeyBytes.slice(1)
    : publicKeyBytes;
  const hash = keccak_256(uncompressed);
  return '0x' + bytesToHex(hash.slice(hash.length - 20));
}

export function hashPayload(payload: ReceiptPayload): string {
  const canonical = canonicalize(payload);
  const hash = keccak_256(utf8ToBytes(canonical));
  return '0x' + bytesToHex(hash);
}

export function signReceipt(
  payload: ReceiptPayload,
  config: ReceiptSignerConfig,
): SignedReceipt {
  const canonical = canonicalize(payload);
  const hash = keccak_256(utf8ToBytes(canonical));
  const privateKeyBytes = hexToBytes(config.privateKey);

  const sig = secp256k1.sign(hash, privateKeyBytes);
  const r = sig.r.toString(16).padStart(64, '0');
  const s = sig.s.toString(16).padStart(64, '0');
  const v = (sig.recovery + 27).toString(16).padStart(2, '0');
  const signatureHex = '0x' + r + s + v;

  const publicKey = secp256k1.getPublicKey(privateKeyBytes, false);
  const signer = deriveAddress(publicKey);

  const payloadHash = '0x' + bytesToHex(hash);
  const id = '0x' + payloadHash.slice(2, 18);

  return {
    id,
    payload,
    signature: {
      alg: 'ES256K',
      keyId: config.keyId,
      signer,
      payloadHash,
      value: signatureHex,
    },
  };
}

export function verifyReceipt(
  receipt: SignedReceipt,
  expectedSigner?: string,
): boolean {
  try {
    // Recompute hash from payload
    const canonical = canonicalize(receipt.payload);
    const hash = keccak_256(utf8ToBytes(canonical));
    const recomputedHash = '0x' + bytesToHex(hash);

    // Check hash matches
    if (recomputedHash !== receipt.signature.payloadHash) {
      return false;
    }

    // Extract r, s, v from 65-byte signature
    const sigHex = receipt.signature.value.startsWith('0x')
      ? receipt.signature.value.slice(2)
      : receipt.signature.value;

    const rHex = sigHex.slice(0, 64);
    const sHex = sigHex.slice(64, 128);
    const vByte = parseInt(sigHex.slice(128, 130), 16);
    const recoveryBit = vByte - 27;

    // Recover public key
    const rs = rHex + sHex;
    const recovered = secp256k1.Signature
      .fromCompact(rs)
      .addRecoveryBit(recoveryBit)
      .recoverPublicKey(hash);

    const recoveredAddress = deriveAddress(recovered.toRawBytes(false));

    // Always check recovered address matches the claimed signer in the receipt.
    // Without this, an attacker can change receipt.signature.signer to any
    // address and verifyReceipt still returns true.
    const claimedSigner = receipt.signature.signer.toLowerCase();
    const actual = recoveredAddress.toLowerCase();
    if (claimedSigner !== actual) {
      return false;
    }

    // Optional: also check against an externally expected signer
    if (expectedSigner && expectedSigner.toLowerCase() !== actual) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}
