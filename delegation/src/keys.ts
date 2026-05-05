import { generateKeyPair as joseGenerateKeyPair, exportJWK, importJWK } from "jose";
import type { JWK } from "jose";

/**
 * Generate an Ed25519 keypair suitable for issuing or verifying delegation
 * receipts. Returns CryptoKey objects (jose accepts both CryptoKey and JWK
 * in its sign/verify APIs).
 */
export async function generateKeyPair(): Promise<{
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}> {
  const { privateKey, publicKey } = await joseGenerateKeyPair("EdDSA", {
    crv: "Ed25519",
    extractable: true,
  });
  return {
    privateKey: privateKey as CryptoKey,
    publicKey: publicKey as CryptoKey,
  };
}

/**
 * Export a keypair to a JWK pair for storage. Caller is responsible for
 * keeping the private JWK secret.
 */
export async function exportKeyPair(kp: {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}): Promise<{ privateJwk: JWK; publicJwk: JWK }> {
  const [privateJwk, publicJwk] = await Promise.all([
    exportJWK(kp.privateKey),
    exportJWK(kp.publicKey),
  ]);
  return { privateJwk, publicJwk };
}

/**
 * Import a JWK back into a CryptoKey usable by sign / verify.
 * `kind` selects the algorithm parameters; for Ed25519 use "EdDSA".
 */
export async function importKeyPair(jwks: {
  privateJwk?: JWK;
  publicJwk?: JWK;
}): Promise<{ privateKey?: CryptoKey; publicKey?: CryptoKey }> {
  const out: { privateKey?: CryptoKey; publicKey?: CryptoKey } = {};
  if (jwks.privateJwk) {
    out.privateKey = (await importJWK(jwks.privateJwk, "EdDSA")) as CryptoKey;
  }
  if (jwks.publicJwk) {
    out.publicKey = (await importJWK(jwks.publicJwk, "EdDSA")) as CryptoKey;
  }
  return out;
}

/**
 * Stable short fingerprint for a public key, suitable for use as an issuer
 * identifier in receipts when the caller doesn't supply one explicitly.
 * Format: "ed25519:<base64url(SHA-256(jwk.x))[:16]>"
 */
export async function fingerprintPublicKey(publicKey: CryptoKey): Promise<string> {
  const jwk = await exportJWK(publicKey);
  if (!jwk.x) throw new Error("public key has no x coordinate");
  const raw = base64urlToBytes(jwk.x);
  const buf = new ArrayBuffer(raw.byteLength);
  new Uint8Array(buf).set(raw);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
  return `ed25519:${bytesToBase64url(digest).slice(0, 22)}`;
}

function base64urlToBytes(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + pad;
  const bin = Buffer.from(b64, "base64");
  // Copy into a fresh Uint8Array backed by ArrayBuffer (not SharedArrayBuffer)
  // so it's compatible with crypto.subtle.digest's BufferSource parameter.
  const out = new Uint8Array(bin.length);
  out.set(bin);
  return out;
}

function bytesToBase64url(b: Uint8Array): string {
  return Buffer.from(b)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}
