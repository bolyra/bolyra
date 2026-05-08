import { calculateJwkThumbprint } from "jose";

export interface OkpEd25519Jwk {
  kty: "OKP";
  crv: "Ed25519";
  x: string;
}

/**
 * Compute the RFC 7638 JWK Thumbprint of an Ed25519 public JWK using SHA-256.
 *
 * Returns the thumbprint as base64url (no padding, 43 chars). v0.2 uses this
 * for `cnf.jkt` confirmation: the holder's KB-JWT must be signed by a key
 * whose thumbprint matches the issuer-bound `cnf.jwk` thumbprint.
 *
 * Only OKP/Ed25519 JWKs are accepted; passing any other key type throws.
 * Field order in the input JWK is irrelevant — jose canonicalizes per RFC 7638.
 *
 * @param jwk Ed25519 public JWK with required fields {kty: "OKP", crv: "Ed25519", x}
 * @returns base64url-encoded SHA-256 thumbprint, 43 chars, no padding
 * @throws if the JWK is not an OKP/Ed25519 public key
 */
export async function jwkThumbprint(jwk: OkpEd25519Jwk): Promise<string> {
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") {
    throw new Error("jwk-thumbprint: only OKP/Ed25519 JWKs are supported in v0.2");
  }
  // RFC 7638: canonical members for OKP are {crv, kty, x} sorted lexicographically.
  // jose does this internally.
  return calculateJwkThumbprint({ kty: jwk.kty, crv: jwk.crv, x: jwk.x }, "sha256");
}
