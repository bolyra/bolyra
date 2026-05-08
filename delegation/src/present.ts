import { SignJWT, decodeJwt, exportJWK } from "jose";
import { jwkThumbprint } from "./jwk-thumbprint";
import type { PresentOptions } from "./types";
import { createHash } from "node:crypto";

export async function present(
  receipt: string,
  holderPrivateKey: CryptoKey,
  opts: PresentOptions,
): Promise<string> {
  if (!receipt.includes("~")) {
    throw new Error("present: receipt is not SD-JWT shaped (missing '~')");
  }
  const parts = receipt.split("~");
  if (parts.length === 3 && parts[1] === "" && parts[2].length > 0) {
    throw new Error("present: receipt already presented");
  }
  if (parts.length !== 2 || parts[1] !== "") {
    throw new Error("present: receipt malformed");
  }
  const jws = parts[0];

  let claims: Record<string, unknown>;
  try {
    claims = decodeJwt(jws) as Record<string, unknown>;
  } catch {
    throw new Error("present: receipt JWS payload not parseable");
  }

  const cnf = claims.cnf as { jwk?: { kty: string; crv: string; x: string } } | undefined;
  if (!cnf?.jwk) throw new Error("present: receipt has no cnf.jwk");

  const holderJwk = await exportJWK(holderPrivateKey);
  if (holderJwk.kty !== "OKP" || holderJwk.crv !== "Ed25519" || typeof holderJwk.x !== "string") {
    throw new Error("present: holderPrivateKey must be Ed25519");
  }
  const tpHolder = await jwkThumbprint({ kty: "OKP", crv: "Ed25519", x: holderJwk.x });
  const tpCnf = await jwkThumbprint({ kty: "OKP", crv: "Ed25519", x: cnf.jwk.x });
  if (tpHolder !== tpCnf) {
    throw new Error("present: holder key thumbprint does not match cnf.jwk");
  }

  const sdHash = createHash("sha256").update(`${jws}~`).digest();
  const sdHashB64 = sdHash.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

  const kbJwt = await new SignJWT({
    aud: opts.audience,
    nonce: opts.nonce,
    sd_hash: sdHashB64,
    iat: Math.floor(Date.now() / 1000),
  })
    .setProtectedHeader({ alg: "EdDSA", typ: "kb+jwt" })
    .sign(holderPrivateKey);

  return `${jws}~~${kbJwt}`;
}
