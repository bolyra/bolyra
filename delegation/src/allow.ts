import { SignJWT, exportJWK, importJWK } from "jose";
import type { AllowOptions } from "./types";

export async function allow(
  opts: AllowOptions,
  issuerKey: { privateKey: CryptoKey; kid: string }
): Promise<string> {
  if (opts.agentPubKey === undefined || opts.agentPubKey === null) {
    throw new Error("allow: agentPubKey missing");
  }
  if (!issuerKey?.kid) throw new Error("allow: issuerKey.kid empty");
  if (opts.statusList) {
    let proto: string;
    try {
      proto = new URL(opts.statusList.uri).protocol;
    } catch {
      throw new Error("allow: statusList.uri must use https://");
    }
    if (proto !== "https:") {
      throw new Error("allow: statusList.uri scheme not https");
    }
  }

  let agentPubCrypto: CryptoKey;
  if (typeof opts.agentPubKey === "string") {
    let parsed: unknown;
    try {
      parsed = JSON.parse(opts.agentPubKey);
    } catch {
      throw new Error("allow: agentPubKey unparseable");
    }
    if (!parsed || typeof parsed !== "object") {
      throw new Error("allow: agentPubKey unparseable");
    }
    try {
      const k = await importJWK(parsed as { kty: string; [k: string]: unknown }, "EdDSA");
      agentPubCrypto = k as CryptoKey;
    } catch {
      throw new Error("allow: agentPubKey unparseable");
    }
  } else {
    agentPubCrypto = opts.agentPubKey;
  }

  const cnfJwk = await exportJWK(agentPubCrypto);
  if (cnfJwk.kty !== "OKP" || cnfJwk.crv !== "Ed25519") {
    throw new Error("allow: agentPubKey must be Ed25519 (OKP)");
  }

  const now = Math.floor(Date.now() / 1000);
  const ttl = opts.ttlSeconds ?? 300;
  const exp = now + ttl;

  const payload: Record<string, unknown> = {
    iss: opts.iss,
    sub: opts.sub,
    aud: opts.aud,
    act: opts.act,
    perm: opts.perm,
    iat: now,
    exp,
    jti: opts.jti ?? crypto.randomUUID(),
    cnf: { jwk: { kty: "OKP", crv: "Ed25519", x: cnfJwk.x } },
    _sd: [],
  };
  if (opts.max) payload.max = opts.max;
  if (opts.statusList) payload.status = { status_list: opts.statusList };

  const jws = await new SignJWT(payload)
    .setProtectedHeader({
      alg: "EdDSA",
      typ: "bolyra-delegation+sd-jwt",
      kid: issuerKey.kid,
      _sd_alg: "sha-256",
    })
    .sign(issuerKey.privateKey);

  return `${jws}~`;
}
