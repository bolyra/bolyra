import { generateKeyPair, SignJWT } from "jose";
import type { KeyLike } from "jose";
import { verifyV01 } from "../src/legacy-v01";
import { staticIssuerResolver } from "../src/kid-resolver";

interface MintArgs {
  privateKey: KeyLike | Uint8Array;
  iss?: string;
  sub?: string;
  aud?: string;
  act?: string;
  perm?: string | number;
  iat?: number;
  exp?: number;
  nbf?: number;
  jti?: string;
  max?: { amount: number; currency: string };
  kid?: string;
  alg?: string;
}
async function mintV01(a: MintArgs): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const payload: Record<string, unknown> = {
    iss: a.iss ?? "i",
    sub: a.sub ?? "s",
    aud: a.aud ?? "a",
    act: a.act ?? "x",
    perm: a.perm ?? (1 << 2), // FINANCIAL_SMALL
    iat: a.iat ?? now,
    exp: a.exp ?? now + 60,
    jti: a.jti ?? "j",
  };
  if (a.nbf !== undefined) payload.nbf = a.nbf;
  if (a.max) payload.max = a.max;
  return new SignJWT(payload)
    .setProtectedHeader({ alg: a.alg ?? "EdDSA", kid: a.kid ?? "k" })
    .sign(a.privateKey);
}

describe("verifyV01 (back-compat path)", () => {
  it("happy path → ok:true, legacyV01:true", async () => {
    const { publicKey, privateKey } = await generateKeyPair("EdDSA");
    const jws = await mintV01({
      privateKey,
      iss: "did:web:bolyra.ai", sub: "agent-1", aud: "merchant-x",
      act: "checkout.charge", perm: 1 << 2, kid: "k1",
    });
    const r = await verifyV01(jws, {
      audience: "merchant-x", action: "checkout.charge", perm: 1 << 2,
      trustedIssuers: staticIssuerResolver({ "did:web:bolyra.ai": { k1: publicKey as unknown as CryptoKey } }),
    });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.legacyV01).toBe(true);
  });

  it("expired → ok:false reason:expired", async () => {
    const { publicKey, privateKey } = await generateKeyPair("EdDSA");
    const past = Math.floor(Date.now() / 1000) - 3600;
    const jws = await mintV01({ privateKey, iat: past - 10, exp: past });
    const r = await verifyV01(jws, {
      audience: "a",
      trustedIssuers: staticIssuerResolver({ i: { k: publicKey as unknown as CryptoKey } }),
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("expired");
  });

  it("not yet valid (iat in future) → ok:false reason:not_yet_valid", async () => {
    const { publicKey, privateKey } = await generateKeyPair("EdDSA");
    const future = Math.floor(Date.now() / 1000) + 3600;
    // v0.1 uses iat as the not-yet-valid anchor (no nbf in v0.1 schema).
    const jws = await mintV01({ privateKey, iat: future, exp: future + 60 });
    const r = await verifyV01(jws, {
      audience: "a",
      trustedIssuers: staticIssuerResolver({ i: { k: publicKey as unknown as CryptoKey } }),
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("not_yet_valid");
  });

  it("audience_mismatch", async () => {
    const { publicKey, privateKey } = await generateKeyPair("EdDSA");
    const jws = await mintV01({ privateKey, aud: "merchant-x" });
    const r = await verifyV01(jws, {
      audience: "merchant-y",
      trustedIssuers: staticIssuerResolver({ i: { k: publicKey as unknown as CryptoKey } }),
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("audience_mismatch");
  });

  it("agent_mismatch when expectedSubject set", async () => {
    const { publicKey, privateKey } = await generateKeyPair("EdDSA");
    const jws = await mintV01({ privateKey, sub: "agent-1" });
    const r = await verifyV01(jws, {
      audience: "a", expectedSubject: "agent-2",
      trustedIssuers: staticIssuerResolver({ i: { k: publicKey as unknown as CryptoKey } }),
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("agent_mismatch");
  });

  it("action_mismatch", async () => {
    const { publicKey, privateKey } = await generateKeyPair("EdDSA");
    const jws = await mintV01({ privateKey, act: "x" });
    const r = await verifyV01(jws, {
      audience: "a", action: "y",
      trustedIssuers: staticIssuerResolver({ i: { k: publicKey as unknown as CryptoKey } }),
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("action_mismatch");
  });

  it("permission_violation", async () => {
    const { publicKey, privateKey } = await generateKeyPair("EdDSA");
    // Grant FINANCIAL_MEDIUM (bit 3) without FINANCIAL_SMALL (bit 2) — invalid encoding.
    const jws = await mintV01({ privateKey, perm: 1 << 3 });
    const r = await verifyV01(jws, {
      audience: "a", perm: 1 << 1,
      trustedIssuers: staticIssuerResolver({ i: { k: publicKey as unknown as CryptoKey } }),
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("permission_violation");
  });

  it("amount_exceeds_cap", async () => {
    const { publicKey, privateKey } = await generateKeyPair("EdDSA");
    const jws = await mintV01({ privateKey, max: { amount: 50, currency: "USD" } });
    const r = await verifyV01(jws, {
      audience: "a", amount: 100, currency: "USD",
      trustedIssuers: staticIssuerResolver({ i: { k: publicKey as unknown as CryptoKey } }),
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("amount_exceeds_cap");
  });

  it("currency_mismatch", async () => {
    const { publicKey, privateKey } = await generateKeyPair("EdDSA");
    const jws = await mintV01({ privateKey, max: { amount: 100, currency: "USD" } });
    const r = await verifyV01(jws, {
      audience: "a", amount: 100, currency: "EUR",
      trustedIssuers: staticIssuerResolver({ i: { k: publicKey as unknown as CryptoKey } }),
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("currency_mismatch");
  });

  it("unknown_issuer_kid → resolver returns null", async () => {
    const { privateKey } = await generateKeyPair("EdDSA");
    const jws = await mintV01({ privateKey, kid: "missing" });
    const r = await verifyV01(jws, {
      audience: "a", trustedIssuers: async () => null,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("unknown_issuer_kid");
  });

  it("invalid_signature → tampered JWS body", async () => {
    const { publicKey, privateKey } = await generateKeyPair("EdDSA");
    const jws = await mintV01({ privateKey });
    const [h, p, s] = jws.split(".");
    // Mutate payload — signature now does not verify against public key.
    const tampered = `${h}.${p.replace(/.$/, p.endsWith("A") ? "B" : "A")}.${s}`;
    const r = await verifyV01(tampered, {
      audience: "a",
      trustedIssuers: staticIssuerResolver({ i: { k: publicKey as unknown as CryptoKey } }),
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("invalid_signature");
  });

  it("tilde input rejected → ok:false reason:legacy_v01_rejected", async () => {
    // A v0.2 SD-JWT receipt accidentally routed through the legacy path.
    const r = await verifyV01("eyJ.eyJ.sig~", {
      audience: "a", trustedIssuers: async () => null,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("legacy_v01_rejected");
  });
});
