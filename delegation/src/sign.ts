import { SignJWT } from "jose";
import { randomUUID } from "crypto";
import type { AllowOptions, Receipt } from "./types";
import { validateCumulativeBitEncoding } from "./permissions";
import { fingerprintPublicKey } from "./keys";

/**
 * Issue a signed delegation receipt. The human (or upstream agent) calls
 * this to grant a scoped, time-limited authority to an agent. The result
 * is an opaque compact JWS string the caller hands to the agent; the agent
 * presents it to a tool / merchant / scope, which uses verify() to check.
 *
 * Example:
 *   const { privateKey, publicKey } = await generateKeyPair();
 *   const receipt = await allow({
 *     agent: "agent_alice",
 *     action: "purchase",
 *     audience: "example.com",
 *     permission: PERM.FINANCIAL_SMALL,
 *     maxAmount: { amount: 50, currency: "USD" },
 *     expiresIn: "1h",
 *   }, privateKey, publicKey);
 */
export async function allow(
  opts: AllowOptions,
  privateKey: CryptoKey,
  publicKey?: CryptoKey,
): Promise<Receipt> {
  const violation = validateCumulativeBitEncoding(opts.permission);
  if (violation) {
    throw new Error(`invalid permission: ${violation}`);
  }

  const issuer = opts.issuer ?? (publicKey ? await fingerprintPublicKey(publicKey) : undefined);
  if (!issuer) {
    throw new Error(
      "allow() requires either opts.issuer or a publicKey to derive an issuer fingerprint",
    );
  }

  const now = Math.floor(Date.now() / 1000);
  const expiresIn = opts.expiresIn ?? "1h";

  const builder = new SignJWT({
    act: opts.action,
    perm: opts.permission,
    ...(opts.maxAmount ? { max: opts.maxAmount } : {}),
  })
    .setProtectedHeader({ alg: "EdDSA", typ: "bolyra-delegation+jwt" })
    .setIssuer(issuer)
    .setSubject(opts.agent)
    .setAudience(opts.audience)
    .setIssuedAt(now)
    .setJti(opts.jti ?? randomUUID())
    .setExpirationTime(typeof expiresIn === "number" ? now + expiresIn : expiresIn);

  return await builder.sign(privateKey);
}
