// demo/demo.js
//
// @bolyra/delegation runnable demo. Designed for visual recording (vhs / asciinema):
// each step prints, pauses, then continues — so a viewer can read every line
// before the next one appears.
//
// Run:  node demo/demo.js   (from repo root, after `npm install` in delegation/)
// Or:   npm install @bolyra/delegation && node demo.js  (from any clean dir)
//
// Requires Node 20+ (Web Crypto / globalThis.crypto for jose).

// Resolve from the published package by default; fall back to local dist
// when running inside this repo (so we can record without re-installing).
let lib;
try {
  lib = require("@bolyra/delegation");
} catch {
  lib = require("../dist");
}
const { allow, present, verify, staticIssuerResolver } = lib;
// jose is a transitive dependency of @bolyra/delegation — used here just to
// mint the two Ed25519 keypairs (issuer + holder) the demo needs.
const { generateKeyPair } = require("jose");

const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const C = {
  dim: (s) => `\x1b[2m${s}\x1b[0m`,
  bold: (s) => `\x1b[1m${s}\x1b[0m`,
  green: (s) => `\x1b[32m${s}\x1b[0m`,
  red: (s) => `\x1b[31m${s}\x1b[0m`,
  cyan: (s) => `\x1b[36m${s}\x1b[0m`,
  yellow: (s) => `\x1b[33m${s}\x1b[0m`,
};

function divider() {
  console.log(C.dim("─".repeat(64)));
}

function freshNonce() {
  return "n-" + Math.random().toString(36).slice(2, 10);
}

async function main() {
  console.log("");
  console.log(C.bold("@bolyra/delegation") + C.dim("  scoped delegation receipts for AI agents"));
  divider();
  await wait(1200);

  // Setup: two Ed25519 keypairs — issuer (the human) and holder (the agent).
  const issuer = await generateKeyPair("EdDSA", { crv: "Ed25519", extractable: true });
  const holder = await generateKeyPair("EdDSA", { crv: "Ed25519", extractable: true });
  const trustedIssuers = staticIssuerResolver({
    "did:bolyra:alice": { k1: issuer.publicKey },
  });

  // --- Step 1: human signs a scoped receipt --------------------------------
  console.log("");
  console.log(C.cyan("[1/3]") + " Human signs receipt: " + C.bold("agent_alice") + C.dim(" → ") + C.bold("purchase @ example.com, $50 cap, 1h"));
  await wait(600);

  const receipt = await allow(
    {
      iss: "did:bolyra:alice",
      sub: "agent_alice",
      aud: "example.com",
      act: "purchase",
      perm: "FINANCIAL_SMALL",
      max: { amount: 50, currency: "USD" },
      ttlSeconds: 3600,
      agentPubKey: holder.publicKey,
    },
    { privateKey: issuer.privateKey, kid: "k1" },
  );
  console.log("      " + C.green("✓") + " issued  " + C.dim(receipt.slice(0, 32) + "...."));
  await wait(1400);

  // --- Step 2: happy path --------------------------------------------------
  console.log("");
  console.log(C.cyan("[2/3]") + " Agent calls " + C.bold("purchase($25)"));
  await wait(600);
  const nonceA = freshNonce();
  const presentedA = await present(receipt, holder.privateKey, {
    audience: "example.com",
    nonce: nonceA,
  });
  const ok = await verify(presentedA, {
    audience: "example.com",
    trustedIssuers,
    kbNonce: nonceA,
    action: "purchase",
    perm: "FINANCIAL_SMALL",
    amount: 25,
    currency: "USD",
  });
  console.log("      " + (ok.ok ? C.green("✓ ALLOWED") : C.red("✗ REJECTED")));
  await wait(1600);

  // --- Step 3: over-cap rejection -----------------------------------------
  console.log("");
  console.log(C.cyan("[3/3]") + " Agent calls " + C.bold("purchase($75)") + C.dim(" — over the $50 cap"));
  await wait(600);
  const nonceB = freshNonce();
  const presentedB = await present(receipt, holder.privateKey, {
    audience: "example.com",
    nonce: nonceB,
  });
  const overCap = await verify(presentedB, {
    audience: "example.com",
    trustedIssuers,
    kbNonce: nonceB,
    action: "purchase",
    perm: "FINANCIAL_SMALL",
    amount: 75,
    currency: "USD",
  });
  console.log(
    "      " +
      (overCap.ok ? C.green("✓ ALLOWED") : C.red("✗ REJECTED")) +
      "   " +
      C.yellow(overCap.ok ? "ok" : overCap.reason),
  );
  await wait(2000);

  // --- Outro ---------------------------------------------------------------
  console.log("");
  divider();
  console.log("");
  console.log("  " + C.bold("npm install @bolyra/delegation"));
  console.log("  " + C.dim("https://github.com/bolyra/bolyra"));
  console.log("");
  await wait(2000);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
