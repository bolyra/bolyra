// demo/demo.js
//
// @bolyra/delegation runnable demo. Designed for visual recording (vhs / asciinema):
// each step prints, pauses, then continues — so a viewer can read every line
// before the next one appears.
//
// Run:  node demo/demo.js   (from repo root, after `npm install` in delegation/)
// Or:   npm install @bolyra/delegation && node demo.js  (from any clean dir)

// Resolve from the published package by default; fall back to local dist
// when running inside this repo (so we can record without re-installing).
let lib;
try {
  lib = require("@bolyra/delegation");
} catch {
  lib = require("../dist");
}
const { allow, verify, generateKeyPair, PERM } = lib;

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

async function main() {
  console.log("");
  console.log(C.bold("@bolyra/delegation") + C.dim("  scoped delegation receipts for AI agents"));
  divider();
  await wait(1200);

  // --- Step 1: human signs a scoped receipt --------------------------------
  console.log("");
  console.log(C.cyan("[1/3]") + " Human signs receipt: " + C.bold("agent_alice") + C.dim(" → ") + C.bold("purchase @ example.com, $50 cap, 1h"));
  await wait(600);

  const human = await generateKeyPair();
  const receipt = await allow(
    {
      agent: "agent_alice",
      action: "purchase",
      audience: "example.com",
      permission: PERM.FINANCIAL_SMALL,
      maxAmount: { amount: 50, currency: "USD" },
      expiresIn: "1h",
    },
    human.privateKey,
    human.publicKey,
  );
  console.log("      " + C.green("✓") + " issued  " + C.dim(receipt.slice(0, 32) + "...."));
  await wait(1400);

  // --- Step 2: happy path --------------------------------------------------
  console.log("");
  console.log(C.cyan("[2/3]") + " Agent calls " + C.bold("purchase($25)"));
  await wait(600);
  const ok = await verify(receipt, {
    expectedAgent: "agent_alice",
    expectedAction: "purchase",
    expectedAudience: "example.com",
    trustedIssuers: human.publicKey,
    invocationAmount: { amount: 25, currency: "USD" },
  });
  console.log("      " + (ok.valid ? C.green("✓ ALLOWED") : C.red("✗ REJECTED")));
  await wait(1600);

  // --- Step 3: over-cap rejection -----------------------------------------
  console.log("");
  console.log(C.cyan("[3/3]") + " Agent calls " + C.bold("purchase($75)") + C.dim(" — over the $50 cap"));
  await wait(600);
  const overCap = await verify(receipt, {
    expectedAgent: "agent_alice",
    expectedAction: "purchase",
    expectedAudience: "example.com",
    trustedIssuers: human.publicKey,
    invocationAmount: { amount: 75, currency: "USD" },
  });
  console.log(
    "      " +
      (overCap.valid ? C.green("✓ ALLOWED") : C.red("✗ REJECTED")) +
      "   " +
      C.yellow(overCap.reason ?? "ok"),
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
