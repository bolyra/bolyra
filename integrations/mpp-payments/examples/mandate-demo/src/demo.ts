/**
 * @bolyra/mpp mandate demo — self-contained, in-process, no chain access.
 *
 * Cast:
 *   OPERATOR  delegates a FINANCIAL_SMALL (< $100) spend mandate to an agent
 *             by signing a Bolyra request binding.
 *   AGENT     calls a paid mppx API, carrying the mandate presentation in the
 *             X-Bolyra-Authorization header alongside MPP's own payment flow.
 *   SERVER    an mppx server whose payment method is wrapped with
 *             `bolyraGate` — the mandate is verified BEFORE the payment flow
 *             proceeds.
 *
 * The payment method itself is a mock (`Method.from` + `Method.toServer`, the
 * same shape mppx's own tests use) so the demo needs no testnet or wallet:
 * the point demonstrated is the authorization gate, not payment settlement.
 *
 * Run: npm install && npm run demo
 */

import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { Challenge, Credential, Method, Receipt, z } from 'mppx';
import { Mppx } from 'mppx/server';
import { derivePublicKey } from '@bolyra/sdk';
import { bolyraGate, BOLYRA_AUTHORIZATION_HEADER } from '@bolyra/mpp';

// ─── 1. OPERATOR: delegate a small-tier spend mandate with `bolyra mandate` ──
//
// The operator issues the presentation with the REAL CLI — `bolyra mandate
// issue` — signing a request binding that names the agent, the audience
// (payee), the financial tier, and an expiry. This is the same issuance path
// the @bolyra/mpp test fixtures use; there is no inline minting. The CLI takes
// an operator key file (here a throwaway scalar) and prints the bvp/1
// presentation on stdout.

const OPERATOR_PRIVATE_KEY = 42n; // demo only — never a real key
const AUDIENCE = 'api.merchant.example';
const MODEL = 'opus-4.1';

/** The built CLI entry point, relative to this example. */
const CLI_MAIN = fileURLToPath(new URL('../../../../cli/dist/main.js', import.meta.url));

/**
 * Issue the mandate by invoking `bolyra mandate issue`. Writes the demo
 * operator scalar to a 32-byte key file (the `bolyra key generate` shape) and
 * shells out to the CLI, returning the presentation it prints on stdout.
 */
function issueMandateViaCli(): string {
  if (!fs.existsSync(CLI_MAIN)) {
    throw new Error(
      `Bolyra CLI is not built at ${CLI_MAIN}.\n` +
        'Build it first:  (cd ../../../cli && npm install && npm run build)',
    );
  }

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bolyra-mandate-demo-'));
  const keyFile = path.join(tmpDir, 'operator.key');
  fs.writeFileSync(
    keyFile,
    Buffer.from(OPERATOR_PRIVATE_KEY.toString(16).padStart(64, '0'), 'hex'),
    { mode: 0o600 },
  );

  try {
    const result = spawnSync(
      process.execPath,
      [
        CLI_MAIN,
        'mandate',
        'issue',
        '--operator-key',
        keyFile,
        '--agent',
        'shopper-bot',
        '--audience',
        AUDIENCE,
        '--model',
        MODEL,
        '--tier',
        'small', // < $100, nothing more
        '--expiry',
        '1h',
      ],
      { encoding: 'utf-8' },
    );
    if (result.status !== 0) {
      throw new Error(`bolyra mandate issue failed:\n${result.stderr}`);
    }
    // stdout is exactly the presentation (pipe-clean by design).
    return result.stdout.trim();
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

// ─── 2. SERVER: an mppx payment method wrapped with bolyraGate ─────────────

const mockCharge = Method.toServer(
  Method.from({
    name: 'mock',
    intent: 'charge',
    schema: {
      credential: { payload: z.object({ token: z.string() }) },
      request: z.object({ amount: z.string(), currency: z.string(), recipient: z.string() }),
    },
  }),
  {
    async verify({ credential }) {
      if (credential.payload.token !== 'demo-payment-token') {
        throw new Error('mock payment rejected');
      }
      return {
        method: 'mock',
        reference: `mock-tx-${Date.now()}`,
        status: 'success' as const,
        timestamp: new Date().toISOString(),
      };
    },
  },
);

async function createServer() {
  const operatorPub = await derivePublicKey(OPERATOR_PRIVATE_KEY);

  const gated = bolyraGate(mockCharge, {
    audience: AUDIENCE,
    verifier: {
      kind: 'classical',
      trustedOperators: [{ x: operatorPub.x.toString(), y: operatorPub.y.toString() }],
    },
    model: MODEL,
    onReceipt: (receipt) => {
      console.log(
        `   [gate receipt] seq=${receipt.payload.chain?.seq} allowed=${receipt.payload.decision.allowed}` +
          `${receipt.payload.decision.reasonCode ? ` reason=${receipt.payload.decision.reasonCode}` : ''}` +
          ` signer=${receipt.signature.signer.slice(0, 10)}…`,
      );
    },
  });

  const mppx = Mppx.create({
    methods: [gated],
    realm: AUDIENCE,
    secretKey: 'demo-secret-key-demo-secret-key-32',
  });

  const routeDefaults = {
    currency: 'USD',
    recipient: 'merchant-account-1',
  };

  // The standard mppx route-handler pattern, unchanged by the gate.
  return async function handler(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const amount = url.pathname === '/api/report' ? '25' : '500';
    const result = await mppx.charge({ amount, ...routeDefaults })(request);
    if (result.status === 402) return result.challenge;
    return result.withReceipt(Response.json({ data: `paid content for ${url.pathname}` }));
  };
}

// ─── 3. AGENT: MPP 402 flow + the mandate header ────────────────────────────

async function payAndCall(
  handler: (request: Request) => Promise<Response>,
  path: string,
  mandate?: string,
): Promise<Response> {
  const headers: Record<string, string> = {};
  if (mandate !== undefined) headers[BOLYRA_AUTHORIZATION_HEADER] = mandate;

  // First request: no payment credential → expect a 402 challenge.
  const first = await handler(new Request(`https://${AUDIENCE}${path}`, { headers }));
  if (first.status !== 402) return first;

  // Build the mock payment credential from the challenge and retry.
  const challenge = Challenge.fromResponse(first);
  const credential = Credential.from({ challenge, payload: { token: 'demo-payment-token' } });
  return handler(
    new Request(`https://${AUDIENCE}${path}`, {
      headers: { ...headers, Authorization: Credential.serialize(credential) },
    }),
  );
}

async function describeResponse(label: string, response: Response) {
  console.log(`\n➤ ${label}`);
  console.log(`   HTTP ${response.status}`);
  const receiptHeader = response.headers.get('Payment-Receipt');
  if (receiptHeader) {
    const receipt = Receipt.deserialize(receiptHeader) as Record<string, unknown>;
    console.log(`   Payment-Receipt: method=${receipt.method} reference=${receipt.reference}`);
    const authz = receipt.bolyraAuthorization as Record<string, unknown> | undefined;
    if (authz) {
      console.log(
        `   bolyraAuthorization: tier=${authz.tier} amountUsd=$${authz.amountUsd} ` +
          `verifier=${authz.verifier} audience=${authz.audience}`,
      );
    }
  } else {
    console.log(`   body: ${await response.text()}`);
  }
}

async function main() {
  console.log('@bolyra/mpp mandate demo — MPP moves the money; Bolyra proves the mandate.\n');
  console.log(`Operator delegates: mpp:financial:small (< $100) to "shopper-bot" for ${AUDIENCE}`);

  const handler = await createServer();
  const mandate = issueMandateViaCli();

  // Allowed: $25 is within the delegated FINANCIAL_SMALL tier.
  await describeResponse(
    'GET /api/report ($25) with mandate — within tier',
    await payAndCall(handler, '/api/report', mandate),
  );

  // Denied: $500 needs FINANCIAL_MEDIUM; the mandate only covers small.
  // The gate denies BEFORE the payment flow proceeds — no challenge, no charge.
  await describeResponse(
    'GET /api/bulk-export ($500) with the same mandate — over tier',
    await payAndCall(handler, '/api/bulk-export', mandate),
  );

  // Denied: no mandate presented at all.
  await describeResponse(
    'GET /api/report ($25) without a mandate',
    await payAndCall(handler, '/api/report'),
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
