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

import { Challenge, Credential, Method, Receipt, z } from 'mppx';
import { Mppx } from 'mppx/server';
import {
  derivePublicKey,
  eddsaSign,
  permissionsToBitmask,
  poseidon3,
  poseidon5,
  Permission,
} from '@bolyra/sdk';
import {
  bolyraGate,
  bindingDigest,
  hashModel,
  BOLYRA_AUTHORIZATION_HEADER,
  type BindingClaim,
} from '@bolyra/mpp';

// ─── 1. OPERATOR: delegate a small-tier spend mandate to the agent ─────────
//
// The operator signs a request binding naming the agent, the audience
// (payee), and the capability set — here the FINANCIAL_SMALL tier only.
// In production this presentation is minted by Bolyra tooling; the demo
// builds it inline to stay dependency-free.

const OPERATOR_PRIVATE_KEY = 42n; // demo only — never a real key
const AUDIENCE = 'api.merchant.example';
const MODEL = 'opus-4.1';
const EXPIRY = Math.floor(Date.now() / 1000) + 3600; // 1 hour mandate

async function mintMandatePresentation(): Promise<string> {
  const binding: BindingClaim = {
    agent_name: 'shopper-bot',
    project_key: AUDIENCE,
    program: 'mpp',
    model: MODEL,
    capabilities: ['mpp:financial:small'], // < $100, nothing more
  };

  const operatorPub = await derivePublicKey(OPERATOR_PRIVATE_KEY);
  const modelHash = hashModel(MODEL);
  const bitmask = permissionsToBitmask([Permission.READ_DATA, Permission.FINANCIAL_SMALL]);
  const credentialCommitment = await poseidon5(
    modelHash,
    operatorPub.x,
    operatorPub.y,
    bitmask,
    BigInt(EXPIRY),
  );
  const scopeCommitment = await poseidon3(bitmask, credentialCommitment, BigInt(EXPIRY));
  const sig = await eddsaSign(OPERATOR_PRIVATE_KEY, bindingDigest(binding));

  const bundle = {
    bvp: 1,
    agent: {
      envelope: {
        version: '1.0.0',
        circuit: { name: 'AgentPolicy', version: '1.0.0' },
        proofType: 'groth16',
        publicSignals: ['1', '2', scopeCommitment.toString(), bitmask.toString(), '1', '3'],
        proof: { pi_a: ['1', '2'], pi_b: [['1', '2'], ['3', '4']], pi_c: ['5', '6'] },
      },
      credential: {
        model_hash: modelHash.toString(),
        operator_pubkey: { x: operatorPub.x.toString(), y: operatorPub.y.toString() },
        permission_bitmask: bitmask.toString(),
        expiry: EXPIRY,
      },
    },
    binding,
    sig: {
      R8: { x: sig.R8.x.toString(), y: sig.R8.y.toString() },
      S: sig.S.toString(),
    },
  };
  return Buffer.from(JSON.stringify(bundle), 'utf8').toString('base64url');
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
  const mandate = await mintMandatePresentation();

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
