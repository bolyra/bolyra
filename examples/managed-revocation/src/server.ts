/**
 * The paid API: one mppx charge method wrapped with `bolyraGate`, verifying every
 * presentation through a HOSTED Bolyra verifier (`verifier: { kind: 'url' }`), and an
 * application handler whose only side effect is `state.counter += 1`. The counter is the
 * evidence: a denied presentation must leave it untouched.
 *
 * `enforce: 'always'` (the gate's default) runs the Bolyra decision on EVERY request —
 * including the credential-less discovery request that mppx answers with a 402 — so one
 * demonstrated 402→pay handshake presents TWO fresh presentations: the discovery attempt
 * reserves the first one's nullifier, and re-sending it on the paid retry denies
 * `nonce_replayed`.
 */
import { Method, z } from 'mppx';
import { Mppx } from 'mppx/server';
import { bolyraGate, handleDenials, isBolyraDeniedError, type DenyVerdict } from '@bolyra/mpp';

export const AUDIENCE = 'api.merchant.example';
export const MODEL = 'opus-4.1';
export const PAYMENT_TOKEN = 'example-payment-token';
/** USD. Within `mpp:financial:small` (< $100), the tier the example's mandates carry. */
export const CHARGE_AMOUNT = '25';

export interface ServerState {
  /** The protected side effect: incremented only after the gate allowed AND mppx accepted payment. */
  counter: number;
  /** The last verdict the gate denied with, as thrown in-process (its `detail` never reaches the HTTP body). */
  lastDenial: DenyVerdict | undefined;
}

export interface GatedServer {
  state: ServerState;
  handler: (request: Request) => Promise<Response>;
}

/** The mock payment method (mppx's own test shape): no wallet, no chain — the point is the gate. */
export const chargeMethod = Method.from({
  name: 'example',
  intent: 'charge',
  schema: {
    credential: { payload: z.object({ token: z.string() }) },
    request: z.object({ amount: z.string() }),
  },
});

export function createServer(verifier: { url: string; token: string }): GatedServer {
  const method = Method.toServer(chargeMethod, {
    async verify({ credential }) {
      if (credential.payload.token !== PAYMENT_TOKEN) throw new Error('mock payment rejected');
      return {
        method: 'example',
        reference: `example-tx-${Date.now()}`,
        status: 'success' as const,
        timestamp: new Date().toISOString(),
      };
    },
  });

  const gated = bolyraGate(method, {
    audience: AUDIENCE,
    model: MODEL,
    verifier: { kind: 'url', url: `${verifier.url}/v1/verify`, token: verifier.token },
  });

  const mppx = Mppx.create({
    methods: [gated],
    realm: AUDIENCE,
    secretKey: 'example-secret-key-example-secret-key-32',
  });

  const state: ServerState = { counter: 0, lastDenial: undefined };

  const action = async (request: Request): Promise<Response> => {
    const result = await mppx.charge({ amount: CHARGE_AMOUNT })(request);
    if (result.status === 402) return result.challenge;
    state.counter += 1; // the protected action
    return result.withReceipt(Response.json({ ok: true, counter: state.counter }));
  };

  // handleDenials turns the gate's thrown BolyraDeniedError into its Problem Details
  // response; the wrapper in between records the verdict so run.ts can show the
  // structured `detail` the HTTP body does not carry.
  const handler = handleDenials(async (request: Request): Promise<Response> => {
    try {
      return await action(request);
    } catch (e) {
      if (isBolyraDeniedError(e)) state.lastDenial = e.verdict;
      throw e;
    }
  });

  return { state, handler };
}
