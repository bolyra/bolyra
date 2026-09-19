/**
 * Real-mppx harness for the gate's integration tests.
 * A custom `Method.from` method with a stub `verify` stands in for a payment
 * rail; the challenge is minted by the SAME Mppx instance so its signature
 * validates; the Bolyra bundle comes from the package's own issuance path.
 */
import { Mppx } from 'mppx/server';
import { Credential, Method, z } from 'mppx';
import { bolyraGate, BOLYRA_AUTHORIZATION_HEADER } from '../src/gate.js';
import type { BolyraGateOptions } from '../src/types.js'; // not re-exported by gate.ts
import { makeBundle, operatorKey, AUDIENCE, NOW_UNIX } from '../test/helpers.js';

export const SECRET_KEY = 'test-secret-key-test-secret-key-32';
/** The mppx realm is the audience the spend mandate is signed for. */
export const REALM = AUDIENCE;
export const ROUTE_URL = 'https://api.merchant.example/paid';

export const testCharge = Method.from({
  name: 'test',
  intent: 'charge',
  schema: {
    credential: { payload: z.object({ token: z.string() }) },
    request: z.object({ amount: z.string() }),
  },
});

/** Everything `Method.toServer` accepts for `testCharge` except `verify`, which the harness supplies. */
export type ServerHooks = Partial<Omit<Method.toServer.Options<typeof testCharge>, 'verify'>>;

/** A server method (real mppx `Method.Server`) whose verify always succeeds; `hooks` lets a test add preflight/authorize. */
export function serverMethod(hooks: ServerHooks = {}) {
  return Method.toServer(testCharge, {
    verify: async () => ({
      method: 'test',
      reference: 'tx-test',
      status: 'success' as const,
      timestamp: new Date(0).toISOString(),
    }),
    ...hooks,
  });
}

export type TestServerMethod = ReturnType<typeof serverMethod>;

export async function classicalGateOptions(
  overrides: Partial<BolyraGateOptions> = {},
): Promise<BolyraGateOptions> {
  return {
    audience: AUDIENCE,
    verifier: { kind: 'classical', trustedOperators: [await operatorKey()] },
    now: () => NOW_UNIX,
    ...overrides,
  };
}

/** One captured `fetch` invocation made by the gate's `url` verifier. */
export interface VerifierFetchCall {
  url: string;
  /** The POSTed request body, JSON-parsed (the raw string if it is not JSON). */
  body: unknown;
}

export type StubVerifierFetchOptions =
  | { status: number; body: unknown; unreachable?: false | undefined }
  | { unreachable: true };

/**
 * Replace `globalThis.fetch` with a stub for the `url` verifier and return a
 * matching verifier config (the stub stands in for a registry built later).
 *
 * - `{ status, body }`: every call resolves with `body` (JSON-encoded unless
 *   already a string) at `status`.
 * - `{ unreachable: true }`: every call rejects with `ECONNREFUSED`.
 *
 * `calls` records `{ url, body }` for each invocation so a test can assert the
 * POSTed `VerifierRequest` (and, later, `consume_nonces`). The stub stays
 * installed until `restore()` is called: **callers are responsible for calling
 * `restore()`** (e.g. in `finally` or an `after` hook) so the original fetch is
 * put back for subsequent tests in the same process.
 */
export function stubVerifierFetch(options: StubVerifierFetchOptions): {
  verifier: BolyraGateOptions['verifier'];
  calls: VerifierFetchCall[];
  restore: () => void;
} {
  const originalFetch = globalThis.fetch;
  const calls: VerifierFetchCall[] = [];
  const stub: typeof fetch = async (input, init) => {
    const url =
      typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const raw = init?.body;
    let body: unknown = raw;
    if (typeof raw === 'string') {
      try {
        body = JSON.parse(raw);
      } catch {
        body = raw;
      }
    }
    calls.push({ url, body });
    if (options.unreachable === true) throw new Error('ECONNREFUSED');
    const payload = typeof options.body === 'string' ? options.body : JSON.stringify(options.body);
    return new Response(payload, {
      status: options.status,
      headers: { 'content-type': 'application/json' },
    });
  };
  globalThis.fetch = stub;
  return {
    verifier: { kind: 'url', url: 'https://verify.test/v1/verify', token: 'verifier-token' },
    calls,
    restore: () => {
      globalThis.fetch = originalFetch;
    },
  };
}

/** Build the app: one gated method, a counter that only the protected action increments. */
export function buildApp(gated: TestServerMethod) {
  const mppx = Mppx.create({ methods: [gated], realm: REALM, secretKey: SECRET_KEY });
  const state = { counter: 0, lastResultStatus: undefined as number | undefined };
  // The README handler pattern, verbatim: the protected action runs before withReceipt.
  const handler = async (request: Request): Promise<Response> => {
    const result = await mppx.charge({ amount: '25' })(request);
    state.lastResultStatus = result.status; // what mppx told the handler (200 = "proceed")
    if (result.status === 402) return result.challenge;
    state.counter += 1; // the protected side effect
    return result.withReceipt(Response.json({ ok: true }));
  };
  return { mppx, state, handler };
}

/** Mint a Payment credential from a challenge issued by this same instance. */
export async function paymentHeader(mppx: ReturnType<typeof buildApp>['mppx']): Promise<string> {
  const challenge = await mppx.challenge.test.charge({ amount: '25' });
  const credential = Credential.from({ challenge, payload: { token: 'ok' } });
  return Credential.serialize(credential);
}

/**
 * Build a request to the gated route.
 *
 * - `payment`: the `Authorization: Payment ...` header value; omitted when `undefined`.
 * - `bundle` is tri-state: `undefined` (default) sends a valid Bolyra bundle from
 *   `makeBundle()`; `null` sends NO `x-bolyra-authorization` header; a string is
 *   sent as given (e.g. a tampered or expired bundle).
 */
export async function requestWith(opts: { payment?: string; bundle?: string | null }): Promise<Request> {
  const headers: Record<string, string> = {};
  if (opts.payment !== undefined) headers['authorization'] = opts.payment;
  const bundle = opts.bundle === undefined ? await makeBundle() : opts.bundle;
  if (bundle !== null) headers[BOLYRA_AUTHORIZATION_HEADER] = bundle;
  return new Request(ROUTE_URL, { headers });
}

/**
 * `bolyraGate` is identity-on-method for real mppx servers with no cast:
 * `MppxServerMethodLike` declares its hooks with method syntax and carries
 * mppx's optional `realm` / `secretKey` / `credential` / `request` fields.
 */
export const gate = bolyraGate;

export { bolyraGate };
