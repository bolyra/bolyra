/**
 * The agent side of one paid call. The discovery request carries a presentation and no
 * payment credential (mppx answers 402 — after the gate ran); the paid retry carries the
 * credential minted from THAT 402 plus a FRESH presentation, because the discovery
 * attempt already reserved the first one's nullifier. Shared by the demo and the tests
 * so they exercise one client, not two.
 */
import { Challenge, Credential } from 'mppx';
import { BOLYRA_AUTHORIZATION_HEADER } from '@bolyra/mpp';
import { AUDIENCE, PAYMENT_TOKEN, chargeMethod } from './server.js';

export const ROUTE = `https://${AUDIENCE}/api/report`;

/** No payment credential yet: the gate runs, then mppx issues the 402 challenge. */
export function discoveryRequest(presentation: string): Request {
  return new Request(ROUTE, { headers: { [BOLYRA_AUTHORIZATION_HEADER]: presentation } });
}

/** Pay the challenge from `challenge402`, presenting `presentation` (which must be fresh). */
export function paidRetryRequest(challenge402: Response, presentation: string): Request {
  const challenge = Challenge.fromResponse(challenge402, { methods: [chargeMethod] });
  const credential = Credential.from({ challenge, payload: { token: PAYMENT_TOKEN } });
  return new Request(ROUTE, {
    headers: { [BOLYRA_AUTHORIZATION_HEADER]: presentation, authorization: Credential.serialize(credential) },
  });
}

/**
 * One paid call end to end: discovery with `first`, then the paid retry with `second`. A
 * denial ends the handshake at the discovery step and that response is returned as is.
 */
export async function paidCall(
  handler: (request: Request) => Promise<Response>,
  first: string,
  second: string,
): Promise<Response> {
  const discovery = await handler(discoveryRequest(first));
  if (discovery.status !== 402) return discovery;
  return handler(paidRetryRequest(discovery, second));
}
