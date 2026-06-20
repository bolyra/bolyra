/**
 * Simulated Stripe PaymentIntent — no real Stripe SDK, no network calls.
 * Clearly labeled as simulated in all output.
 */

import * as crypto from 'crypto';

export interface SimulatedPaymentIntent {
  id: string;
  amount: number;
  currency: string;
  status: 'requires_confirmation' | 'succeeded';
  metadata: {
    bolyra_acting_did: string;
    bolyra_root_did: string;
    bolyra_receipt_id: string;
  };
}

export function simulatePaymentIntent(
  amount: number,
  currency: string,
  actingDid: string,
  rootDid: string,
  receiptId: string,
): SimulatedPaymentIntent {
  const hex = crypto.randomBytes(8).toString('hex');
  return {
    id: `pi_test_${hex}`,
    amount,
    currency,
    status: 'requires_confirmation',
    metadata: {
      bolyra_acting_did: actingDid,
      bolyra_root_did: rootDid,
      bolyra_receipt_id: receiptId,
    },
  };
}
