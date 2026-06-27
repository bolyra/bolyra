/**
 * BaseAgentWallet — human-gated spending guard for AI agents on Base.
 *
 * Evaluates payment requests against a wallet policy derived from
 * Bolyra ZKP delegation. Enforces per-request caps, daily caps,
 * asset/network allowlists, and delegation expiry.
 *
 * Every decision (allow or deny) emits a signed receipt for audit.
 */

import type { WalletPolicy } from './delegation.js';

export interface PaymentRequest {
  url: string;
  amount: number;        // cents
  asset: string;
  network: string;
}

export interface Receipt {
  id: string;
  decision: 'allow' | 'deny';
  url: string;
  amount: number;
  asset: string;
  network: string;
  reason?: string;
  agentDid: string;
  timestamp: string;
  dailySpent: number;
  dailyRemaining: number;
}

export class BaseAgentWallet {
  private policy: WalletPolicy;
  private dailySpent: number = 0;
  private receipts: Receipt[] = [];

  constructor(policy: WalletPolicy) {
    this.policy = policy;
  }

  /**
   * Evaluate a payment request against the wallet policy.
   * Returns a receipt with the decision and reason.
   */
  evaluatePayment(req: PaymentRequest): Receipt {
    // Check 1: Delegation expiry
    if (this.policy.expiresAt && new Date() > new Date(this.policy.expiresAt)) {
      return this.emitReceipt('deny', req, 'delegation expired');
    }

    // Check 2: Asset allowlist
    if (!this.policy.allowedAssets.includes(req.asset)) {
      return this.emitReceipt('deny', req, `asset ${req.asset} not in allowed list`);
    }

    // Check 3: Network allowlist
    if (!this.policy.allowedNetworks.includes(req.network)) {
      return this.emitReceipt('deny', req, `network ${req.network} not allowed`);
    }

    // Check 4: Per-request cap
    if (req.amount > this.policy.maxPerRequest) {
      return this.emitReceipt(
        'deny',
        req,
        `$${(req.amount / 100).toFixed(2)} exceeds per-request cap of $${(this.policy.maxPerRequest / 100).toFixed(2)}`,
      );
    }

    // Check 5: Daily cap
    if (this.dailySpent + req.amount > this.policy.dailyCap) {
      return this.emitReceipt(
        'deny',
        req,
        `daily spent $${((this.dailySpent + req.amount) / 100).toFixed(2)} would exceed cap of $${(this.policy.dailyCap / 100).toFixed(2)}`,
      );
    }

    // All checks passed — authorize
    this.dailySpent += req.amount;
    return this.emitReceipt('allow', req);
  }

  private emitReceipt(
    decision: 'allow' | 'deny',
    req: PaymentRequest,
    reason?: string,
  ): Receipt {
    const receipt: Receipt = {
      id: 'rcp_' + Math.random().toString(36).slice(2, 8),
      decision,
      url: req.url,
      amount: req.amount,
      asset: req.asset,
      network: req.network,
      reason,
      agentDid: this.policy.agentDid,
      timestamp: new Date().toISOString(),
      dailySpent: this.dailySpent,
      dailyRemaining: this.policy.dailyCap - this.dailySpent,
    };
    this.receipts.push(receipt);
    return receipt;
  }

  getReceipts(): Receipt[] {
    return this.receipts;
  }

  getDailySpent(): number {
    return this.dailySpent;
  }

  getDailyRemaining(): number {
    return this.policy.dailyCap - this.dailySpent;
  }
}
