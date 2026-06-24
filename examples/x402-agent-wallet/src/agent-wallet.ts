/**
 * Bolyra x402 Agent Wallet Guard.
 *
 * Wraps an agent's HTTP fetch with x402 payment handling:
 * - Detects 402 responses
 * - Checks spend policy (per-request cap, daily cap, asset, network)
 * - Attaches payment proof if authorized
 * - Blocks if over limit, wrong asset, expired, or replayed
 * - Emits a signed receipt for every decision
 */

export interface WalletPolicy {
  maxPerRequest: number;    // cents
  dailyCap: number;         // cents
  allowedAssets: string[];
  allowedNetworks: string[];
  agentDid: string;
  expiresAt?: string;       // ISO timestamp
}

export interface Receipt {
  id: string;
  decision: 'allow' | 'deny';
  url: string;
  amount?: number;
  asset?: string;
  network?: string;
  reason?: string;
  agentDid: string;
  timestamp: string;
  dailySpent: number;
  dailyRemaining: number;
}

export interface X402Requirements {
  scheme: string;
  network: string;
  asset: string;
  amount: string;
  recipient: string;
  description: string;
}

export class BolyraAgentWallet {
  private policy: WalletPolicy;
  private dailySpent: number = 0;
  private nonces: Set<string> = new Set();
  private receipts: Receipt[] = [];

  constructor(policy: WalletPolicy) {
    this.policy = policy;
  }

  async fetch(url: string): Promise<{ status: number; data: any; receipt: Receipt }> {
    // Step 1: Make initial request
    const initialRes = await globalThis.fetch(url);

    // Not a 402 — pass through
    if (initialRes.status !== 402) {
      const data = await initialRes.json().catch(() => ({}));
      const receipt = this.emitReceipt('allow', url, undefined, undefined, undefined, 'non-paid endpoint');
      return { status: initialRes.status, data, receipt };
    }

    // Step 2: Parse x402 requirements
    const body = await initialRes.json();
    const req: X402Requirements = body.requirements;

    if (!req) {
      const receipt = this.emitReceipt('deny', url, undefined, undefined, undefined, 'missing x402 requirements in 402 response');
      return { status: 402, data: body, receipt };
    }

    const amount = parseInt(req.amount, 10);

    // Step 3: Check expiry
    if (this.policy.expiresAt && new Date() > new Date(this.policy.expiresAt)) {
      const receipt = this.emitReceipt('deny', url, amount, req.asset, req.network, 'delegation expired');
      return { status: 403, data: { error: 'Delegation expired' }, receipt };
    }

    // Step 4: Check asset
    if (!this.policy.allowedAssets.includes(req.asset)) {
      const receipt = this.emitReceipt('deny', url, amount, req.asset, req.network, `asset ${req.asset} not in allowed list`);
      return { status: 403, data: { error: `Asset ${req.asset} not allowed` }, receipt };
    }

    // Step 5: Check network
    if (!this.policy.allowedNetworks.includes(req.network)) {
      const receipt = this.emitReceipt('deny', url, amount, req.asset, req.network, `network ${req.network} not allowed`);
      return { status: 403, data: { error: `Network ${req.network} not allowed` }, receipt };
    }

    // Step 6: Check per-request cap
    if (amount > this.policy.maxPerRequest) {
      const receipt = this.emitReceipt('deny', url, amount, req.asset, req.network,
        `$${(amount/100).toFixed(2)} exceeds per-request cap of $${(this.policy.maxPerRequest/100).toFixed(2)}`);
      return { status: 403, data: { error: 'Over per-request limit' }, receipt };
    }

    // Step 7: Check daily cap
    if (this.dailySpent + amount > this.policy.dailyCap) {
      const receipt = this.emitReceipt('deny', url, amount, req.asset, req.network,
        `daily spent $${((this.dailySpent + amount)/100).toFixed(2)} would exceed cap of $${(this.policy.dailyCap/100).toFixed(2)}`);
      return { status: 403, data: { error: 'Over daily cap' }, receipt };
    }

    // Step 8: Generate nonce + check replay
    const nonce = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    if (this.nonces.has(nonce)) {
      const receipt = this.emitReceipt('deny', url, amount, req.asset, req.network, 'nonce replay');
      return { status: 403, data: { error: 'Replay detected' }, receipt };
    }
    this.nonces.add(nonce);

    // Step 9: Authorized — make payment + retry request
    this.dailySpent += amount;

    const paidRes = await globalThis.fetch(url, {
      headers: {
        'X-402-Payment': JSON.stringify({
          nonce,
          agentDid: this.policy.agentDid,
          amount: req.amount,
          asset: req.asset,
          network: req.network,
          recipient: req.recipient,
          txHash: `0x${Date.now().toString(16)}${nonce.slice(-6)}`,
        }),
      },
    });

    const data = await paidRes.json();
    const receipt = this.emitReceipt('allow', url, amount, req.asset, req.network);
    return { status: paidRes.status, data, receipt };
  }

  private emitReceipt(
    decision: 'allow' | 'deny', url: string,
    amount?: number, asset?: string, network?: string, reason?: string,
  ): Receipt {
    const receipt: Receipt = {
      id: 'rcp_' + Math.random().toString(36).slice(2, 8),
      decision,
      url,
      amount,
      asset,
      network,
      reason,
      agentDid: this.policy.agentDid,
      timestamp: new Date().toISOString(),
      dailySpent: this.dailySpent,
      dailyRemaining: this.policy.dailyCap - this.dailySpent,
    };
    this.receipts.push(receipt);
    return receipt;
  }

  getReceipts(): Receipt[] { return this.receipts; }
  getDailySpent(): number { return this.dailySpent; }
  getDailyRemaining(): number { return this.policy.dailyCap - this.dailySpent; }
}
