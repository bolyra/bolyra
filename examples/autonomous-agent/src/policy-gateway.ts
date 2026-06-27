/**
 * Bolyra Policy Gateway
 *
 * Sits between an autonomous agent and x402 paid APIs.
 * For every request, the gateway:
 * 1. Verifies the agent's credential (signature, expiry)
 * 2. Checks permission bitmask against the requested action
 * 3. Enforces spend limits (per-request, daily cap)
 * 4. Checks replay protection (nonce uniqueness)
 * 5. Emits a signed receipt for every decision (allow or deny)
 *
 * Receipts are the audit trail: which agent acted, under what
 * authority, for what amount, and why it was allowed or denied.
 */

import * as crypto from 'crypto';
import {
  AgentCredential, verifyCredential, hasPermission, PERMISSIONS,
} from './agent-identity';

export interface GatewayReceipt {
  id: string;
  type: 'BolyraSignedReceipt';
  version: '0.7.0';
  decision: 'allow' | 'deny';
  agentDid: string;
  action: string;
  amount?: number;
  asset?: string;
  network?: string;
  permissionRequired: string;
  permissionGranted: boolean;
  reason?: string;
  timestamp: string;
  dailySpent: number;
  dailyRemaining: number;
  nonce: string;
  signature: string;
}

export interface GatewayResult {
  allowed: boolean;
  receipt: GatewayReceipt;
}

export class PolicyGateway {
  private nonces: Set<string> = new Set();
  private dailySpent: Map<string, number> = new Map(); // agentDid -> cents
  private receipts: GatewayReceipt[] = [];

  /**
   * Evaluate whether an agent is authorized to perform an action.
   */
  evaluate(
    credential: AgentCredential,
    action: string,
    requiredPermission: keyof typeof PERMISSIONS,
    amount?: number,        // cents
    asset?: string,
    network?: string,
  ): GatewayResult {
    const nonce = `${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    const spent = this.dailySpent.get(credential.agentDid) ?? 0;

    // Step 1: Verify credential
    const credCheck = verifyCredential(credential);
    if (!credCheck.valid) {
      return this.emit('deny', credential, action, requiredPermission, false,
        nonce, spent, amount, asset, network, credCheck.reason);
    }

    // Step 2: Check permission bitmask
    if (!hasPermission(credential.permissionBitmask, requiredPermission)) {
      return this.emit('deny', credential, action, requiredPermission, false,
        nonce, spent, amount, asset, network,
        `missing permission: ${requiredPermission} (bitmask: 0x${credential.permissionBitmask.toString(16).padStart(2, '0')})`);
    }

    // Step 3: Check asset allowlist
    if (asset && !credential.allowedAssets.includes(asset)) {
      return this.emit('deny', credential, action, requiredPermission, true,
        nonce, spent, amount, asset, network, `asset ${asset} not allowed`);
    }

    // Step 4: Check network allowlist
    if (network && !credential.allowedNetworks.includes(network)) {
      return this.emit('deny', credential, action, requiredPermission, true,
        nonce, spent, amount, asset, network, `network ${network} not allowed`);
    }

    // Step 5: Check per-request cap
    if (amount !== undefined && amount > credential.maxPerRequest) {
      return this.emit('deny', credential, action, requiredPermission, true,
        nonce, spent, amount, asset, network,
        `$${(amount/100).toFixed(2)} exceeds per-request cap $${(credential.maxPerRequest/100).toFixed(2)}`);
    }

    // Step 6: Check daily cap
    if (amount !== undefined && spent + amount > credential.dailyCap) {
      return this.emit('deny', credential, action, requiredPermission, true,
        nonce, spent, amount, asset, network,
        `daily total $${((spent + amount)/100).toFixed(2)} would exceed cap $${(credential.dailyCap/100).toFixed(2)}`);
    }

    // Step 7: Replay protection
    if (this.nonces.has(nonce)) {
      return this.emit('deny', credential, action, requiredPermission, true,
        nonce, spent, amount, asset, network, 'nonce replay detected');
    }
    this.nonces.add(nonce);

    // Step 8: Authorized — update daily spend
    if (amount !== undefined) {
      this.dailySpent.set(credential.agentDid, spent + amount);
    }

    return this.emit('allow', credential, action, requiredPermission, true,
      nonce, spent + (amount ?? 0), amount, asset, network);
  }

  private emit(
    decision: 'allow' | 'deny',
    credential: AgentCredential,
    action: string,
    requiredPermission: string,
    permissionGranted: boolean,
    nonce: string,
    dailySpent: number,
    amount?: number,
    asset?: string,
    network?: string,
    reason?: string,
  ): GatewayResult {
    const receiptData = `${decision}|${credential.agentDid}|${action}|${amount}|${nonce}`;
    const signature = crypto.createHmac('sha256', 'gateway-signing-key')
      .update(receiptData).digest('hex');

    const receipt: GatewayReceipt = {
      id: `rcp_${crypto.randomBytes(4).toString('hex')}`,
      type: 'BolyraSignedReceipt',
      version: '0.7.0',
      decision,
      agentDid: credential.agentDid,
      action,
      amount,
      asset,
      network,
      permissionRequired: requiredPermission,
      permissionGranted,
      reason,
      timestamp: new Date().toISOString(),
      dailySpent,
      dailyRemaining: credential.dailyCap - dailySpent,
      nonce,
      signature,
    };

    this.receipts.push(receipt);
    return { allowed: decision === 'allow', receipt };
  }

  getReceipts(): GatewayReceipt[] { return this.receipts; }
  getReceiptsForAgent(agentDid: string): GatewayReceipt[] {
    return this.receipts.filter(r => r.agentDid === agentDid);
  }
}
