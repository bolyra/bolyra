# Autonomous Agent Identity Demo

Full lifecycle of an autonomous agent with Bolyra identity, spend policy, and verifiable receipts.

Agents own keys and hold balances. Bolyra proves what they're allowed to do with them.

## What This Shows

| Phase | What happens |
|-------|-------------|
| 1. PROVISION | Agent generates keypair, human issues credential with permissions + spend limits + expiry |
| 2. OPERATE | Agent autonomously calls paid APIs through policy gateway (8 scenarios) |
| 3. AUDIT | Every decision has a signed receipt — saved to disk for replay |
| 4. REVOKE | Expired credential rejected — human controls the lifecycle |

### Scenarios

| # | Action | Amount | Permission | Result |
|---|--------|--------|-----------|--------|
| 1 | Read market data | $0.25 | READ_DATA | Allowed |
| 2 | Buy research report | $1.50 | FINANCIAL_SMALL | Allowed |
| 3 | GPU inference | $1.00 | FINANCIAL_SMALL | Allowed |
| 4 | Premium data | $3.00 | FINANCIAL_SMALL | **Denied** (per-request cap) |
| 5 | Wire transfer | $50.00 | FINANCIAL_MEDIUM | **Denied** (missing permission) |
| 6 | Read analytics | $0.50 | READ_DATA | Allowed |
| 7 | Buy dataset | $2.00 | FINANCIAL_SMALL | **Denied** (daily cap) |
| 8 | Pay on Ethereum | $0.50 | FINANCIAL_SMALL | **Denied** (wrong network) |
| 9 | Read (expired) | $0.25 | READ_DATA | **Denied** (credential expired) |

## Quick Start

```bash
cd examples/autonomous-agent
npm install
npm run demo
```

## How It Works

```
Human issues credential to agent
    │ permissions: READ_DATA + WRITE_DATA + FINANCIAL_SMALL
    │ limits: $2.00/request, $5.00/day, USDC, base-sepolia
    │ expiry: 24 hours
    ▼
Agent owns keypair + credential
    │
    │ Agent autonomously calls paid API
    ▼
Bolyra Policy Gateway evaluates
    │ 1. Credential valid? (signature, expiry)
    │ 2. Permission granted? (bitmask check)
    │ 3. Asset/network allowed?
    │ 4. Under spend cap? (per-request + daily)
    │ 5. Nonce fresh? (replay protection)
    ▼
Decision: ALLOW or DENY
    │
    ▼
Signed receipt emitted
    { decision, agentDid, action, amount, reason, nonce, signature }
    │
    ▼
Receipts saved to disk → replayable + verifiable
```

## Links

- [Bolyra Playground](https://bolyra.ai/playground)
- [x402 Agent Wallet Example](../x402-agent-wallet/)
- [@bolyra/gateway](https://www.npmjs.com/package/@bolyra/gateway)
