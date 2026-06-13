# Bolyra Prospect Walkthrough

One command shows the full Bolyra flow: identity creation, MCP auth,
tool policy enforcement, signed receipts, and commerce authorization.

## Run

```
npm install && npm start
```

## What You're Seeing

1. **Identity** -- dev-mode human + agent identities created instantly
2. **Auth** -- MCP verification with proof bundle (dev mode, mock ZKP)
3. **Policy** -- per-tool permission gating (allowed vs denied)
4. **Receipt** -- signed verification receipt (secp256k1, EVM-compatible)
5. **Commerce** -- payment authorization with spend cap enforcement
