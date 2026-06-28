# Theseus Network — What We Know

## Overview

- **Tagline:** "Agency for Agents" — an L1 chain purpose-built for autonomous AI agents
- **Core thesis:** Agents hold their own keys, manage their own balances, persist on-chain, and have verifiable AI execution
- **Key architectural constraint:** No human-controlled key path. Agents are first-class citizens, not proxies for humans.

## Company

- **Founded:** 2025
- **Funding:** $100K from Orange DAO (Y Combinator alumni DAO)
- **HQ:** Las Vegas, NV
- **Team lead:** Eric Wang (appears to be founder/lead)
- **Website:** theseuschain.com

## Timeline

- **Call booked:** Sunday, June 29, 2026

## Why This Matters for Bolyra

Theseus's "no human key path" constraint is structurally novel. Most identity systems (including Bolyra's current architecture) assume a human root of trust. Theseus needs identity and authorization primitives designed for agent-rooted trust chains — a gap Bolyra is uniquely positioned to fill given its ZKP delegation circuits and 8-bit permission model.

## Open Questions

- What is Theseus's current identity/auth approach? (likely raw EdDSA keypairs)
- How do they handle agent-to-agent delegation today?
- What's their timeline to mainnet?
- How many agents are they targeting at launch?
- What's the on-chain execution environment? (EVM-compatible? Custom VM?)
- How do they define "verifiable AI execution" — attestation? TEE? ZKP?
