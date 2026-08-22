# x402 EVC Authorization-Evidence Profile — demo

The smallest runnable form of `spec/x402-evc-profile-v0.md`: an x402 resource
server checks **who authorized this spend** (gate 1, authorization evidence)
before its payment logic runs. Payment settlement and payee risk (gate 2) are
deliberately out of frame.

| Step | Request | Outcome |
|---|---|---|
| 1 | $25 with a small-tier mandate | **ALLOW** (HTTP 200) |
| 2 | $500 with the same mandate | **DENY** 403, RFC 9457 `problem+json` |
| 3 | $25 replaying step 1's challenge nonce | **DENY** 403 `nonce_replayed` |

```
operator ──issueMandate──▶ bvp/1 presentation
                              │  x-bolyra-authorization
agent ──x402 retry──▶ resource server
                              │  build EVC §2.1 request (+ x402_evc extension)
                              ▼
                    verifier (classical | command | url)
                              │  allow / deny (fail-closed)
                              ▼
              RFC 9457 denial  ·or·  payment logic proceeds
```

## Quick start

```bash
npm install
npm run demo
```

No signup, no chain access, no ZK artifacts — the classical verifier runs
in-process. The mandate's EdDSA-Poseidon binding signature over
`{agent_name, project_key, program, model, capabilities, expiry}` is the
load-bearing fact; the profile binds the x402 context
(`resource`/`amount`/`nonce`/`expires_at`/verifier identity) alongside it.
