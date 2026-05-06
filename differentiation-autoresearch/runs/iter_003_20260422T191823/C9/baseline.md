# Baseline — RFC 9449 DPoP + RFC 8693 Token Exchange + WIMSE Short-Lived SVIDs

## Strongest Non-ZK Candidate for Forward-Secure Agent Delegation

The best available non-ZK construction combines three orthogonal mitigations:

1. **RFC 9449 DPoP** with aggressive key rotation (daily or per-session ephemeral keypairs)
2. **RFC 8693 Token Exchange** for scoped delegation chains with short-lived tokens
3. **WIMSE draft-ietf-wimse-s2s-protocol** with sub-hour SVID lifetimes, replacing long-lived SVIDs with attestation-fresh identities

No single spec covers forward secrecy for agent identity. This combination represents the ceiling of what OAuth-era tooling plus WIMSE can achieve before ZK becomes necessary.

---

## What This Baseline CAN Do

### Key Rotation as a Forward-Secrecy Proxy

RFC 9449 (https://datatracker.ietf.org/doc/html/rfc9449) binds each access token to a specific keypair via a `DPoP` proof JWT signed per-request. If the agent generates a **new DPoP keypair per epoch** (e.g., per day or per task boundary), then compromise of the current epoch key does not expose DPoP proofs signed under prior keypairs — provided the prior private keys were deleted. This is not cryptographic forward secrecy; it is operational key hygiene masquerading as forward secrecy. The distinction matters: the guarantee is only as strong as the deletion guarantee.

### Short-Lived Token Windows

RFC 8693 token exchange (https://datatracker.ietf.org/doc/html/rfc8693) supports issuing narrow-scoped, short-lifetime delegation tokens. Combined with RFC 8707 resource indicators (https://datatracker.ietf.org/doc/html/rfc8707), each token is audience-bound and expires quickly. An attacker who obtains a key at time T finds only tokens valid within the last short window — not a 30-day activity graph — if the AS issues tokens with `exp` set aggressively (e.g., 5-minute lifetime).

### WIMSE Workload Attestation with Ephemeral SVIDs

WIMSE (https://datatracker.ietf.org/wg/wimse/about/, draft-ietf-wimse-s2s-protocol) supports workload-to-workload authentication with X.509 SVIDs that carry a short `notAfter`. If SPIRE re-attests and re-issues SVIDs every 15 minutes, the effective window of exposure per compromised SVID is bounded. The WIMSE architecture spec (draft-ietf-wimse-arch) explicitly discusses agent-like workloads and acknowledges the need for short rotation cycles.

### Transport-Layer Forward Secrecy

TLS 1.3 (RFC 8446, https://datatracker.ietf.org/doc/html/rfc8446) provides forward secrecy at the session layer via ephemeral ECDH key agreement. Compromise of the TLS certificate private key does not retroactively decrypt prior TLS sessions. This is real, cryptographically grounded forward secrecy — but it operates at the transport layer only, protecting confidentiality of the wire bytes, not the application-layer agent identity or activity metadata.

### What the Combination Achieves

A well-configured deployment can:

- Bound the token-validity window to minutes, limiting replay scope
- Isolate DPoP proof liability to a single epoch if keys are deleted on rotation
- Protect wire-level confidentiality of prior sessions via TLS 1.3
- Prevent cross-RS activity correlation at the token level via RFC 8707 audience binding and OIDC PPIDs
- Force AS-mediated delegation that restricts scope per hop (RFC 8693)

---

## What This Baseline Fundamentally CANNOT Do

### 1. Cryptographic Forward Secrecy at Application Layer

TLS 1.3's forward secrecy does not protect application-layer identifiers. The DPoP `jkt` thumbprint, the SVID SPIFFE ID, and every `sub` claim issued by the AS are **durable identifiers tied to a long-term keypair or a stable identity**. When an adversary obtains the agent's DPoP keypair, they can reconstruct every DPoP proof the agent ever signed — the proof body includes `htu`, `htm`, `iat`, and `ath` (access token hash), forming a timestamped activity log. RFC 9449 Section 11.1 explicitly acknowledges this: "DPoP does not prevent an attacker who has obtained the private key from forging new proofs or from linking existing proofs." Key compromise retroactively reveals the complete activity graph.

### 2. Unlinkability of Prior Sessions After Key Compromise

DPoP proofs are signed with the agent's keypair. An adversary holding the private key can verify every prior proof against every prior token. The `ath` field links each DPoP proof to a specific access token; the `jti` prevents replay but does not hide the proof. The baseline has no mechanism to make pre-T proofs cryptographically unlinkable once the signing key is known. There is no construction in RFC 9449, RFC 8693, RFC 8707, or WIMSE that provides post-compromise unlinkability of prior-signed assertions.

### 3. Non-Replayability Guarantees After Key Compromise

RFC 9449 Section 8 specifies that `jti` uniqueness prevents replay of a given DPoP proof only at the RS/AS that has seen it. An adversary with the private key can **generate new valid DPoP proofs** that replay the same `htu`/`htm`/`ath` pattern. Token Exchange (RFC 8693) tokens are AS-issued and short-lived, but the delegation chain metadata visible to the AS is durable — the AS logged every exchange, and that log is not forward-secure.

### 4. IND-FS-AGENT Security in the Formal Sense

No RFC or IETF draft defines a security game equivalent to IND-FS-AGENT. The closest formal treatment in the OAuth space is the DPoP security analysis in RFC 9449 Appendix B, which covers sender-constraint but not forward secrecy. The WIMSE threat model (draft-ietf-wimse-arch Section 7) lists "compromise of workload credentials" as an in-scope threat but defers the response to short rotation periods — a quantitative bound, not a cryptographic one. The baseline cannot produce a proof that an adversary with the key at time T has negligible advantage in linking pre-T sessions.

### 5. Epoch-Isolated Nullifiers

The baseline has no nullifier mechanism. There is no construction in DPoP, SVID, or Token Exchange that produces a per-session commitment that is unlinkable across epochs yet still verifiable as non-replayed. The closest analog is the DPoP `jti` (a random nonce), but this is bound to the key that signed it — nullifiers must be verifiable without revealing the key, which is not possible in the non-ZK baseline.

### 6. Key Rotation ≠ Forward Secrecy

Operational key rotation (deleting old DPoP private keys after epoch boundary) reduces exposure only if deletion is guaranteed. It provides no cryptographic proof of deletion to any relying party. An auditor, regulator, or adversary with access to the AS logs, the token endpoint logs, or the `jkt` thumbprint history can reconstruct the agent's identity continuity across rotations. RFC 9449 provides no mechanism to prove that a current keypair is unrelated to a prior keypair. WIMSE SPIFFE IDs are explicitly designed to be stable identifiers — SPIRE reissues the same SVID path on rotation.

---

## Sources

- RFC 9449 DPoP: https://datatracker.ietf.org/doc/html/rfc9449
- RFC 8693 Token Exchange: https://datatracker.ietf.org/doc/html/rfc8693
- RFC 8707 Resource Indicators: https://datatracker.ietf.org/doc/html/rfc8707
- RFC 7662 Token Introspection: https://datatracker.ietf.org/doc/html/rfc7662
- RFC 8446 TLS 1.3: https://datatracker.ietf.org/doc/html/rfc8446
- WIMSE WG: https://datatracker.ietf.org/wg/wimse/about/
- draft-ietf-wimse-arch: https://datatracker.ietf.org/doc/draft-ietf-wimse-arch/
- draft-ietf-wimse-s2s-protocol: https://datatracker.ietf.org/doc/draft-ietf-wimse-s2s-protocol/
- SPIFFE: https://spiffe.io/
- SPIRE: https://github.com/spiffe/spire

---

**Bar to beat:** Any Bolyra forward-secrecy construction must produce a cryptographic proof — not an operational policy — that an adversary holding the agent's signing key at time T has negligible advantage in linking, replaying, or reconstructing any session executed before T, a guarantee that RFC 9449 + RFC 8693 + WIMSE cannot provide by design.
