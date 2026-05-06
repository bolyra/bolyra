# Baseline — SPIFFE/SPIRE + WIMSE Workload Identity

The strongest infrastructure-layer baseline for workload (and by extension agent) identity.

## Core

**SPIFFE (Secure Production Identity Framework For Everyone)**
- SPIFFE ID: `spiffe://trust-domain/path`
- SVID (SPIFFE Verifiable Identity Document): X.509 or JWT
- SPIFFE Workload API: local unix socket, workload fetches its own SVID

**SPIRE (SPIFFE Runtime Environment)**
- Server + agent model
- Agent attests node identity (AWS IID, k8s PSAT, Docker label, etc.)
- Server issues SVID to attested workload
- Supports federation across trust domains

**WIMSE (Workload Identity in Multi-System Environments)**
- IETF working group (https://datatracker.ietf.org/wg/wimse/about/)
- draft-ietf-wimse-arch — architecture
- draft-ietf-wimse-s2s-protocol — service-to-service with workload identity
- Scope includes agent-like workloads (including AI agents per recent discussion)

## What SPIFFE/WIMSE can do

1. Strong workload identity: each workload has a short-lived SVID cryptographically tied to node attestation
2. Federation: cross-trust-domain workload-to-workload auth without shared PKI
3. mTLS between workloads via X.509 SVIDs
4. JWT SVIDs for protocol-agnostic transport
5. Workload-to-service auth with minimal configuration

## What SPIFFE/WIMSE does NOT do (today, baseline)

1. **Selective attribute disclosure** — SVID claims are public to any verifier
2. **Issuer-blind proofs** — the trust domain is always visible in the SPIFFE ID
3. **Cross-scope unlinkability** — the SPIFFE ID is a stable identifier; cross-service correlation is trivial
4. **ZK predicate proofs over credentials** — out of scope
5. **Human-in-the-loop mutual authentication** — SPIFFE is workload-only; no human identity primitive
6. **Forward secrecy for prior workload sessions** — SVIDs are short-lived but not forward-secure; compromise of workload key exposes recent sessions

## Where SPIFFE and Bolyra could compose

SPIFFE handles node/workload attestation. Bolyra handles privacy properties on top of that identity. A Bolyra credential could commit to a SPIFFE ID as one of its private claims; the workload uses SPIFFE for transport auth and Bolyra for privacy-preserving predicates. This is not a competition point — it's a layering opportunity that a strong construction should acknowledge.

## Sources

- SPIFFE: https://spiffe.io/
- SPIRE: https://github.com/spiffe/spire
- WIMSE WG: https://datatracker.ietf.org/wg/wimse/about/
- draft-ietf-wimse-arch: https://datatracker.ietf.org/doc/draft-ietf-wimse-arch/
