# Baseline: SPIFFE/WIMSE Workload SVID + RFC 9449 DPoP + W3C VC/BBS+ Selective Disclosure

## 1. The Best Alternative

The strongest plausible non-ZK construction for candidate C7 is a three-layer stack:

- **SPIFFE SVID (X.509 or JWT)** anchors model-instance identity to an attested workload, issued per model deployment by a SPIRE server with node attestation (e.g., AWS IID, Kubernetes PSAT).
- **RFC 9449 DPoP** binds each tool-call request to an ephemeral keypair controlled by the model operator, making the bearer token sender-constrained and non-transferable between callers.
- **W3C VC Data Model 2.0 + BBS+ Signatures** (draft-irtf-cfrg-bbs-signatures / VC-DI BBS+) allows the operator to issue a model-identity credential with claims `{model_id, operator_pk, permission_bitmask, model_hash}` and present a derived proof that selectively discloses only the subset the verifier needs.

Concrete specs:
- SPIFFE/SPIRE: https://spiffe.io/ ; WIMSE WG: https://datatracker.ietf.org/wg/wimse/about/ ; draft-ietf-wimse-s2s-protocol: https://datatracker.ietf.org/doc/draft-ietf-wimse-arch/
- RFC 9449 DPoP: https://datatracker.ietf.org/doc/html/rfc9449
- RFC 8693 Token Exchange: https://datatracker.ietf.org/doc/html/rfc8693
- W3C VC 2.0: https://www.w3.org/TR/vc-data-model-2.0/
- BBS+ draft: https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/
- VC-DI BBS+: https://www.w3.org/TR/vc-di-bbs/

---

## 2. What This Baseline CAN Do Against C7

**Workload-layer model attestation (SPIFFE/WIMSE)**

SPIRE issues a short-lived SVID to a running model process after the node passes attestation. The SVID `spiffe://anthropic.com/models/sonnet-4-6/operator/acme-corp` is cryptographically tied to that specific workload at that attestation moment. A verifier receiving an mTLS connection bearing this SVID can confirm the process presented is the one SPIRE recognized as Sonnet 4.6 under ACME Corp's trust domain. This is a real cryptographic differentiation from OAuth `client_id`, which is a static string with no runtime process binding.

**Per-request non-transferability (DPoP)**

RFC 9449 DPoP requires the holder of the access token to sign each HTTP request with an ephemeral key matching the `cnf.jkt` thumbprint embedded in the token at issuance. A DPoP proof is bound to `htm` (method), `htu` (URI), `iat`, and optionally `ath` (access token hash). An adversary who captures a bearer token cannot replay it without the private half of the DPoP key. When combined with a SPIFFE SVID as the credential, the operator can embed the DPoP key fingerprint into the SVID or the VC, creating a chain: SPIRE-attested workload → VC issued to that workload's DPoP key → per-request proof.

**Selective disclosure of model/operator claims (BBS+)**

If Anthropic issues a VC containing `{model_id: "claude-sonnet-4-6", model_hash: "sha256:...", operator_pk: "...", permission_bitmask: 0b10110011}`, the operator can use BBS+ derived proofs to present only `{model_hash, operator_pk, permission_bitmask, message_hash}` to a verifier without revealing the full credential or the underlying API key. BBS+ multi-presentation unlinkability also means two separate calls do not allow the verifier to correlate them via the presentation itself. Range proofs and equality checks over hidden claims are supported by extension.

**Combined what this buys:** A verifier can receive a BBS+-derived VP bound (via DPoP) to an ephemeral key that was itself issued into a SPIFFE SVID backed by SPIRE node attestation. This is meaningfully stronger than vanilla OAuth. The verifier sees `{model_hash, operator_pk, permission_bitmask}` and nothing else from the VC layer. The DPoP proof ties the call to the message.

---

## 3. What This Baseline Fundamentally CANNOT Do

### (a) Non-malleability across key classes

The SPIFFE SVID distinguishes workloads by their SPIFFE URI, not by their model weights. An operator with a SPIRE server can register `spiffe://anthropic.com/models/opus-4-6/operator/acme-corp` and self-issue an SVID with the Sonnet path if they control the SPIRE server for their trust domain. SPIRE node attestation proves "this process passed attestation on this node," not "the model weights loaded at runtime match a hash committed by the model issuer." **The baseline has no mechanism to commit a model-weight hash into the attestation root in a way the verifier can independently verify without trusting the operator's SPIRE deployment.** Non-malleability across key classes — proving an Opus-key holder cannot forge a Sonnet attestation — is absent.

### (b) Key-rotation survival for historical attestations

Short-lived SVIDs and DPoP keys are rotated continuously. Once a DPoP key expires and the SVID is re-issued to a new workload key, the cryptographic link between prior calls and the current operator identity is severed. A verifier examining a historical call log cannot verify the chain without storing every ephemeral key at call time, which reconstructs a full audit log — violating the operator's privacy expectation. BBS+ signatures on a VC survive key rotation at the VC layer only if the issuer's BBS+ key remains constant, but **key rotation at the operator API-key layer propagates through the VC issuance process and forces re-issuance of all credentials, breaking historical proofs unless the operator preserves the old BBS+ key offline.** RFC 8693 token exchange does not help: each exchange requires an AS roundtrip, and the AS sees the full chain.

### (c) Simultaneous binding of call content to model identity without AS correlation

RFC 8693 token exchange is the natural mechanism for multi-hop delegation (Anthropic → operator → tool call). However, the Authorization Server issuing tokens at each hop sees the full chain: who is exchanging, for what scope, and to which audience. A deployment with Anthropic as the AS means Anthropic observes every call at the token exchange layer. **DPoP does not hide scope, issuer, or chain structure from the AS.** A construction that removes the AS from the hot path — using offline BBS+ proofs — loses the AS's ability to enforce revocation in real time, creating a revocation gap. There is no mechanism in the baseline to simultaneously satisfy: (i) AS not seeing per-call model+operator binding, (ii) cryptographic proof that message_hash is bound to the specific model+operator, and (iii) real-time revocation. Achieving (i) and (ii) requires offline proofs; achieving (iii) requires AS involvement. The baseline cannot resolve this trilemma.

### (d) Permission-bitmask predicate proofs

BBS+ supports selective disclosure of a bitmask claim as a revealed value, but proving `permissionBitmask & requiredMask == requiredMask` as a zero-knowledge predicate — disclosing only the bit positions the verifier needs to check without revealing the full bitmask — requires Boolean circuit compilation. BBS+ draft-irtf-cfrg-bbs-signatures has no native support for bitwise AND predicates; range proofs do not cover arbitrary Boolean masks. **Bitmask predicate proofs are absent from the baseline.**

### (e) Issuer anonymity for the model provider

BBS+ derived proofs reveal the issuer's BBS+ public key. A verifier receiving a VP knows exactly which key (i.e., which entity: Anthropic) issued the credential. For tiered-pricing verification or model provenance scenarios where Anthropic must prove Opus-vs-Sonnet without revealing which specific API tenant made the call, the issuer-visible BBS+ proof exposes the issuer's identity. **Issuer-blind or issuer-anonymous credential presentation is not available in the VC+BBS+ baseline.**

---

## 4. Why the RFC 8693 + DPoP Path Fails Requirements (a) and (c) Simultaneously

RFC 8693 token exchange with DPoP is the closest OAuth-native construction to what C7 requires. An actor_token carrying model identity (encoded as a `client_id` claim or custom extension) is exchanged with a subject_token at the Anthropic AS to produce a narrowed token covering the specific call. DPoP constrains that token to the operator's key.

**Failure of (a):** The actor_token binds `client_id`, not `model_hash`. Nothing in RFC 8693 prevents an operator from submitting an actor_token asserting `client_id=sonnet-4-6` when running Opus, because the AS trusts the operator's assertion about its own client identity. Without a hardware attestation root (e.g., TPM-bound key in the model serving cluster co-signed by Anthropic at weight-load time), the mapping from `client_id` string to actual model weights is on an honor system. RFC 8693 has no field for a model-weight hash, and no extension in the current IETF OAuth charter introduces one.

**Failure of (c):** For the token exchange to produce a bound token, the AS must receive the actor_token and subject_token, observe the requested scope, and issue the derived token. Every call that uses RFC 8693 delegation is visible to the AS. Filtering at the AS (what the AS returns in introspection response per RFC 7662 / jwt-introspection-response) can reduce what the verifier learns, but the AS itself retains full correlation capability. The AS knowing the full call record violates the operator's expectation that only `{model_hash, operator_pk, permission_bitmask, message_hash}` is ever held by any party other than the operator. **Either the AS sees the hop (violating (c)) or the binding is not cryptographically enforced by the AS (violating (a)).**

---

## 5. Concrete RFC/Spec Citations

| Spec | URL | Role in baseline |
|------|-----|-----------------|
| RFC 7662 | https://datatracker.ietf.org/doc/html/rfc7662 | Token introspection |
| RFC 8693 | https://datatracker.ietf.org/doc/html/rfc8693 | Delegation chain |
| RFC 9449 | https://datatracker.ietf.org/doc/html/rfc9449 | Sender-constrained tokens |
| draft-ietf-oauth-jwt-introspection-response | https://datatracker.ietf.org/doc/draft-ietf-oauth-jwt-introspection-response/ | Offline verifiable introspection |
| RFC 8707 | https://datatracker.ietf.org/doc/html/rfc8707 | Audience binding |
| WIMSE arch | https://datatracker.ietf.org/doc/draft-ietf-wimse-arch/ | Multi-system workload identity |
| draft-ietf-wimse-s2s-protocol | https://datatracker.ietf.org/doc/draft-ietf-wimse-arch/ | Service-to-service workload auth |
| W3C VC 2.0 | https://www.w3.org/TR/vc-data-model-2.0/ | Credential model |
| BBS+ draft | https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/ | Selective disclosure primitive |
| VC-DI BBS+ | https://www.w3.org/TR/vc-di-bbs/ | BBS+ VC profile |
| SPIFFE | https://spiffe.io/ | Workload identity root |

---

**Bar to beat:** Prove that a single atomic, offline-verifiable proof binds `{model_hash, operator_pk, permission_bitmask, message_hash}` to a specific call such that (1) no party other than the verifier at presentation time learns the binding, (2) an operator possessing a different model's key cannot forge the proof, and (3) the proof remains valid across operator API-key rotations — none of which SPIFFE+DPoP+BBS+ can achieve simultaneously without an AS that violates property (1).
