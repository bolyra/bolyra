Base-Commit: 9bf754441ab36ab93992ed5936d34c44a4128f92
Target-File: spec/external-verifier-contract-v1.md
Finding: competing-spec-author-action-instance-unbound-extension-fields-ignored

```diff
--- a/spec/external-verifier-contract-v1.md
+++ b/spec/external-verifier-contract-v1.md
@@ -99,6 +99,66 @@
 A request that is not a JSON object, is missing a **REQUIRED** field, or has a
 field of the wrong type **MUST** yield `deny code=malformed_input` (§4). A
 well-formed request whose `version` is not `1` **MUST** yield
 `deny code=unsupported_version`.
 
+### 2.1.1 What the verdict decides; extension fields
+
+**The verdict is a capability-class admission, not an action-instance
+authorization.** A verifier decides whether the bundle authorizes the principal
+identified by `agent_name`, `project_key`, `program`, and `model` to exercise
+every token in `granted_capabilities`, evaluated at `now_unix`. Those five
+`request` fields are the only request context this contract compares against
+the bundle, and — together with the binding's `expiry` — the only request
+context the binding signature covers (§4.1). No other request content (a tool
+name, a target, an amount, an argument digest) is signed, compared, or
+evaluated by this contract. A host that needs the decision to cover a specific
+action instance **MUST** fold the instance-identifying material into a
+capability token (see the informative note at the end of this section) so that
+it travels inside `granted_capabilities`, is covered by the signed
+`capabilities` array, and is subject to the §9 `request_mismatch` and
+`unknown_capability` checks. A host **MUST NOT** treat an `allow` as
+authorization of any action detail that was not so folded.
+
+**Extension fields are not authorization inputs.** The §2.2 schema declares
+`additionalProperties: true` on both the envelope and the inner `request`
+object. That is a forward-compatibility affordance for verifier vendors and
+future revisions of this contract; it is **not** a channel through which a host
+adds inputs to the decision. Any envelope or `request` member this document
+does not define is an **extension field**, and the following rules apply:
+
+- A verifier **MAY** ignore any extension field. Because the field is
+  schema-valid, a verifier **MUST NOT** classify the request as
+  `malformed_input` solely because an extension field is present.
+- A host **MUST NOT** infer from an `allow` that any extension field it sent was
+  read, validated, matched against the bundle, or bound by any signature. An
+  `allow` means exactly what the preceding paragraph states, whatever else the
+  request carried.
+- A verifier that evaluates an extension field **MUST** document, in its own
+  vendor contract, the field's name, semantics, and resulting verdict(s). A host
+  **MUST** establish that the verifier it spawned implements that contract from
+  its configured verifier identity or policy (the same rule that governs `kind`,
+  §3.5) — never from the absence of a deny.
+- A verifier **MUST NOT** use an extension field to relax any check this
+  document requires on the defined fields. An extension field is host-asserted
+  and not covered by the §4 binding signature; it can only narrow the outcome
+  (an additional `deny`), never widen it.
+
+> **Informative — binding an action instance by capability-token fold.** A host
+> that must authorize "send a message to *this* recipient" rather than "send
+> messages" carries the instance inside the token itself, e.g.
+> `send_message:to=<sha256-hex of recipient>` or `pay:payee=<id>:max=<amount>`.
+> The token then appears in `granted_capabilities`, and authorization requires
+> the binding's `capabilities` array to contain an identical token (set
+> comparison, §4.1; otherwise `deny code=request_mismatch`, §9). The instance is
+> therefore under the same signature as every other bound field, and it was
+> chosen at issuance by the operator who signed the binding — which is the
+> property a host wants. The token grammar is host-defined and opaque to this
+> contract; the verifier's capability map must recognize the folded form, or the
+> request is denied `unknown_capability` (§9), the correct fail-closed default
+> for a verifier that has not been told how to interpret it. Whether the
+> reference `bolyra verify` capability map admits instance-qualified tokens is
+> defined by the design spec (§6 capability map), not by this document. By
+> contrast, an unsigned extension field such as `tool_args_sha256` gives the
+> host no instance guarantee at all.
+
 ### 2.2 Request JSON Schema
 
 ```json
@@ -137,6 +197,12 @@
     "now_unix": { "type": "integer", "exclusiveMinimum": 0 }
   }
 }
 ```
 
+The `additionalProperties: true` declarations above admit extension fields for
+forward compatibility only. They do not make an undeclared member an input to
+the decision: a verifier is free to ignore it, and an `allow` carries no
+information about it (§2.1.1). Hosts and verifiers **MUST NOT** derive
+authorization semantics from the schema's permissiveness.
+
 ## 3. Verifier → host verdict (stdout)
 
 The verifier **MUST** write exactly one JSON object to stdout and nothing else
@@ -585,6 +651,8 @@
 1. **Spawn** the verifier command (e.g. `bolyra verify` — see §12 for flags).
 2. **Write** the §2.1 request object to the child's stdin (the host fills in its
    own capability tokens in `granted_capabilities` and its wall clock in
-   `now_unix`), then close stdin.
+   `now_unix`), then close stdin. Any further field the host adds is an
+   extension field (§2.1.1): it does not widen what the verdict decides, and an
+   action instance the host needs covered belongs inside a capability token.
 3. **Read** exactly one JSON verdict from the child's stdout under the strict
    single-object rule (§5.2), enforcing the host timeout (§6).
```

## Rationale

**What the pinned text permits.** §2.2 declares `"additionalProperties": true` on the envelope and again on the inner `request` object, and §2.1's field requirements govern only the five defined `request` members plus `version`, `bundle`, and `now_unix`. §4.1 fixes the signed surface at "exactly the six fields `agent_name`, `project_key`, `program`, `model`, `capabilities` (a string array), and `expiry`". Nowhere in §2 is there a verifier obligation toward an undefined member, and nowhere is a host told what an `allow` does and does not cover. Two concrete divergences follow:

- **Fail-open belief.** A host adds `"tool_args_sha256": "..."` to `request`, receives `{ "verdict": "allow" }`, and records the action as argument-verified. The verifier, conforming to the pinned text, never looked at the field. The host's audit trail now asserts a guarantee the contract never provided. The competing layers cited in the finding (OAP, agentgateway CEL on `call_tools`, Pomerium `mcp_tool`) all evaluate the tool call with its arguments in scope, so a host migrating from one of them will naturally assume EVC does too.
- **Vendor divergence without a contract.** One `external`-class verifier ignores the field, another denies on it, a third uses it to *widen* a decision (e.g. skipping `request_mismatch` when an extension carries a "pre-authorized" flag). Under the pinned text all three are conforming, and a host cannot tell which it spawned.

**Why this wording closes it.** The new §2.1.1 does three things without touching the wire:

1. It states what an `allow` means: capability-class admission of the five-field principal at `now_unix`, nothing more. This is not new behavior; it is the behavior §4.1 and §9 (`request_mismatch`, `unknown_capability`, `scope_exceeded`) already imply, made explicit so a host cannot claim to have read the spec and still believe an argument digest was checked.
2. It gives the host a spec-sanctioned way to get instance coverage that lands inside the existing signed surface: fold the instance into the capability token. Because §9 `request_mismatch` already denies when "`granted_capabilities` are not covered by the binding's capabilities", and §4.1 already says the verifier compares `capabilities` as a set, a folded token is instance-bound by the signature with zero new verifier logic. The note is informative because the token grammar is host-defined; the fold's security follows from existing normative text, not from the note.
3. It defines "extension field" and pins its authorization weight to zero on both sides.

**RFC 2119 choices.**

- Host `MUST NOT` infer verification from `allow` and `MUST NOT` treat `allow` as covering unfolded detail: these are the load-bearing rules. Anything weaker leaves the fail-open belief a conforming host behavior.
- Host `MUST` fold instance material into a token if it wants instance coverage: this is the only mechanism the six-field binding admits, so a SHOULD would leave a conforming host with a non-working alternative.
- Verifier `MAY` ignore extension fields: this preserves the forward-compatibility purpose of `additionalProperties: true` and matches what every existing conforming verifier already does.
- Verifier `MUST NOT` deny `malformed_input` solely for an extension field: §2.1 reserves `malformed_input` for non-object, missing-REQUIRED, or wrong-type conditions, and the §2.2 schema already accepts extension fields. A verifier that rejected them would be strictly outside the pinned schema; the rule makes the existing schema's promise explicit rather than changing it.
- Verifier `MUST` document any extension it evaluates and host `MUST` establish that from configured identity: this mirrors the §3.5 rule for `kind` ("never from the `kind` string alone") so there is one consistent principle for verifier-asserted metadata.
- Verifier `MUST NOT` widen on an extension field: an extension is not under the §4 signature, so allowing it to relax a check would let a host-controlled byte override an operator-signed binding, reintroducing exactly the class of re-anchoring §4.1's binding v2 closed for `expiry`.

## Impact

**Published vectors.** No effect on the 28 published vectors. The change is prose only. The §2.2 schema is byte-identical (`additionalProperties: true` is retained on both objects, no new property, no new `required`), the verdict schema and §9 registry are untouched, and no new denial code is introduced. No accompanying vector artifact is required. The host-conformance suite exercises host handling of verifier output; the new host rules are rules of interpretation (what a host may believe about an `allow`) and are not observable through the stdout/exit surface those vectors test.

**Wire compatibility.** Fully compatible within wire version `1` in both directions. Every request that was valid remains valid; every verdict a conforming verifier emitted remains conforming. A host or verifier written against the pinned text that already ignores extension fields is conforming to this revision without change.

**One item requiring maintainer verification.** The new "verifier MUST NOT classify as `malformed_input` solely because an extension field is present" rule is consistent with the pinned §2.2 schema, but whether the reference `bolyra verify` request validation in `integrations/cli` actually accepts unknown members (as opposed to validating with a closed schema) requires maintainer verification against that implementation. If it rejects them today, that is a pre-existing divergence from the pinned schema that this diff surfaces rather than creates, and the rule should be kept.

**Reference capability map.** The informative note deliberately does not claim the reference verifier's capability map accepts instance-qualified tokens; that is governed by the design spec's §6 capability map and requires maintainer verification against `docs/superpowers/specs/2026-07-08-external-verifier-cli-design.md`. Under the pinned §9, an unrecognized folded token is denied `unknown_capability`, so the fail-closed default holds either way.

**Header and changelog.** The document-revision line in the status block and the §15 changelog should receive a matching prose-only entry. §15 is not quoted in this artifact, so that entry is left to the maintainer rather than diffed blind.

**-02 relevance.** The finding names the -02 draft's request section as a second target. The two normative rules of §2.1.1 (verdict scope; extension fields carry no authorization weight) and the capability-token fold note should be mirrored there in the draft's own terminology. This artifact targets only the EVC contract file; the -02 text is not quoted here and requires maintainer verification against the current -02 working draft before a companion diff is staged. This is a strengthening item for -02: it removes the most likely "how does this compare to per-tool-call policy engines" reviewer objection by stating precisely where an action instance lives in the signed surface.
