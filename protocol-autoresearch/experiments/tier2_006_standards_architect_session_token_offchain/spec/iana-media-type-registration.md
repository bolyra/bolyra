# IANA Media Type Registration: `application/bolyra-session+jwt`

This document is a draft registration template for the `application/bolyra-session+jwt` media type per [RFC 6838 Section 5](https://www.rfc-editor.org/rfc/rfc6838#section-5).

## Registration Template

**Type name:** application

**Subtype name:** bolyra-session+jwt

**Required parameters:** None

**Optional parameters:** None

**Encoding considerations:** binary

A `bolyra-session+jwt` value is a JWS Compact Serialization as defined in [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515), which is a sequence of Base64url-encoded segments separated by period (`.`) characters. The token is always US-ASCII compatible.

**Security considerations:**

The security considerations of [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515) and [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) apply. Additionally:

- Tokens MUST be transmitted over TLS 1.2 or later to prevent interception.
- The `humanNullifier` and `agentNullifier` claims contain pseudonymous identifiers derived from zero-knowledge proofs. While not directly linkable to real-world identities, they are linkable within the session scope and SHOULD be treated as sensitive.
- The `scopeCommitment` claim encodes permission bits. Relying parties MUST validate scope before granting access to protected resources.
- Tokens are bearer credentials. Possession of a valid token grants access. Implementations MUST protect tokens against theft (e.g., XSS, CSRF).
- Symmetric signing algorithms (e.g., HS256) are explicitly prohibited. Only asymmetric algorithms (EdDSA, ES256) are permitted.
- Token lifetime SHOULD be minimized. The specification RECOMMENDS a maximum of 1 hour for financial scopes and 24 hours for read-only scopes.

**Interoperability considerations:**

The structured syntax suffix `+jwt` indicates that the content follows the JWT format defined in [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519). The `typ` header parameter is set to `bolyra-session+jwt` to distinguish BSTs from other JWT-based tokens.

Implementations MUST support the `EdDSA` (Ed25519) algorithm. The `ES256` (P-256 ECDSA) algorithm is OPTIONAL but RECOMMENDED for environments lacking Ed25519 support.

The payload contains Bolyra-specific private claims (`humanNullifier`, `agentNullifier`, `sessionNonce`, `scopeCommitment`) alongside standard JWT registered claims (`iat`, `exp`, `iss`).

**Published specification:**

Bolyra Session Token Format Specification:
https://github.com/bolyra/bolyra/blob/main/spec/session-token-format.md

**Applications that use this media type:**

- Bolyra SDK (`@bolyra/sdk`) — TypeScript and Python implementations
- LangChain, CrewAI, and MCP middleware consuming Bolyra-authenticated sessions
- Relying party servers validating off-chain session tokens after on-chain ZKP handshake verification

**Fragment identifier considerations:** N/A

**Additional information:**

- **Deprecated alias names for this type:** None
- **Magic number(s):** The Base64url-encoded JOSE header will begin with `eyJ` (the encoding of `{"`).
- **File extension(s):** `.bst`
- **Macintosh file type code(s):** None

**Person & email address to contact for further information:**

ZKProva Inc. <contact@bolyra.ai>

**Intended usage:** COMMON

**Restrictions on usage:** None

**Author/Change controller:**

ZKProva Inc.
https://bolyra.ai
