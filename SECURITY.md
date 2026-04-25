# Security Policy

The Bolyra project takes security seriously. This document describes how to
report vulnerabilities and what you can expect from the project in response.

## Scope

This policy covers vulnerabilities in code that ships under the official
Bolyra packages:

- `@bolyra/sdk` (TypeScript SDK, including `sdk/` source tree)
- `@bolyra/mcp` (MCP middleware, including `integrations/mcp/` source tree)
- The Bolyra circuits (`circuits/` source tree, including the trusted setup
  artifacts checked into `circuits/build/`)
- The Bolyra smart contracts (`contracts/` source tree)
- The Bolyra protocol specification (when published)

Third-party dependencies (snarkjs, circomlibjs, ethers, the MCP SDK, etc.) are
out of scope for this policy. Please report vulnerabilities in those projects
to their respective maintainers.

## Reporting a vulnerability

**Do not file a public GitHub issue for security-sensitive reports.**

Preferred channel: **GitHub Security Advisories** (private). Open a draft
advisory at:

  https://github.com/bolyra/bolyra/security/advisories/new

This keeps the report private to the maintainers, integrates CVE assignment
when a fix ships, and lets us coordinate the public disclosure with you in
the same thread.

If you do not have a GitHub account or prefer email, send your report to:

  **security@bolyra.ai**

A useful report includes:

1. A description of the vulnerability and its potential impact.
2. Steps to reproduce, ideally with a minimal proof of concept.
3. Affected versions, commits, or deployments.
4. Any suggested mitigations or fixes you have in mind.
5. Whether you would like public credit, and under what name.

For non-security inquiries, please use the public issue tracker — the
security address and private advisory channel are reserved for vulnerability
reports and will not get a faster response for general questions.

## Response timeline

- **Acknowledgement:** within 5 business days of receipt.
- **Initial triage and severity assessment:** within 10 business days.
- **Fix or mitigation:** target window depends on severity, generally 30-90
  days. Critical vulnerabilities are prioritized.
- **Coordinated disclosure:** we will work with you on disclosure timing. The
  default is a 90-day embargo from the date the report is acknowledged, with
  earlier disclosure if a fix ships sooner.

## Vulnerabilities specifically of interest

Because Bolyra is a zero-knowledge authentication protocol, the following
classes of issue are particularly important:

- Soundness bugs in the circuits (proofs that should not verify).
- Zero-knowledge or completeness bugs (correct provers that fail, or proofs
  that leak witness data).
- Trusted-setup compromise concerns or evidence of malformed ceremony output.
- Replay or scope-confusion attacks in the handshake protocol.
- Authentication bypass in the MCP middleware (`@bolyra/mcp`).
- Key recovery, malleability, or domain-separation issues.
- Memory safety issues in any native code we ship (e.g., the rapidsnark
  prover binary).

Demo files in `examples/mcp-demo/demo-data/` use deliberately fake credentials
and are not security-sensitive.

## Safe harbor

We will not pursue legal action against good-faith security researchers who:

- Make a reasonable effort to avoid privacy violations, destruction of data,
  and interruption or degradation of services.
- Do not access more data than is strictly necessary to demonstrate the
  vulnerability.
- Give the project a reasonable opportunity to respond before any public
  disclosure.

## Recognition

With your consent, we will credit you in the security advisory and the
project changelog. We do not currently operate a paid bug-bounty program.
