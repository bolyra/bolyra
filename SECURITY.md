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

## Known accepted residual Dependabot alerts

We track every Dependabot alert on the default branch. The vast majority are
resolved by direct version bumps or by `overrides` blocks in the relevant
`package.json` (which forces transitive resolution at install time). A small
set of alerts have been triaged and accepted as tolerable residuals because
the affected code is not reachable from any shipped Bolyra package or because
no upstream patch is yet available. They are documented here so consumers and
auditors can independently confirm our reasoning.

- **`elliptic` advisories (multiple).** `elliptic` is pulled in transitively
  via `circomlibjs` and `ethers@5` (Hardhat dev tooling). At the time of
  writing there is no published `elliptic` release that addresses the open
  advisories. The affected code is not invoked by `@bolyra/sdk` or
  `@bolyra/mcp` at runtime — it is reachable only from the contracts build
  toolchain and the circomlibjs Poseidon helpers used during proof
  generation. We are tracking upstream and will bump the override as soon as
  a fixed release lands.

- **`snarkjs` v0.5.x transitively via `circom_tester` → `circomkit` →
  `@zk-kit/artifacts` (CLI).** The vulnerable `snarkjs` is only reachable via
  the `@zk-kit/artifacts` CLI entry point (`dist/cli/index.js`). The runtime
  entry that the published Bolyra packages actually import is
  `dist/index.node.js`, which does not depend on `circomkit` or the
  vulnerable `snarkjs`. The repository pins `snarkjs` to a fixed version via
  a nested `circom_tester.snarkjs` override in every manifest that exposes
  the `circom_tester` subtree, so installs and CI use the patched version
  even for the dev-only path.

- **`axios`, `lodash`, `undici`, `uuid` advisories in `contracts/`.** These
  are reachable only through `@nomicfoundation/hardhat-toolbox` and its
  transitive dependencies. The contracts package is a development-only
  Hardhat workspace; none of these dependencies ship in any published
  Bolyra package. A clean fix requires a major-version Hardhat toolchain
  bump, which is on the roadmap but is deferred to keep the contracts build
  reproducible against the audited circuit verifier contracts.

- **`@modelcontextprotocol/sdk` consumer caveat (`integrations/mcp/`).**
  `@bolyra/mcp` lists `@modelcontextprotocol/sdk` as a peer dependency.
  Repository-level `overrides` clean our lockfile but do **not** propagate
  to downstream consumers of `@bolyra/mcp`. Consumers are responsible for
  upgrading their own `@modelcontextprotocol/sdk` version when the SDK
  ships an advisory fix. We will publish a new `@bolyra/mcp` minor whenever
  the peer range needs to widen.

### CI gate

A `dependency-audit` job in `.github/workflows/ci.yml` runs
`npm audit --omit=dev --audit-level=high` against each published package
(`sdk`, `integrations/mcp`, `integrations/openclaw`,
`integrations/payment-protocols`) on every push and pull request to `main`.
A new high or critical runtime advisory will fail CI. The job intentionally
excludes dev dependencies — runtime-reachable risk is the gate.
