# MCP Auth Works in Dev. Then Production Asks: Who Is This User?

## The demo works

Your MCP server starts.

The agent calls a tool.

The local auth path says yes.

## Then production asks 5 questions your demo can't answer

Local demos prove plumbing. Production needs attribution.

Not "did the request include something auth-shaped?" but: who is acting, who authorized them, what are they allowed to do, has this proof already been spent, and can you prove the decision later?

### 1. Who is this agent?

In dev, the caller is whatever script you just ran.

In production, the caller needs a stable identity tied to a credential commitment, so your server can resolve the agent before trusting the proof.

Bolyra one-liner:

```ts
resolveCredential: (commitment) => credentialStore.resolve(commitment),
```

That turns an opaque proof bundle into an agent credential your server can verify, score, log, and map to a DID like `did:bolyra:<network>:<commitment>`.

### 2. Did a human authorize this?

A production agent is usually not the root actor. It is acting through delegated authority.

Bolyra proof bundles carry the human proof and, in v2, an optional `delegationChain`. After verification, the MCP auth context tells you how many delegation hops were checked.

Bolyra one-liner:

```ts
const delegated = auth.chainDepth > 0;
```

That is the difference between "an agent showed up" and "an agent showed up through a verified human-to-agent delegation path."

### 3. What tools can they use?

Your demo probably has one happy path.

Production has tools with different blast radius. Reading a file is not writing a file. Listing resources is not deleting data. Auth has to narrow at the tool boundary, not just at server entry.

Bolyra one-liner:

```ts
toolPolicy: { list_files: 1n, read_file: 1n, write_file: 2n },
```

The wrapper checks the caller's effective permission bitmask before the tool runs. Tools outside the map only require a verified handshake; sensitive tools get explicit policy.

### 4. Has this proof been used before?

A valid proof is not enough if an attacker can replay it.

Production needs nonce freshness. Use `MemoryNonceStore` for single-process, Redis for multi-instance.

Bolyra one-liner:

```ts
nonceStore: new MemoryNonceStore(),
```

The important part is the contract: mark the nonce once, reject it the second time.

### 5. Can I prove what happened?

Logs are useful until someone asks for a signed artifact.

Bolyra can attach a signed auth receipt to the verification decision when a receipt signer is configured. That gives you a portable record of who was checked, what decision was made, and who signed that decision.

Bolyra one-liner:

```ts
receiptSigner: { issuer: 'my-mcp-server', keyId: 'prod-001', privateKey: process.env.RECEIPT_PRIVATE_KEY! },
```

Now audit is not just "search the logs and hope." It is a signed receipt your system can verify later.

## The production shape

The production example wires the real pieces together:

```ts
withBolyraAuthStdio(mcpServer.server, {
  devMode: mode === 'dev',
  resolveCredential: (commitment) => credentialStore.resolve(commitment),
  validateRoots: createMockRootValidator(),
  nonceStore: new MemoryNonceStore(),
  toolPolicy: {
    list_files: 1n,
    read_file: 1n,
    write_file: 2n,
  },
  ...(sdkConfig ? { sdkConfig } : {}),
});
```

The demo proves the tool call works. Production proves who authorized it.

Start here: [Production MCP example on GitHub](https://github.com/bolyra/bolyra/tree/main/integrations/mcp/examples/production-server).
