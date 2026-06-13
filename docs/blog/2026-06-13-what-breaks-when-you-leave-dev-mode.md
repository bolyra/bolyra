# What breaks when you leave dev mode

Dev mode is great for trying Bolyra. It gives you instant mock proofs, no circuit artifacts, and a short path to seeing `@bolyra/mcp` gate a tool call.

It also skips four things that matter in production:

1. `resolveCredential`: who is this agent?
2. `validateRoots`: is this proof against a real Merkle tree?
3. `nonceStore`: was this proof already used?
4. proof-to-credential binding: does this proof match the claimed credential?

Here is the TypeScript config difference:

```ts
// Dev mode — what you start with:
withBolyraAuthStdio(server, {
  devMode: true,
  toolPolicy: { list_files: 1n, read_file: 1n, write_file: 2n },
});

// Production — what you need:
const credentialStore = new InMemoryCredentialStore([agent]);
const sdkConfig = { circuitDir: process.env.BOLYRA_CIRCUIT_DIR };

withBolyraAuthStdio(server, {
  devMode: false,
  resolveCredential: (commitment) => credentialStore.resolve(commitment),
  validateRoots: createMockRootValidator(),
  nonceStore: new MemoryNonceStore(),
  toolPolicy: { list_files: 1n, read_file: 1n, write_file: 2n },
  sdkConfig,
});
```

## 1. `resolveCredential`: who is this agent?

In dev mode, the verifier accepts a dev bundle and reads mock public signals. It does not look up the agent credential from your registry.

Production mode is different. `@bolyra/mcp` refuses to start without `resolveCredential` when `devMode` is not enabled — it throws at setup time, not on the first request. Once running, unresolved commitments fail the request.

```diff
 withBolyraAuthStdio(server, {
-  devMode: true,
+  resolveCredential: (commitment) => credentialStore.resolve(commitment),
 });
```

The production example keeps this deliberately small:

```ts
export class InMemoryCredentialStore {
  private credentials = new Map<string, AgentCredential>();

  constructor(seed: AgentCredential[]) {
    for (const cred of seed) {
      this.credentials.set(cred.commitment.toString(), cred);
    }
  }

  async resolve(commitment: string): Promise<AgentCredential | null> {
    return this.credentials.get(commitment) ?? null;
  }
}
```

That is enough for the example. In real production, replace the map with Postgres, DynamoDB, or your on-chain credential registry.

## 2. `validateRoots`: is this proof against a real Merkle tree?

A Groth16 proof can be valid while still proving membership against a root your server should not trust.

That is why `BolyraMcpConfig` has `validateRoots`:

```diff
 withBolyraAuthStdio(server, {
   resolveCredential: (commitment) => credentialStore.resolve(commitment),
+  validateRoots: createMockRootValidator(),
 });
```

The verifier extracts:

```ts
const humanRoot = BigInt(bundle.humanProof.publicSignals[0]);
const agentRoot = BigInt(bundle.agentProof.publicSignals[0]);
```

Then it calls your validator. If it returns `false`, the request fails with root validation errors.

The example uses a mock:

```ts
export function createMockRootValidator() {
  return async (humanRoot: bigint, agentRoot: bigint): Promise<boolean> => {
    void humanRoot;
    void agentRoot;
    return true;
  };
}
```

That is production-shaped, not production-complete. The real version should check the on-chain `IdentityRegistry`, for example `humanRootExists(humanRoot)` and `agentRootExists(agentRoot)`.

## 3. `nonceStore`: was this proof already used?

Dev mode checks nonce freshness from the timestamp embedded in the nonce. It does not remember whether the same proof bundle was already submitted.

Production should reject replay.

```diff
+import { MemoryNonceStore } from '@bolyra/mcp';

 withBolyraAuthStdio(server, {
   resolveCredential: (commitment) => credentialStore.resolve(commitment),
   validateRoots: createMockRootValidator(),
+  nonceStore: new MemoryNonceStore(),
 });
```

`MemoryNonceStore` does exactly one thing:

```ts
async markIfFresh(nonce: string, ttlSeconds: number): Promise<boolean> {
  this.cleanup();
  if (this.used.has(nonce)) return false;
  this.used.set(nonce, Date.now() + ttlSeconds * 1000);
  return true;
}
```

That is fine for a single-process MCP server. If you run multiple instances, put this behind Redis or a database with TTL semantics. Otherwise, instance A and instance B will not share replay state.

## 4. Proof-to-credential binding: does this proof match the claimed credential?

This is the subtle one.

A request carries `credentialCommitment`. The server resolves that commitment to an `AgentCredential`, then verifies the ZK handshake.

Production verification also recomputes the scope commitment from the resolved credential:

```ts
const expectedScope = await sdk.poseidon3(
  credential.permissionBitmask,
  credential.commitment,
  credential.expiryTimestamp,
);

if (expectedScope !== verifyResult.scopeCommitment) {
  return {
    verified: false,
    reason: 'Proof is not bound to the claimed credential',
    warnings: [
      'Proof scopeCommitment does not match resolved credential',
    ],
  };
}
```

That check prevents credential substitution: a caller cannot prove against credential A, set `credentialCommitment` to privileged credential B, and inherit B's permissions.

There is no separate config flag for this. The fix is to leave dev mode and provide a real `resolveCredential`:

```diff
 withBolyraAuthStdio(server, {
-  devMode: true,
+  resolveCredential: (commitment) => credentialStore.resolve(commitment),
 });
```

Once the verifier has the resolved credential, `@bolyra/mcp` performs the binding check automatically.

## Bonus: delegation chains

If your agent uses v=2 bundles with delegation hops, production mode also verifies each delegation proof, recomputes each hop's scope commitment, checks delegatee expiry, and enforces a maximum chain depth of 3 hops. Dev mode only checks chain shape and extracts the leaf scope. That means a delegation chain that works in dev mode might fail in production if the proofs are invalid or the scope narrowing is incorrect.

## The short version

Dev mode answers: "Can I wire Bolyra into my MCP server?"

Production should answer:

- Does this commitment map to a real agent credential?
- Are the proof roots recognized?
- Has this nonce already been used?
- Does the proof actually bind to the credential being claimed?

The production example shows the smallest complete shape: credential resolver, root validator hook, nonce store, tool policy, and circuit config.

Start here: [integrations/mcp/examples/production-server on GitHub](https://github.com/bolyra/bolyra/tree/main/integrations/mcp/examples/production-server).
