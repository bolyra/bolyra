# Bolyra Session Token Integration Guide

This guide shows how to extract and validate Bolyra JWT session tokens in
server-side middleware, with specific patterns for Express, LangChain, and
Vercel AI SDK.

## Overview

After a successful Bolyra handshake, the relayer issues a short-lived JWT
(default 5-minute TTL) containing the handshake's public signals. Downstream
services validate this bearer token instead of re-verifying the ZKP on every
request.

```
Client                  Relayer                 Your API
  |                       |                       |
  |-- ZKP handshake ----->|                       |
  |<-- session JWT -------|                       |
  |                                               |
  |-- Authorization: Bearer <jwt> --------------->|
  |                                               |-- verifySessionToken()
  |<-- 200 OK -----------------------------------|  
```

## Installation

```bash
npm install @bolyra/sdk jose
```

## Express Middleware

```typescript
import { verifySessionToken, BolyraSessionTokenError } from '@bolyra/sdk';
import { importSPKI } from 'jose';
import type { Request, Response, NextFunction } from 'express';

// Load the relayer's public key once at startup
const RELAYER_PUB_KEY_PEM = process.env.BOLYRA_RELAYER_PUB_KEY!;
const pubKeyPromise = importSPKI(RELAYER_PUB_KEY_PEM, 'ES256');

export async function bolyraAuth(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Missing Authorization header' });
    return;
  }

  const token = header.slice(7);
  try {
    const pubKey = await pubKeyPromise;
    const session = await verifySessionToken(token, pubKey);

    // Attach verified claims to the request for downstream handlers
    (req as any).bolyraSession = session;
    next();
  } catch (err) {
    if (err instanceof BolyraSessionTokenError) {
      const status = err.code === 'TOKEN_EXPIRED' ? 401 : 403;
      res.status(status).json({ error: err.code, message: err.message });
      return;
    }
    res.status(500).json({ error: 'Internal auth error' });
  }
}
```

**Usage:**

```typescript
import express from 'express';
import { bolyraAuth } from './middleware/bolyra-auth.js';

const app = express();

app.get('/api/protected', bolyraAuth, (req, res) => {
  const session = (req as any).bolyraSession;
  res.json({
    humanNullifier: session.payload.humanNullifier,
    permissions: session.payload.scopeCommitment,
    remainingSeconds: session.remainingSeconds,
  });
});
```

## LangChain Integration

Extract the Bolyra session from incoming requests in a LangChain
`RunnableMiddleware` or custom chain:

```typescript
import { RunnableLambda } from '@langchain/core/runnables';
import { verifySessionToken } from '@bolyra/sdk';
import { importSPKI } from 'jose';

const pubKey = await importSPKI(process.env.BOLYRA_RELAYER_PUB_KEY!, 'ES256');

const bolyraGate = new RunnableLambda({
  func: async (input: { token: string; query: string }) => {
    const session = await verifySessionToken(input.token, pubKey);
    if (!session.active) {
      throw new Error('Bolyra session expired');
    }
    return {
      ...input,
      bolyraSession: session,
    };
  },
});

// Compose with your chain
const chain = bolyraGate.pipe(yourLangChainPipeline);
```

### Extracting the Token from HTTP Headers

When serving a LangChain app via LangServe or a custom Express wrapper,
extract the bearer token from the `Authorization` header before passing it
to the chain:

```typescript
app.post('/api/chat', async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No token' });

  const result = await chain.invoke({ token, query: req.body.query });
  res.json(result);
});
```

## Vercel AI SDK Integration

For Vercel AI SDK (using `@bolyra/ai` or direct integration), validate the
session token in the route handler before streaming:

```typescript
import { streamText } from 'ai';
import { openai } from '@ai-sdk/openai';
import { verifySessionToken } from '@bolyra/sdk';
import { importSPKI } from 'jose';
import { NextRequest } from 'next/server';

const pubKey = await importSPKI(process.env.BOLYRA_RELAYER_PUB_KEY!, 'ES256');

export async function POST(req: NextRequest) {
  const token = req.headers.get('authorization')?.replace('Bearer ', '');
  if (!token) {
    return new Response('Unauthorized', { status: 401 });
  }

  const session = await verifySessionToken(token, pubKey);
  if (!session.active) {
    return new Response('Session expired', { status: 401 });
  }

  const { messages } = await req.json();

  const result = streamText({
    model: openai('gpt-4o'),
    messages,
    // Pass Bolyra session metadata to the model context
    system: `Authenticated via Bolyra. Human nullifier: ${session.payload.humanNullifier}`,
  });

  return result.toDataStreamResponse();
}
```

## Token Lifecycle

| Phase | Action |
|---|---|
| **Issue** | Relayer calls `issueSessionToken()` after successful on-chain handshake verification. |
| **Transmit** | Client receives JWT and includes it as `Authorization: Bearer <token>` on subsequent requests. |
| **Validate** | API middleware calls `verifySessionToken()` to check signature, expiry, and claims. |
| **Refresh** | When `remainingSeconds < 30`, client should re-handshake. Tokens are not refreshable. |

## Security Notes

1. **Always use TLS** — session tokens MUST only be transmitted over HTTPS.
2. **Never log tokens** — JWTs contain nullifier hashes that could be correlated.
3. **Short TTLs** — default 5 minutes. Increase only if your use case requires it (max 1 hour).
4. **Key rotation** — rotate relayer signing keys periodically. Publish public keys via a JWK Set endpoint.
5. **Issuer allowlisting** — always pass `expectedIssuer` to `verifySessionToken()` in production.
