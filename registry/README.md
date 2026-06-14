# @bolyra/registry

Credential registry API for Bolyra agent credentials. Express + Postgres MVP.

## Quick Start

```bash
# Start Postgres + registry via Docker Compose
docker compose up -d

# Or run locally (requires Postgres on DATABASE_URL)
npm install
npm run build
DATABASE_URL=postgres://... REGISTRY_API_KEY=your-key npm start

# Development mode (tsx, auto-reload)
DATABASE_URL=postgres://... REGISTRY_API_KEY=your-key npm run dev

# Run migrations
DATABASE_URL=postgres://... npm run migrate
```

## API

All endpoints require `Authorization: Bearer <REGISTRY_API_KEY>` except `/health`.

### POST /v1/credentials

Register or update an agent credential.

```json
{
  "credential": {
    "modelHash": "123456",
    "operatorPublicKey": { "x": "111", "y": "222" },
    "permissionBitmask": "7",
    "expiryTimestamp": "1750000000",
    "signature": { "R8": { "x": "333", "y": "444" }, "S": "555" },
    "commitment": "999"
  },
  "metadata": {}
}
```

Response: `{ "commitment": "999", "status": "active" }`

### GET /v1/credentials/:commitment

Returns `{ "credential": {...} }` or 404 if not found / revoked.

### DELETE /v1/credentials/:commitment

Soft-revokes the credential. Returns `{ "commitment": "...", "status": "revoked" }`.

### GET /health

Returns `{ "status": "ok" }`.

## SDK Integration

Use `createRegistryResolver` from `@bolyra/sdk` to resolve credentials from this API:

```typescript
import { createRegistryResolver } from '@bolyra/sdk';

const resolve = createRegistryResolver({
  baseUrl: 'http://localhost:3100',
  apiKey: 'your-key',
});

const credential = await resolve('999');
```
