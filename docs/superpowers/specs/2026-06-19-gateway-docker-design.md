# Docker Image for @bolyra/gateway -- Design Spec

**Date:** 2026-06-19
**Pipeline:** pdlc-2026-06-19-gateway-docker
**Author:** Viswa + Claude Opus 4.6
**Status:** Draft (awaiting Gate 1 approval)

## Overview

Ship a production-ready Docker image for `@bolyra/gateway` so operators can run the MCP auth gateway without installing Node.js. The image publishes to GitHub Container Registry (`ghcr.io/bolyra/gateway`) on every semver tag, with a GitHub Actions CI workflow handling build, push, and multi-arch support.

## Goals

1. **Zero-dependency runtime.** `docker run ghcr.io/bolyra/gateway --target http://host.docker.internal:3000/mcp` works out of the box.
2. **Config via volume mount or env vars.** Mount `gateway.yaml` at `/etc/bolyra/gateway.yaml` or pass all config through env vars and CLI flags.
3. **Redis nonce store support.** `REDIS_URL` env var connects to an external Redis for multi-instance nonce replay protection.
4. **Multi-arch builds.** `linux/amd64` and `linux/arm64` (covers x86 servers and ARM-based cloud instances / Apple Silicon dev).
5. **Automated CI.** GitHub Actions workflow builds and pushes on version tags (`v*`). Also builds on PR for validation (no push).
6. **Small image.** Multi-stage build with Alpine; target under 100MB compressed.

## Non-Goals

- Docker Compose orchestration (out of scope; users can compose themselves).
- Helm chart or Kubernetes manifests (future work).
- Docker Hub publishing (GHCR only for now; can add later).
- Bundling Redis inside the image (Redis is an external dependency).

## Architecture

### Dockerfile (multi-stage)

```
Stage 1: builder
  FROM node:22-alpine
  WORKDIR /app
  COPY integrations/gateway/package*.json ./
  COPY sdk/                  # @bolyra/sdk (workspace dep)
  COPY integrations/mcp/     # @bolyra/mcp (workspace dep)
  COPY integrations/receipts/ # @bolyra/receipts (workspace dep)
  RUN npm ci
  COPY integrations/gateway/ ./gateway/
  RUN cd gateway && npm run build

Stage 2: runtime
  FROM node:22-alpine
  WORKDIR /app
  COPY --from=builder /app/gateway/dist/ ./dist/
  COPY --from=builder /app/gateway/package*.json ./
  COPY --from=builder /app/node_modules/ ./node_modules/
  RUN npm prune --production
  EXPOSE 4100
  HEALTHCHECK CMD wget -qO- http://localhost:4100/healthz || exit 1
  ENTRYPOINT ["node", "dist/cli.js"]
```

**Key decision: monorepo-aware build vs published npm packages.**

Option A (monorepo build): COPY workspace packages into the builder, resolve deps from source.
Option B (npm install): `npm install @bolyra/gateway` in the builder from the npm registry.

**Chosen: Option B (npm install from registry).** Rationale:
- The gateway is already published to npm at v0.2.0 with all deps declared.
- Avoids copying the entire monorepo into the Docker context.
- Simpler Dockerfile, faster builds, smaller context.
- The CI workflow tags the Docker image to the same version as the npm package -- they are always in sync because the release agent publishes npm first, then triggers the Docker build.

Revised Dockerfile concept:

```dockerfile
# Stage 1: install
FROM node:22-alpine AS builder
WORKDIR /app
RUN npm install --production @bolyra/gateway@latest
# The bin entry "bolyra-gateway" points to dist/cli.js

# Stage 2: runtime
FROM node:22-alpine
RUN addgroup -g 1001 bolyra && adduser -u 1001 -G bolyra -s /bin/sh -D bolyra
WORKDIR /app
COPY --from=builder /app/node_modules/ ./node_modules/
RUN mkdir -p /etc/bolyra /app/receipts && chown -R bolyra:bolyra /app/receipts
USER bolyra
EXPOSE 4100
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD wget -qO- http://localhost:4100/healthz || exit 1
ENTRYPOINT ["node", "node_modules/@bolyra/gateway/dist/cli.js"]
CMD ["--config", "/etc/bolyra/gateway.yaml"]
```

### Config Resolution Order

Inside the container, the gateway resolves config in this order (later wins):

1. `/etc/bolyra/gateway.yaml` (volume-mounted config file)
2. Environment variables (`REDIS_URL`, etc. -- substituted via `${VAR}` syntax in YAML)
3. CLI flags passed after the image name

Usage examples:

```bash
# Minimal: dev mode, no config file
docker run --rm ghcr.io/bolyra/gateway \
  --target http://host.docker.internal:3000/mcp --dev

# Production: config file + Redis
docker run -d \
  -v $(pwd)/gateway.yaml:/etc/bolyra/gateway.yaml:ro \
  -e REDIS_URL=redis://redis:6379 \
  -e BOLYRA_RECEIPT_KEY=hex-encoded-key \
  -p 4100:4100 \
  ghcr.io/bolyra/gateway

# Override port via CLI
docker run --rm -p 8080:8080 ghcr.io/bolyra/gateway \
  --target http://upstream:3000/mcp --port 8080 --dev
```

### .dockerignore

Placed at `integrations/gateway/.dockerignore`. Excludes `node_modules/`, `test/`, `.git/`, etc. Since we use Option B (npm install), the Dockerfile lives at repo root level and the `.dockerignore` at repo root excludes everything except what the Dockerfile needs.

### GitHub Actions Workflow

File: `.github/workflows/docker-gateway.yml`

```yaml
name: Docker Gateway

on:
  push:
    tags: ['gateway-v*']   # e.g., gateway-v0.2.0
  pull_request:
    paths:
      - 'integrations/gateway/**'
      - 'Dockerfile.gateway'
      - '.github/workflows/docker-gateway.yml'

jobs:
  build-and-push:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    steps:
      - uses: actions/checkout@v4

      - uses: docker/setup-qemu-action@v3
      - uses: docker/setup-buildx-action@v3

      - uses: docker/login-action@v3
        if: startsWith(github.ref, 'refs/tags/')
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Extract version from tag
        id: version
        run: echo "version=${GITHUB_REF#refs/tags/gateway-v}" >> "$GITHUB_OUTPUT"

      - uses: docker/build-push-action@v6
        with:
          context: .
          file: Dockerfile.gateway
          platforms: linux/amd64,linux/arm64
          push: ${{ startsWith(github.ref, 'refs/tags/') }}
          tags: |
            ghcr.io/bolyra/gateway:${{ steps.version.outputs.version }}
            ghcr.io/bolyra/gateway:latest
          build-args: |
            GATEWAY_VERSION=${{ steps.version.outputs.version }}
          cache-from: type=gha
          cache-to: type=gha,mode=max
```

**Tag convention:** `gateway-v{semver}` (e.g., `gateway-v0.2.0`). Separate from npm version tags to allow independent Docker releases if needed, but in practice they track 1:1.

### Dockerfile Location

`Dockerfile.gateway` at repo root. Rationale: Docker context needs to be the repo root if we ever switch to Option A (monorepo build). Even with Option B (npm install), keeping it at root is conventional for multi-Dockerfile repos. The `.dockerignore` at root keeps context small.

### Security Considerations

1. **Non-root user.** The runtime stage runs as `bolyra:bolyra` (UID 1001). No root.
2. **Read-only filesystem compatible.** The only writable path is `/app/receipts/` (for file-mode receipts). Users can mount a volume or use `--receipt-stdout` instead.
3. **No secrets baked in.** All credentials (Redis URL, receipt signing key, HMAC secret) are passed via env vars at runtime.
4. **Alpine base.** Minimal attack surface. node:22-alpine is the same base used by `registry/Dockerfile`.
5. **HEALTHCHECK built in.** Orchestrators (Docker Compose, ECS, K8s) can use the native healthcheck.
6. **Pinned base image.** Use `node:22-alpine` (not `node:latest`) for reproducibility. Consider digest pinning in a follow-up.

### Testing

1. **Build test (CI).** The PR-triggered workflow builds the image without pushing. Build success = test pass.
2. **Smoke test in CI.** After build, run the container in dev mode, hit `/healthz`, verify 200. This confirms the entrypoint, config loading, and health endpoint work inside the container.
3. **Local dev test.** Document in README how to build and run locally:
   ```bash
   docker build -f Dockerfile.gateway -t bolyra-gateway:local .
   docker run --rm -p 4100:4100 bolyra-gateway:local --target http://host.docker.internal:3000/mcp --dev
   curl http://localhost:4100/healthz
   ```

## Files Changed

| File | Action | Description |
|------|--------|-------------|
| `Dockerfile.gateway` | Create | Multi-stage Dockerfile for gateway |
| `.dockerignore` | Create | Root-level Docker context exclusions |
| `.github/workflows/docker-gateway.yml` | Create | CI workflow for build + push to GHCR |
| `integrations/gateway/README.md` | Modify | Add Docker usage section |

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Workspace deps not resolvable via npm install | Build fails | Gateway v0.2.0 is already on npm with all deps declared; verified installable |
| Multi-arch build slow in CI | Long CI times | Use GHA cache (`cache-from: type=gha`); QEMU for arm64 is ~2-3min overhead |
| GHCR rate limits for public pulls | Users throttled | GHCR has generous limits for public packages; monitor and add Docker Hub mirror if needed |
| Base image CVEs | Security | Pin to node:22-alpine, set up Dependabot for Docker base image updates |

## Open Questions (resolved in spec)

1. **GHCR vs Docker Hub?** GHCR. Free for public packages, integrated with GitHub, no separate account needed.
2. **Tag convention?** `gateway-v{semver}` for Git tags, `{semver}` + `latest` for Docker tags.
3. **Monorepo build vs npm install?** npm install. Simpler, faster, avoids context bloat.
