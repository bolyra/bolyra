# Plan: Docker Image for @bolyra/gateway

**Date:** 2026-06-19
**Pipeline:** pdlc-2026-06-19-gateway-docker
**Spec:** `docs/superpowers/specs/2026-06-19-gateway-docker-design.md`

## Tasks

| # | Task | Size | Type | Depends On |
|---|------|------|------|------------|
| 1 | Create `Dockerfile.gateway` (multi-stage, npm install from registry) | S | parallel | -- |
| 2 | Create `.dockerignore` (minimize build context) | S | parallel | -- |
| 3 | Create `.github/workflows/docker-gateway.yml` (CI build + GHCR push) | M | parallel | -- |
| 4 | Update `integrations/gateway/README.md` with Docker section | S | parallel | -- |
| 5 | Build and smoke-test Docker image locally | S | sequential | 1, 2 |

**Parallelization:** Tasks 1-4 run concurrently. Task 5 waits for 1+2.
**Estimated scope:** 5 tasks, 4 parallelizable.
