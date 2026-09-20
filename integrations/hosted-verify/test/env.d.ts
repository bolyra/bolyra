import type { Env } from '../src/index';

declare global {
  namespace Cloudflare {
    // `cloudflare:test`'s `env` is typed as `Cloudflare.Env` — bind it to the
    // worker's own Env shape.
    interface Env extends EnvShape {}
  }
}

type EnvShape = Env & {
  /** Injected by vitest.config.mts for test/wrangler-config.spec.ts (not a Worker binding). */
  WRANGLER_CONFIG: string;
};

export {};
