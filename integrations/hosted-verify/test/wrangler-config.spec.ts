/**
 * wrangler.jsonc is configuration that only a deploy exercises, so pin what a deploy
 * would silently get wrong: the capability map must be the mpp vocabulary (the
 * managed-revocation example and every mpp mandate deny unknown_capability otherwise),
 * and the staging environment must redeclare exactly the bindings Wrangler does not
 * inherit. vitest.config.mts reads the JSONC and hands both environments in as JSON.
 */
import { describe, expect, it } from 'vitest';
import { env } from 'cloudflare:test';
import mandate from './fixtures/mandate.json';

const cfg = JSON.parse(env.WRANGLER_CONFIG!) as {
  vars: Record<string, string>;
  durable_objects: unknown;
  analytics_engine_datasets: Array<{ binding: string; dataset: string }>;
  migrations: unknown;
  version_metadata: unknown;
  env: { staging: { vars: Record<string, string>; durable_objects: unknown; analytics_engine_datasets: Array<{ binding: string; dataset: string }>; version_metadata: unknown; name?: string } };
};

describe('wrangler.jsonc', () => {
  it('sets CAPABILITY_MAP to the mpp vocabulary, in production and staging alike', () => {
    expect(JSON.parse(cfg.vars.CAPABILITY_MAP!)).toEqual(mandate.capability_map);
    expect(JSON.parse(cfg.env.staging.vars.CAPABILITY_MAP!)).toEqual(mandate.capability_map);
  });

  it('staging redeclares the non-inherited bindings and nothing diverges from production', () => {
    expect(cfg.env.staging.durable_objects).toEqual(cfg.durable_objects);
    expect(cfg.env.staging.analytics_engine_datasets.map((d) => d.binding)).toEqual(cfg.analytics_engine_datasets.map((d) => d.binding));
    expect(cfg.env.staging.analytics_engine_datasets[0]!.dataset).toBe(`${cfg.analytics_engine_datasets[0]!.dataset}_staging`);
    expect(Object.keys(cfg.env.staging.vars).sort()).toEqual(Object.keys(cfg.vars).sort());
    expect(cfg.env.staging.vars.RECEIPT_ISSUER).toBe('bolyra-hosted-verify-staging');
    expect(cfg.env.staging.name).toBeUndefined(); // Wrangler names it bolyra-hosted-verify-staging
    expect(cfg.migrations).toBeDefined(); // inherited by every environment
  });

  it('declares the version_metadata binding /health echoes, in production and staging (not inherited)', () => {
    expect(cfg.version_metadata).toEqual({ binding: 'CF_VERSION_METADATA' });
    expect(cfg.env.staging.version_metadata).toEqual({ binding: 'CF_VERSION_METADATA' });
  });
});
