import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
  loadConfigFile,
  substituteEnvVars,
  validateConfig,
  mergeCliFlags,
  loadConfig,
  ConfigValidationError,
} from '../src/config';
import type { GatewayConfig } from '../src/types';

describe('config loader', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gateway-config-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('loadConfigFile', () => {
    it('loads YAML config', () => {
      const configPath = path.join(tmpDir, 'gateway.yaml');
      fs.writeFileSync(configPath, `
target: http://localhost:3000/mcp
port: 4100
devMode: true
`);
      const config = loadConfigFile(configPath);
      expect(config).toEqual({
        target: 'http://localhost:3000/mcp',
        port: 4100,
        devMode: true,
      });
    });

    it('loads JSON config', () => {
      const configPath = path.join(tmpDir, 'gateway.json');
      fs.writeFileSync(configPath, JSON.stringify({
        target: 'http://localhost:3000/mcp',
        port: 5000,
      }));
      const config = loadConfigFile(configPath);
      expect(config).toEqual({
        target: 'http://localhost:3000/mcp',
        port: 5000,
      });
    });

    it('returns null for missing file', () => {
      const config = loadConfigFile(path.join(tmpDir, 'nonexistent.yaml'));
      expect(config).toBeNull();
    });
  });

  describe('substituteEnvVars', () => {
    it('replaces ${VAR} with env value', () => {
      process.env.TEST_GATEWAY_VAR = 'replaced_value';
      const result = substituteEnvVars({ key: '${TEST_GATEWAY_VAR}' });
      expect(result).toEqual({ key: 'replaced_value' });
      delete process.env.TEST_GATEWAY_VAR;
    });

    it('preserves unset variables as-is', () => {
      delete process.env.UNSET_VAR_XYZ;
      const result = substituteEnvVars({ key: '${UNSET_VAR_XYZ}' });
      expect(result).toEqual({ key: '${UNSET_VAR_XYZ}' });
    });

    it('handles nested objects', () => {
      process.env.TEST_NESTED = 'deep';
      const result = substituteEnvVars({ a: { b: '${TEST_NESTED}' } });
      expect(result).toEqual({ a: { b: 'deep' } });
      delete process.env.TEST_NESTED;
    });

    it('handles arrays', () => {
      process.env.TEST_ARR = 'item';
      const result = substituteEnvVars(['${TEST_ARR}', 'static']);
      expect(result).toEqual(['item', 'static']);
      delete process.env.TEST_ARR;
    });
  });

  describe('validateConfig', () => {
    it('passes valid config', () => {
      const config: GatewayConfig = {
        target: 'http://localhost:3000/mcp',
        port: 4100,
        network: 'base-sepolia',
        devMode: false,
        nonce: { store: 'memory', maxProofAge: 300 },
        receipts: { enabled: true, output: 'file', dir: './receipts/' },
        health: { enabled: true, path: '/healthz' },
      };
      expect(() => validateConfig(config)).not.toThrow();
    });

    it('throws on missing target', () => {
      const config = { port: 4100 } as Partial<GatewayConfig>;
      expect(() => validateConfig(config)).toThrow(ConfigValidationError);
      expect(() => validateConfig(config)).toThrow('"target" is required');
    });

    it('throws on invalid port', () => {
      const config = { target: 'http://localhost', port: 99999 } as Partial<GatewayConfig>;
      expect(() => validateConfig(config)).toThrow('"port" must be a number');
    });

    it('throws on webhook without URL', () => {
      const config = {
        target: 'http://localhost',
        receipts: { enabled: true, output: 'webhook' as const },
      } as Partial<GatewayConfig>;
      expect(() => validateConfig(config)).toThrow('webhook.url');
    });

    it('passes valid receipts.privateKey (with and without 0x prefix)', () => {
      const base: GatewayConfig = {
        target: 'http://localhost:3000/mcp',
        port: 4100,
        network: 'base-sepolia',
        devMode: false,
        nonce: { store: 'memory', maxProofAge: 300 },
        receipts: { enabled: true, output: 'file', privateKey: '0x' + 'ab'.repeat(32) },
        health: { enabled: true, path: '/healthz' },
      };
      expect(() => validateConfig(base)).not.toThrow();
      base.receipts.privateKey = 'ab'.repeat(32);
      expect(() => validateConfig(base)).not.toThrow();
    });

    it('throws on malformed receipts.privateKey', () => {
      const config = {
        target: 'http://localhost',
        receipts: { enabled: true, output: 'file' as const, privateKey: 'not-a-key' },
      } as Partial<GatewayConfig>;
      expect(() => validateConfig(config)).toThrow('"receipts.privateKey" must be a 32-byte secp256k1 key');
    });

    it('throws on receipts.privateKey with unresolved env var', () => {
      const config = {
        target: 'http://localhost',
        receipts: { enabled: true, output: 'file' as const, privateKey: '${BOLYRA_RECEIPT_KEY}' },
      } as Partial<GatewayConfig>;
      expect(() => validateConfig(config)).toThrow('unresolved environment variable');
    });

    it('passes valid redis nonce config', () => {
      const config: GatewayConfig = {
        target: 'http://localhost:3000/mcp',
        port: 4100,
        network: 'base-sepolia',
        devMode: false,
        nonce: { store: 'redis', maxProofAge: 300, redis: { url: 'redis://localhost:6379' } },
        receipts: { enabled: true, output: 'file', dir: './receipts/' },
        health: { enabled: true, path: '/healthz' },
      };
      expect(() => validateConfig(config)).not.toThrow();
    });

    it('throws on redis store without redis.url', () => {
      const config = {
        target: 'http://localhost:3000/mcp',
        nonce: { store: 'redis' as const },
      } as Partial<GatewayConfig>;
      expect(() => validateConfig(config)).toThrow('nonce.redis.url');
    });

    it('throws on redis.url with unresolved env var', () => {
      const config = {
        target: 'http://localhost:3000/mcp',
        nonce: { store: 'redis' as const, redis: { url: '${REDIS_URL}' } },
      } as Partial<GatewayConfig>;
      expect(() => validateConfig(config)).toThrow('unresolved environment variable');
    });

    it('throws on unknown nonce store type', () => {
      const config = {
        target: 'http://localhost:3000/mcp',
        nonce: { store: 'postgres' as any },
      } as Partial<GatewayConfig>;
      expect(() => validateConfig(config)).toThrow('"nonce.store" must be one of');
    });

    it('throws on maxProofAge of 0', () => {
      const config = {
        target: 'http://localhost:3000/mcp',
        nonce: { store: 'memory' as const, maxProofAge: 0 },
      } as Partial<GatewayConfig>;
      expect(() => validateConfig(config)).toThrow('"nonce.maxProofAge" must be between 30 and 86400 seconds');
    });

    it('throws on negative maxProofAge', () => {
      const config = {
        target: 'http://localhost:3000/mcp',
        nonce: { store: 'memory' as const, maxProofAge: -1 },
      } as Partial<GatewayConfig>;
      expect(() => validateConfig(config)).toThrow('"nonce.maxProofAge" must be between 30 and 86400 seconds');
    });

    it('throws on maxProofAge exceeding 86400', () => {
      const config = {
        target: 'http://localhost:3000/mcp',
        nonce: { store: 'memory' as const, maxProofAge: 100000 },
      } as Partial<GatewayConfig>;
      expect(() => validateConfig(config)).toThrow('"nonce.maxProofAge" must be between 30 and 86400 seconds');
    });

    it('passes on valid maxProofAge', () => {
      const config: GatewayConfig = {
        target: 'http://localhost:3000/mcp',
        port: 4100,
        network: 'base-sepolia',
        devMode: false,
        nonce: { store: 'memory', maxProofAge: 300 },
        receipts: { enabled: true, output: 'file', dir: './receipts/' },
        health: { enabled: true, path: '/healthz' },
      };
      expect(() => validateConfig(config)).not.toThrow();
    });

    it('throws on redis URL with http:// scheme', () => {
      const config = {
        target: 'http://localhost:3000/mcp',
        nonce: { store: 'redis' as const, redis: { url: 'http://localhost:6379' } },
      } as Partial<GatewayConfig>;
      expect(() => validateConfig(config)).toThrow('"nonce.redis.url" must use redis:// or rediss:// scheme');
    });

    it('passes on redis URL with redis:// scheme', () => {
      const config: GatewayConfig = {
        target: 'http://localhost:3000/mcp',
        port: 4100,
        network: 'base-sepolia',
        devMode: false,
        nonce: { store: 'redis', maxProofAge: 300, redis: { url: 'redis://localhost:6379' } },
        receipts: { enabled: true, output: 'file', dir: './receipts/' },
        health: { enabled: true, path: '/healthz' },
      };
      expect(() => validateConfig(config)).not.toThrow();
    });

    it('continues to accept memory store (regression)', () => {
      const config: GatewayConfig = {
        target: 'http://localhost:3000/mcp',
        port: 4100,
        network: 'base-sepolia',
        devMode: false,
        nonce: { store: 'memory', maxProofAge: 300 },
        receipts: { enabled: true, output: 'file', dir: './receipts/' },
        health: { enabled: true, path: '/healthz' },
      };
      expect(() => validateConfig(config)).not.toThrow();
    });
  });

  describe('mergeCliFlags', () => {
    it('CLI flags override config values', () => {
      const config: Partial<GatewayConfig> = {
        target: 'http://original:3000',
        port: 4100,
        devMode: false,
        receipts: { enabled: true, output: 'file', dir: './receipts/' },
      };
      const merged = mergeCliFlags(config, {
        target: 'http://override:5000',
        port: 8080,
        dev: true,
      });
      expect(merged.target).toBe('http://override:5000');
      expect(merged.port).toBe(8080);
      expect(merged.devMode).toBe(true);
    });

    it('--no-receipts disables receipts', () => {
      const config: Partial<GatewayConfig> = {
        target: 'http://localhost',
        receipts: { enabled: true, output: 'file', dir: './receipts/' },
      };
      const merged = mergeCliFlags(config, { noReceipts: true });
      expect(merged.receipts!.enabled).toBe(false);
    });

    it('--receipt-stdout switches to stdout mode', () => {
      const config: Partial<GatewayConfig> = {
        target: 'http://localhost',
        receipts: { enabled: true, output: 'file', dir: './receipts/' },
      };
      const merged = mergeCliFlags(config, { receiptStdout: true });
      expect(merged.receipts!.output).toBe('stdout');
      expect(merged.receipts!.enabled).toBe(true);
    });
  });

  describe('loadConfig', () => {
    it('applies defaults when no config file', () => {
      const config = loadConfig({
        config: path.join(tmpDir, 'nonexistent.yaml'),
        target: 'http://localhost:3000/mcp',
      });
      expect(config.port).toBe(4100);
      expect(config.network).toBe('base-sepolia');
      expect(config.devMode).toBe(false);
      expect(config.receipts.enabled).toBe(true);
      expect(config.health.path).toBe('/healthz');
      expect(config.nonce.maxProofAge).toBe(300);
    });

    it('loads from YAML and merges CLI', () => {
      const configPath = path.join(tmpDir, 'gateway.yaml');
      fs.writeFileSync(configPath, `
target: http://from-file:3000
port: 4200
`);
      const config = loadConfig({
        config: configPath,
        port: 9999,
      });
      expect(config.target).toBe('http://from-file:3000');
      expect(config.port).toBe(9999); // CLI overrides
    });
  });
});

describe('credentials config (v0.4.0 credential binding)', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gateway-creds-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  function baseConfig(overrides: Partial<GatewayConfig> = {}): Partial<GatewayConfig> {
    return {
      target: 'http://localhost:3000/mcp',
      devMode: true,
      ...overrides,
    };
  }

  describe('validateConfig', () => {
    it('accepts a static credentials section (number and string masks, optional expiry in dev)', () => {
      const config = baseConfig({
        credentials: {
          type: 'static',
          map: {
            '12345678': { permissionBitmask: 3 },
            '87654321': { permissionBitmask: '7', expiryTimestamp: '1893456000' },
          },
        },
      });
      expect(() => validateConfig(config)).not.toThrow();
    });

    it('rejects type: registry with a clear "not supported" message (fail closed, never silently ignored)', () => {
      const config = baseConfig({
        credentials: { type: 'registry', registryAddress: '0xabc', rpcUrl: 'https://rpc' } as never,
      });
      expect(() => validateConfig(config)).toThrow(ConfigValidationError);
      expect(() => validateConfig(config)).toThrow(/registry.*not.*supported/i);
    });

    it('rejects non-decimal permission masks and map keys', () => {
      expect(() => validateConfig(baseConfig({
        credentials: { type: 'static', map: { '12345678': { permissionBitmask: 'not-a-number' } } },
      }))).toThrow(/permissionBitmask/);
      expect(() => validateConfig(baseConfig({
        credentials: { type: 'static', map: { '0xdeadbeef': { permissionBitmask: 3 } } },
      }))).toThrow(/decimal/);
    });

    it('rejects an empty static map (configured-but-empty must not silently disable binding)', () => {
      expect(() => validateConfig(baseConfig({
        credentials: { type: 'static', map: {} },
      }))).toThrow(/at least one/i);
    });

    it('requires expiryTimestamp per entry when devMode is false (needed for scopeCommitment binding)', () => {
      const config = baseConfig({
        devMode: false,
        credentials: { type: 'static', map: { '12345678': { permissionBitmask: 3 } } },
      });
      expect(() => validateConfig(config)).toThrow(/expiryTimestamp/);
    });
  });

  describe('--credentials <path> flag', () => {
    it('loads a bare-map credentials file and overrides config.credentials', () => {
      const credsPath = path.join(tmpDir, 'credentials.yaml');
      fs.writeFileSync(credsPath, `
"12345678":
  permissionBitmask: 3
`);
      const config = loadConfig({
        config: path.join(tmpDir, 'nonexistent.yaml'),
        target: 'http://localhost:3000/mcp',
        dev: true,
        credentials: credsPath,
      });
      expect(config.credentials).toEqual({
        type: 'static',
        map: { '12345678': { permissionBitmask: 3 } },
      });
    });

    it('also accepts the full credentials-section shape in the file', () => {
      const credsPath = path.join(tmpDir, 'credentials.json');
      fs.writeFileSync(credsPath, JSON.stringify({
        type: 'static',
        map: { '12345678': { permissionBitmask: '3', expiryTimestamp: '1893456000' } },
      }));
      const config = loadConfig({
        config: path.join(tmpDir, 'nonexistent.yaml'),
        target: 'http://localhost:3000/mcp',
        dev: true,
        credentials: credsPath,
      });
      expect(config.credentials!.type).toBe('static');
      expect((config.credentials as { map: Record<string, unknown> }).map['12345678']).toBeDefined();
    });

    it('errors when the flag points at a missing file (explicit flag must not fail open)', () => {
      expect(() => loadConfig({
        config: path.join(tmpDir, 'nonexistent.yaml'),
        target: 'http://localhost:3000/mcp',
        dev: true,
        credentials: path.join(tmpDir, 'missing-credentials.yaml'),
      })).toThrow(/credentials/i);
    });
  });
});

describe('credentials config — unsafe numbers (Codex P2)', () => {
  it('rejects numeric masks/expiries above Number.MAX_SAFE_INTEGER (YAML rounds them silently)', () => {
    const base = { target: 'http://localhost:3000/mcp', devMode: true };
    expect(() => validateConfig({
      ...base,
      credentials: { type: 'static', map: { '12345678': { permissionBitmask: 2 ** 53 } } },
    })).toThrow(/permissionBitmask/);
    expect(() => validateConfig({
      ...base,
      credentials: { type: 'static', map: { '12345678': { permissionBitmask: 3, expiryTimestamp: 2 ** 60 } } },
    })).toThrow(/expiryTimestamp/);
    // Big values as decimal STRINGS stay exact and are fine up to uint64.
    expect(() => validateConfig({
      ...base,
      credentials: { type: 'static', map: { '12345678': { permissionBitmask: '3', expiryTimestamp: '18446744073709551615' } } },
    })).not.toThrow();
  });
});

describe('credentials config — canonical commitment keys (Codex round-2 P2)', () => {
  it('rejects non-canonical decimal keys (leading zeros) that would silently collide after normalization', () => {
    const base = { target: 'http://localhost:3000/mcp', devMode: true };
    expect(() => validateConfig({
      ...base,
      credentials: { type: 'static', map: { '001': { permissionBitmask: 3 } } },
    })).toThrow(/canonical/);
    // "1" and "001" both validating would let one silently overwrite the
    // other in the registry while the banner counts both.
    expect(() => validateConfig({
      ...base,
      credentials: { type: 'static', map: { '1': { permissionBitmask: 3 }, '001': { permissionBitmask: 255 } } },
    })).toThrow(/canonical/);
    expect(() => validateConfig({
      ...base,
      credentials: { type: 'static', map: { '0': { permissionBitmask: 1 }, '10': { permissionBitmask: 3 } } },
    })).not.toThrow();
  });
});

describe('credentials config — circuit semantics (Codex round-3 P2)', () => {
  const base = { target: 'http://localhost:3000/mcp', devMode: true };

  it('rejects masks/expiries outside uint64 (AgentPolicy/Delegation are 64-bit)', () => {
    expect(() => validateConfig({
      ...base,
      credentials: { type: 'static', map: { '12345678': { permissionBitmask: '18446744073709551616' } } },
    })).toThrow(/uint64/);
    expect(() => validateConfig({
      ...base,
      credentials: { type: 'static', map: { '12345678': { permissionBitmask: 3, expiryTimestamp: '18446744073709551616' } } },
    })).toThrow(/uint64/);
  });

  it('rejects masks that violate the cumulative-bit encoding the circuits enforce', () => {
    // 16 = FINANCIAL_UNLIMITED (bit 4) without FINANCIAL_SMALL/MEDIUM —
    // createAgentCredential and the circuits both reject this shape.
    expect(() => validateConfig({
      ...base,
      credentials: { type: 'static', map: { '12345678': { permissionBitmask: 16 } } },
    })).toThrow(/cumulative/);
    // 8 = FINANCIAL_MEDIUM (bit 3) without FINANCIAL_SMALL (bit 2).
    expect(() => validateConfig({
      ...base,
      credentials: { type: 'static', map: { '12345678': { permissionBitmask: 8 } } },
    })).toThrow(/cumulative/);
    // 28 = FINANCIAL_* stack (bits 2+3+4) — valid cumulative shape.
    expect(() => validateConfig({
      ...base,
      credentials: { type: 'static', map: { '12345678': { permissionBitmask: 28 } } },
    })).not.toThrow();
  });
});
