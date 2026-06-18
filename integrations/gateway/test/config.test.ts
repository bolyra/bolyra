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
