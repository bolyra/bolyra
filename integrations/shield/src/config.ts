import * as fs from 'fs';
import * as path from 'path';
import { parse as parseYaml } from 'yaml';

export interface ShieldToolPolicy {
  requireBitmask?: number;
  minScore?: number;
  maxChainDepth?: number;
}

export interface ShieldConfig {
  server: string;
  devMode: boolean;
  network: string;
  nonce: { store: 'memory'; maxProofAge: number };
  receipts: { enabled: boolean; output: 'stderr' | 'file'; dir?: string };
  tools: Record<string, ShieldToolPolicy>;
}

const DEFAULTS: ShieldConfig = {
  server: '',
  devMode: false,
  network: 'base-sepolia',
  nonce: { store: 'memory', maxProofAge: 300 },
  receipts: { enabled: true, output: 'stderr' },
  tools: {},
};

function substituteEnvVars(obj: any): any {
  if (typeof obj === 'string') {
    return obj.replace(/\$\{([^}]+)\}/g, (_m: string, v: string) => process.env[v] ?? `\${${v}}`);
  }
  if (Array.isArray(obj)) return obj.map(substituteEnvVars);
  if (obj !== null && typeof obj === 'object') {
    const r: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj)) r[k] = substituteEnvVars(v);
    return r;
  }
  return obj;
}

export function loadShieldConfig(configPath: string, cliServer?: string): ShieldConfig {
  let fileConfig: Record<string, any> = {};
  const resolved = path.resolve(configPath);
  if (fs.existsSync(resolved)) {
    const raw = fs.readFileSync(resolved, 'utf-8');
    fileConfig = substituteEnvVars(parseYaml(raw) ?? {});
  }

  const config: ShieldConfig = {
    ...DEFAULTS,
    ...fileConfig,
    nonce: { ...DEFAULTS.nonce, ...(fileConfig.nonce ?? {}) },
    receipts: { ...DEFAULTS.receipts, ...(fileConfig.receipts ?? {}) },
    tools: fileConfig.tools ?? {},
  };

  if (cliServer) config.server = cliServer;

  if (!config.server) {
    throw new Error('@bolyra/shield: --server is required (command to spawn the MCP server)');
  }

  return config;
}
