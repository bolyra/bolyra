/**
 * Bolyra-injecting MCP proxy (stdio ↔ stdio).
 *
 * Sits between an unmodified MCP host (Claude Desktop / Claude Code) and a
 * Bolyra-protected upstream MCP server. For every `tools/call` request the
 * proxy generates a fresh Bolyra handshake proof and merges it into
 * `params._meta.bolyra` so the upstream's withBolyraAuth gate accepts the
 * call. All other JSON-RPC messages pass through unchanged.
 *
 *   Claude Desktop ──vanilla MCP──► bolyra-proxy ──MCP+_meta.bolyra──► server-fixed
 *
 * Env vars:
 *   BOLYRA_UPSTREAM_SCRIPT  Absolute path to upstream node script.
 *                           Defaults to ./server-fixed.js next to this file.
 */

import { spawn } from 'child_process';
import * as path from 'path';
import { attachBolyraProof } from '@bolyra/mcp';
import { loadDemoIdentities, DEMO_SDK_CONFIG } from './shared';

async function main() {
  const upstreamScript =
    process.env.BOLYRA_UPSTREAM_SCRIPT ??
    path.resolve(__dirname, 'server-fixed.js');

  process.stderr.write('[bolyra-proxy] loading demo identities...\n');
  const { human, credential } = await loadDemoIdentities();
  process.stderr.write(
    `[bolyra-proxy] spawning upstream: node ${upstreamScript}\n`,
  );

  const child = spawn('node', [upstreamScript], {
    stdio: ['pipe', 'pipe', 'inherit'],
  });

  child.on('exit', (code, signal) => {
    process.stderr.write(
      `[bolyra-proxy] upstream exited code=${code} signal=${signal}\n`,
    );
    process.exit(code ?? 0);
  });

  child.on('error', (err) => {
    process.stderr.write(`[bolyra-proxy] upstream spawn error: ${err}\n`);
    process.exit(1);
  });

  const writeUpstream = (msg: unknown) =>
    child.stdin!.write(JSON.stringify(msg) + '\n');
  const writeHost = (msg: unknown) =>
    process.stdout.write(JSON.stringify(msg) + '\n');

  // Inbound: host → proxy → (maybe inject) → upstream.
  let hostBuf = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', async (chunk) => {
    hostBuf += chunk;
    let nl: number;
    while ((nl = hostBuf.indexOf('\n')) >= 0) {
      const line = hostBuf.slice(0, nl);
      hostBuf = hostBuf.slice(nl + 1);
      if (!line.trim()) continue;

      let msg: any;
      try {
        msg = JSON.parse(line);
      } catch (err) {
        process.stderr.write(
          `[bolyra-proxy] bad inbound JSON, dropping: ${err}\n`,
        );
        continue;
      }

      if (msg && msg.method === 'tools/call') {
        const toolName = msg.params?.name ?? '<unknown>';
        try {
          const t0 = Date.now();
          const auth = await attachBolyraProof(
            human,
            credential,
            DEMO_SDK_CONFIG,
          );
          process.stderr.write(
            `[bolyra-proxy] proof for ${toolName} in ${Date.now() - t0}ms\n`,
          );
          msg.params = { ...(msg.params ?? {}) };
          msg.params._meta = {
            ...(msg.params._meta ?? {}),
            bolyra: auth.meta.bolyra,
          };
        } catch (err: unknown) {
          const message =
            err instanceof Error ? err.message : String(err);
          process.stderr.write(
            `[bolyra-proxy] proof generation failed: ${message}\n`,
          );
          writeHost({
            jsonrpc: '2.0',
            id: msg.id,
            error: {
              code: -32000,
              message: `Bolyra proof generation failed: ${message}`,
            },
          });
          continue;
        }
      }

      writeUpstream(msg);
    }
  });

  // Outbound: upstream → proxy → host (verbatim).
  let upBuf = '';
  child.stdout!.setEncoding('utf8');
  child.stdout!.on('data', (chunk: string) => {
    upBuf += chunk;
    let nl: number;
    while ((nl = upBuf.indexOf('\n')) >= 0) {
      const line = upBuf.slice(0, nl);
      upBuf = upBuf.slice(nl + 1);
      if (!line.trim()) continue;
      process.stdout.write(line + '\n');
    }
  });

  process.stdin.on('end', () => {
    child.stdin!.end();
  });
}

main().catch((err) => {
  process.stderr.write(`[bolyra-proxy] fatal: ${err}\n`);
  process.exit(1);
});
