import { spawn } from 'child_process';
import * as fs from 'fs';
import * as readline from 'readline';
import { stringify as stringifyYaml } from 'yaml';
import { splitCommand } from './command';

export interface LearnedTool {
  name: string;
  description?: string;
}

export interface LearnOptions {
  server: string;
  outPath: string;
  /** Overall deadline for the whole discovery handshake. */
  timeoutMs?: number;
  /** Hard cap on tools/list pages — a malicious server can't paginate forever. */
  maxPages?: number;
}

export interface LearnResult {
  tools: LearnedTool[];
  outPath: string;
}

const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_PAGES = 50;
const READ_DATA_BITMASK = 1;

export async function learn(opts: LearnOptions): Promise<LearnResult> {
  // Fail fast; the O_EXCL flag on the write below is the atomic guarantee.
  if (fs.existsSync(opts.outPath)) {
    throw new Error(`${opts.outPath} already exists — refusing to overwrite. Move it aside and re-run.`);
  }

  const tools = await discoverTools(
    opts.server,
    opts.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    opts.maxPages ?? DEFAULT_MAX_PAGES,
  );

  const doc = {
    _generated: {
      by: '@bolyra/shield --learn',
      server: opts.server,
      date: new Date().toISOString(),
      note: 'Every tool starts at READ_DATA (requireBitmask: 1). Review and raise per-tool requirements before production use.',
    },
    defaultDeny: true,
    tools: Object.fromEntries(
      tools.map(t => [t.name, { requireBitmask: READ_DATA_BITMASK }]),
    ),
  };

  fs.writeFileSync(opts.outPath, stringifyYaml(doc), { flag: 'wx' });
  return { tools, outPath: opts.outPath };
}

function discoverTools(server: string, timeoutMs: number, maxPages: number): Promise<LearnedTool[]> {
  return new Promise((resolve, reject) => {
    const [cmd, ...args] = splitCommand(server);
    const child = spawn(cmd, args, { stdio: ['pipe', 'pipe', 'inherit'] });
    const rl = readline.createInterface({ input: child.stdout! });

    const tools: LearnedTool[] = [];
    const pending = new Map<number, (result: any) => void>();
    let nextId = 1;
    let settled = false;

    // Every exit path funnels through here so the child never outlives discovery.
    const finish = (err: Error | null, value?: LearnedTool[]) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      rl.close();
      child.kill('SIGTERM');
      if (err) reject(err);
      else resolve(value!);
    };

    const timer = setTimeout(
      () => finish(new Error(`Discovery timed out after ${timeoutMs}ms — server never completed the handshake`)),
      timeoutMs,
    );

    child.on('error', err => finish(new Error(`Failed to spawn server: ${err.message}`)));
    child.on('exit', code => finish(new Error(`Server exited (code ${code ?? 'null'}) before discovery completed`)));

    rl.on('line', (line: string) => {
      let msg: any;
      try { msg = JSON.parse(line); } catch { return; }
      const resolver = pending.get(msg.id);
      if (!resolver) return;
      pending.delete(msg.id);
      if (msg.error) {
        finish(new Error(`Server returned error for request ${msg.id}: ${msg.error.message}`));
        return;
      }
      resolver(msg.result);
    });

    function send(method: string, params: Record<string, unknown>): Promise<any> {
      const id = nextId++;
      return new Promise(res => {
        pending.set(id, res);
        child.stdin!.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
      });
    }

    (async () => {
      await send('initialize', {
        protocolVersion: '2025-03-26',
        clientInfo: { name: '@bolyra/shield', version: 'learn' },
        capabilities: {},
      });
      child.stdin!.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');

      let cursor: string | undefined;
      let pages = 0;
      do {
        pages++;
        if (pages > maxPages) {
          finish(new Error(`tools/list pagination exceeded ${maxPages} pages — refusing to continue`));
          return;
        }
        const result = await send('tools/list', cursor ? { cursor } : {});
        for (const t of result?.tools ?? []) {
          if (typeof t?.name === 'string' && t.name.length > 0) {
            tools.push({ name: t.name, ...(t.description ? { description: t.description } : {}) });
          }
        }
        cursor = typeof result?.nextCursor === 'string' ? result.nextCursor : undefined;
      } while (cursor);

      finish(null, tools);
    })().catch(err => finish(err as Error));
  });
}
