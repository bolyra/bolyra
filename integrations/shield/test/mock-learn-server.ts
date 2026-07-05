/**
 * Configurable stdio MCP server for testing @bolyra/shield --learn.
 * Mode via argv[2]:
 *   single    — one tools/list page with read_file + write_file
 *   paginated — read_file on page 1 (nextCursor), write_file on page 2
 *   infinite  — every tools/list response carries a nextCursor (never terminates)
 *   silent    — answers initialize, never answers tools/list
 */
import * as readline from 'readline';

const mode = process.argv[2] ?? 'single';
const rl = readline.createInterface({ input: process.stdin });

function reply(id: any, result: any) {
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, result }) + '\n');
}

const READ_TOOL = { name: 'read_file', description: 'Read a file', inputSchema: { type: 'object' } };
const WRITE_TOOL = { name: 'write_file', description: 'Write a file', inputSchema: { type: 'object' } };

let infinitePage = 0;

rl.on('line', (line: string) => {
  let msg: any;
  try { msg = JSON.parse(line); } catch { return; }

  if (msg.method === 'initialize') {
    reply(msg.id, {
      protocolVersion: '2025-03-26',
      serverInfo: { name: 'mock-learn-server', version: '0.1.0' },
      capabilities: { tools: {} },
    });
  } else if (msg.method === 'tools/list') {
    if (mode === 'silent') return;
    if (mode === 'single') {
      reply(msg.id, { tools: [READ_TOOL, WRITE_TOOL] });
    } else if (mode === 'paginated') {
      if (msg.params?.cursor === 'page2') {
        reply(msg.id, { tools: [WRITE_TOOL] });
      } else {
        reply(msg.id, { tools: [READ_TOOL], nextCursor: 'page2' });
      }
    } else if (mode === 'infinite') {
      infinitePage++;
      reply(msg.id, {
        tools: [{ name: `tool_${infinitePage}`, description: 'endless', inputSchema: { type: 'object' } }],
        nextCursor: `page${infinitePage + 1}`,
      });
    }
  }
});
