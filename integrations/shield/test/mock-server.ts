/**
 * Minimal stdio MCP server for testing @bolyra/shield.
 * Reads JSON-RPC from stdin, responds on stdout.
 */
import * as readline from 'readline';

const rl = readline.createInterface({ input: process.stdin });

rl.on('line', (line: string) => {
  let msg: any;
  try { msg = JSON.parse(line); } catch { return; }

  if (msg.method === 'initialize') {
    process.stdout.write(JSON.stringify({
      jsonrpc: '2.0', id: msg.id,
      result: {
        protocolVersion: '2025-03-26',
        serverInfo: { name: 'mock-server', version: '0.1.0' },
        capabilities: { tools: {} },
      },
    }) + '\n');
  } else if (msg.method === 'tools/list') {
    process.stdout.write(JSON.stringify({
      jsonrpc: '2.0', id: msg.id,
      result: { tools: [
        { name: 'read_file', description: 'Read a file', inputSchema: { type: 'object' } },
        { name: 'write_file', description: 'Write a file', inputSchema: { type: 'object' } },
      ] },
    }) + '\n');
  } else if (msg.method === 'tools/call') {
    process.stdout.write(JSON.stringify({
      jsonrpc: '2.0', id: msg.id,
      result: { content: [{ type: 'text', text: `executed ${msg.params?.name}` }] },
    }) + '\n');
  }
});
