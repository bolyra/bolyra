/**
 * Mock X MCP server for demo purposes.
 * Simulates X's xurl MCP tool surface over stdio JSON-RPC.
 */
import * as readline from 'readline';

const TOOLS = [
  { name: 'search_recent_posts', description: 'Search recent posts', inputSchema: { type: 'object', properties: { query: { type: 'string' } } } },
  { name: 'get_user_by_username', description: 'Get user by username', inputSchema: { type: 'object', properties: { username: { type: 'string' } } } },
  { name: 'get_me', description: 'Get current authenticated user', inputSchema: { type: 'object' } },
  { name: 'get_bookmarks', description: 'List bookmarks', inputSchema: { type: 'object' } },
  { name: 'add_bookmark', description: 'Add a bookmark', inputSchema: { type: 'object', properties: { post_id: { type: 'string' } } } },
  { name: 'remove_bookmark', description: 'Remove a bookmark', inputSchema: { type: 'object', properties: { post_id: { type: 'string' } } } },
  { name: 'create_article', description: 'Create and publish an article', inputSchema: { type: 'object', properties: { title: { type: 'string' }, body: { type: 'string' } } } },
];

const MOCK_RESPONSES: Record<string, (args: any) => string> = {
  search_recent_posts: (args) => JSON.stringify({ posts: [{ id: '1', text: `Mock result for "${args?.query ?? 'test'}"`, author: '@demo_user' }] }),
  get_user_by_username: (args) => JSON.stringify({ user: { id: '42', username: args?.username ?? 'unknown', name: 'Demo User' } }),
  get_me: () => JSON.stringify({ user: { id: '1', username: 'bolyra_demo', name: 'Bolyra Demo' } }),
  get_bookmarks: () => JSON.stringify({ bookmarks: [{ post_id: '100', text: 'Bookmarked post' }] }),
  add_bookmark: (args) => JSON.stringify({ success: true, post_id: args?.post_id ?? '0' }),
  remove_bookmark: (args) => JSON.stringify({ success: true, post_id: args?.post_id ?? '0' }),
  create_article: (args) => JSON.stringify({ success: true, article_id: 'art_001', title: args?.title ?? 'Untitled' }),
};

const rl = readline.createInterface({ input: process.stdin });

rl.on('line', (line: string) => {
  let msg: any;
  try { msg = JSON.parse(line); } catch { return; }

  if (msg.method === 'initialize') {
    process.stdout.write(JSON.stringify({
      jsonrpc: '2.0', id: msg.id,
      result: {
        protocolVersion: '2025-03-26',
        serverInfo: { name: 'mock-x-server', version: '0.1.0' },
        capabilities: { tools: {} },
      },
    }) + '\n');
  } else if (msg.method === 'tools/list') {
    process.stdout.write(JSON.stringify({
      jsonrpc: '2.0', id: msg.id,
      result: { tools: TOOLS },
    }) + '\n');
  } else if (msg.method === 'tools/call') {
    const toolName = msg.params?.name ?? '';
    const args = msg.params?.arguments ?? {};
    const handler = MOCK_RESPONSES[toolName];
    if (handler) {
      process.stdout.write(JSON.stringify({
        jsonrpc: '2.0', id: msg.id,
        result: { content: [{ type: 'text', text: handler(args) }] },
      }) + '\n');
    } else {
      process.stdout.write(JSON.stringify({
        jsonrpc: '2.0', id: msg.id,
        result: { content: [{ type: 'text', text: `executed ${toolName}` }] },
      }) + '\n');
    }
  }
});
