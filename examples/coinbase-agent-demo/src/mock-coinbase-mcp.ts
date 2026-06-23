/**
 * Mock Coinbase AgentKit MCP server for demo purposes.
 *
 * Simulates a Coinbase agent account on Base with:
 * - Wallet balance and portfolio
 * - Token transfers (ETH, USDC)
 * - Token swaps (via Uniswap)
 * - x402 paid API calls
 *
 * No real Coinbase API keys needed. Returns realistic mock data.
 */
import * as http from 'http';

const PORT = parseInt(process.env.MOCK_PORT ?? '3200', 10);

const MOCK_WALLET = {
  address: '0x742d35Cc6634C0532925a3b844Bc9e7595f8bDe7',
  network: 'base-sepolia',
  balances: {
    ETH: '2.4531',
    USDC: '1,250.00',
    cbBTC: '0.0832',
  },
};

const MOCK_PORTFOLIO = {
  totalValue: '$3,891.24',
  positions: [
    { asset: 'ETH', amount: '2.4531', value: '$2,453.10', change24h: '+3.2%' },
    { asset: 'USDC', amount: '1,250.00', value: '$1,250.00', change24h: '0.0%' },
    { asset: 'cbBTC', amount: '0.0832', value: '$188.14', change24h: '-1.1%' },
  ],
};

type ToolHandler = (params: Record<string, unknown>) => unknown;

const TOOLS: Record<string, ToolHandler> = {
  // Read-only
  get_wallet_balance: () => MOCK_WALLET.balances,
  get_portfolio: () => MOCK_PORTFOLIO,
  get_wallet_address: () => ({ address: MOCK_WALLET.address, network: MOCK_WALLET.network }),
  get_token_price: (p) => ({
    token: p.token ?? 'ETH',
    price: p.token === 'USDC' ? '$1.00' : p.token === 'cbBTC' ? '$2,261.00' : '$1,000.45',
    network: 'base-sepolia',
  }),
  get_transaction_history: () => ({
    transactions: [
      { type: 'transfer', token: 'USDC', amount: '50.00', to: '0xabc...def', timestamp: '2026-06-22T14:30:00Z' },
      { type: 'swap', from: 'ETH', to: 'USDC', amount: '0.5', received: '500.22', timestamp: '2026-06-22T10:15:00Z' },
    ],
  }),

  // Transfers (financial)
  transfer_token: (p) => ({
    txHash: `0x${Date.now().toString(16)}abcdef`,
    token: p.token ?? 'USDC',
    amount: p.amount ?? '0',
    to: p.to ?? '0x0000',
    status: 'confirmed',
    network: 'base-sepolia',
    timestamp: new Date().toISOString(),
  }),

  // Swaps (financial)
  swap_tokens: (p) => ({
    txHash: `0x${Date.now().toString(16)}fedcba`,
    from: p.fromToken ?? 'ETH',
    to: p.toToken ?? 'USDC',
    amountIn: p.amount ?? '0',
    amountOut: '500.22',
    protocol: 'Uniswap V3',
    status: 'confirmed',
    network: 'base-sepolia',
    timestamp: new Date().toISOString(),
  }),

  // x402 paid API call
  pay_for_api: (p) => ({
    paymentHash: `0x${Date.now().toString(16)}402402`,
    amount: p.amount ?? '0',
    currency: p.currency ?? 'USDC',
    recipient: p.recipient ?? '0xvendor',
    purpose: p.purpose ?? 'API access',
    status: 'paid',
    timestamp: new Date().toISOString(),
  }),

  // Deploy contract (high-privilege)
  deploy_contract: (p) => ({
    contractAddress: `0x${Date.now().toString(16)}deploy`,
    bytecodeHash: '0xabcdef...',
    network: 'base-sepolia',
    status: 'deployed',
    timestamp: new Date().toISOString(),
  }),
};

function handleJsonRpc(body: { method: string; params?: Record<string, unknown>; id?: string | number }): unknown {
  if (body.method === 'initialize') {
    return {
      protocolVersion: '2025-03-26',
      serverInfo: { name: 'mock-coinbase-agent', version: '0.1.0' },
      capabilities: { tools: {} },
    };
  }
  if (body.method === 'tools/list') {
    return {
      tools: Object.keys(TOOLS).map(name => ({
        name,
        description: `Mock ${name}`,
        inputSchema: { type: 'object', properties: {} },
      })),
    };
  }
  if (body.method === 'tools/call') {
    const toolName = body.params?.name as string;
    const toolArgs = (body.params?.arguments ?? {}) as Record<string, unknown>;
    const handler = TOOLS[toolName];
    if (!handler) {
      return { error: { code: -32601, message: `Unknown tool: ${toolName}` } };
    }
    const result = handler(toolArgs);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  }
  if (body.method === 'notifications/initialized' || body.method === 'ping') {
    return { ok: true };
  }
  return { error: { code: -32601, message: `Unknown method: ${body.method}` } };
}

const server = http.createServer((req, res) => {
  let data = '';
  req.on('data', (chunk: Buffer) => { data += chunk.toString(); });
  req.on('end', () => {
    try {
      const body = JSON.parse(data);
      const result = handleJsonRpc(body);
      const response = { jsonrpc: '2.0', id: body.id ?? null, result };
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(response));
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }));
    }
  });
});

server.listen(PORT, () => {
  console.log(`Mock Coinbase Agent MCP server on http://localhost:${PORT}`);
});

export { server, PORT };
