// examples/robinhood-demo/src/mock-robinhood-mcp.ts
import * as http from 'http';

const PORT = parseInt(process.env.MOCK_PORT ?? '3100', 10);

// -- Mock tool responses ----------------------------------------------------

const MOCK_PORTFOLIO = {
  equity: '48,231.56',
  total_return: '+12.4%',
  positions: [
    { symbol: 'AAPL', quantity: 50, avg_cost: 178.32, current_price: 198.45 },
    { symbol: 'NVDA', quantity: 30, avg_cost: 420.10, current_price: 512.88 },
    { symbol: 'TSLA', quantity: 20, avg_cost: 245.00, current_price: 267.33 },
  ],
};

const MOCK_ACCOUNTS = [
  { account_number: 'XXXX1234', type: 'individual', buying_power: '5,420.00' },
  { account_number: 'XXXX5678', type: 'agentic', buying_power: '1,000.00' },
];

const MOCK_QUOTE = (symbol: string) => ({
  symbol,
  last_trade_price: '198.45',
  bid_price: '198.40',
  ask_price: '198.50',
  previous_close: '196.20',
  updated_at: new Date().toISOString(),
});

const MOCK_ORDER_RESULT = (params: Record<string, unknown>) => ({
  order_id: `ORD-${Date.now()}`,
  symbol: params.symbol ?? 'AAPL',
  side: params.side ?? 'buy',
  quantity: params.quantity ?? 1,
  type: params.type ?? 'market',
  status: 'confirmed',
  estimated_price: '198.45',
  timestamp: new Date().toISOString(),
});

// -- Tool handler registry --------------------------------------------------

type ToolHandler = (params: Record<string, unknown>) => unknown;

const TOOLS: Record<string, ToolHandler> = {
  robinhood_check_session: () => ({ authenticated: true, expires_in: '8h' }),
  robinhood_get_portfolio: () => MOCK_PORTFOLIO,
  robinhood_get_accounts: () => MOCK_ACCOUNTS,
  robinhood_get_account: (p) =>
    MOCK_ACCOUNTS.find((a) =>
      a.account_number.includes(String(p.account_id ?? '1234'))
    ) ?? MOCK_ACCOUNTS[0],
  robinhood_get_stock_quote: (p) => MOCK_QUOTE(String(p.symbol ?? 'AAPL')),
  robinhood_get_historicals: (p) => ({
    symbol: p.symbol,
    interval: p.interval ?? '1d',
    data: [
      { date: '2026-06-20', close: '196.20' },
      { date: '2026-06-21', close: '198.45' },
    ],
  }),
  robinhood_get_news: (p) => ({
    symbol: p.symbol,
    articles: [
      {
        title: `${p.symbol} hits new high`,
        source: 'Reuters',
        date: '2026-06-21',
      },
    ],
  }),
  robinhood_get_movers: () => ({
    gainers: [{ symbol: 'NVDA', change: '+3.2%' }],
    losers: [{ symbol: 'INTC', change: '-1.8%' }],
  }),
  robinhood_get_options: (p) => ({
    symbol: p.symbol,
    expiration: '2026-07-18',
    calls: [{ strike: 200, premium: 5.4 }],
    puts: [{ strike: 195, premium: 3.2 }],
  }),
  robinhood_get_crypto: (p) => ({
    symbol: p.symbol ?? 'BTC',
    price: '68,421.00',
    change_24h: '+2.1%',
  }),
  robinhood_place_stock_order: (p) => MOCK_ORDER_RESULT(p),
  robinhood_place_option_order: (p) => ({
    ...MOCK_ORDER_RESULT(p),
    type: 'option',
    contract: p.contract,
  }),
  robinhood_place_crypto_order: (p) => ({
    ...MOCK_ORDER_RESULT(p),
    asset: p.symbol ?? 'BTC',
  }),
  robinhood_get_orders: () => ({
    orders: [
      {
        order_id: 'ORD-001',
        symbol: 'AAPL',
        side: 'buy',
        status: 'filled',
        quantity: 10,
      },
    ],
  }),
  robinhood_cancel_order: (p) => ({
    order_id: p.order_id,
    status: 'cancelled',
  }),
  robinhood_get_order_status: (p) => ({
    order_id: p.order_id,
    status: 'filled',
    filled_at: '2026-06-21T10:30:00Z',
  }),
  robinhood_search: (p) => ({
    results: [
      {
        symbol: String(p.query).toUpperCase(),
        name: `${p.query} Inc.`,
        type: 'stock',
      },
    ],
  }),
  robinhood_browser_login: () => ({
    error: 'Browser login is not available in mock mode',
  }),
};

// -- JSON-RPC server --------------------------------------------------------

function handleJsonRpc(body: {
  method: string;
  params?: Record<string, unknown>;
  id?: string | number;
}): unknown {
  if (body.method === 'initialize') {
    return {
      protocolVersion: '2025-03-26',
      serverInfo: { name: 'mock-robinhood', version: '0.7.0' },
      capabilities: { tools: {} },
    };
  }
  if (body.method === 'tools/list') {
    return {
      tools: Object.keys(TOOLS).map((name) => ({
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
    return {
      content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
    };
  }
  if (body.method === 'notifications/initialized' || body.method === 'ping') {
    return { ok: true };
  }
  return { error: { code: -32601, message: `Unknown method: ${body.method}` } };
}

const server = http.createServer((req, res) => {
  let data = '';
  req.on('data', (chunk: Buffer) => {
    data += chunk.toString();
  });
  req.on('end', () => {
    try {
      const body = JSON.parse(data);
      const result = handleJsonRpc(body);
      const response = { jsonrpc: '2.0', id: body.id ?? null, result };
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(response));
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          jsonrpc: '2.0',
          id: null,
          error: { code: -32700, message: 'Parse error' },
        })
      );
    }
  });
});

server.listen(PORT, () => {
  console.log(
    `Mock Robinhood MCP server listening on http://localhost:${PORT}`
  );
});

export { server, PORT };
