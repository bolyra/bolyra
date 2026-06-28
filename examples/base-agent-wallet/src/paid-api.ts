/**
 * Mock x402 paid API server.
 *
 * Returns 402 Payment Required with x402 payment requirements,
 * or 200 with data if payment proof is attached.
 */
import * as http from 'http';

const PORT = parseInt(process.env.API_PORT ?? '3300', 10);

interface X402Requirements {
  scheme: 'x402';
  network: 'base-sepolia';
  asset: 'USDC';
  amount: string;       // in cents
  recipient: string;
  description: string;
}

const ENDPOINTS: Record<string, { price: number; desc: string; data: any }> = {
  '/research/nvda': {
    price: 50, desc: 'NVDA earnings analysis',
    data: { ticker: 'NVDA', rating: 'Strong Buy', targetPrice: '$185', catalyst: 'Data center revenue +82% YoY', confidence: 0.91 },
  },
  '/research/btc': {
    price: 25, desc: 'BTC market summary',
    data: { ticker: 'BTC', price: '$68,421', trend: 'Bullish', support: '$64,200', resistance: '$71,800', sentiment: 0.74 },
  },
  '/compute/gpu-hour': {
    price: 100, desc: '1 hour GPU inference (A100)',
    data: { instanceId: 'gpu-' + Date.now().toString(36), type: 'A100-80GB', duration: '1h', status: 'provisioned', endpoint: 'https://gpu.example.com/run' },
  },
  '/data/market-feed': {
    price: 10, desc: 'Real-time market data feed (1h)',
    data: { feedId: 'mkt-' + Date.now().toString(36), symbols: ['AAPL', 'NVDA', 'TSLA', 'ETH', 'BTC'], resolution: '1s', expires: '1h' },
  },
  '/premium/report': {
    price: 500, desc: 'Premium sector analysis report',
    data: { reportId: 'rpt-premium', title: 'AI Infrastructure Investment Thesis 2026', pages: 42 },
  },
};

const server = http.createServer((req, res) => {
  const endpoint = ENDPOINTS[req.url ?? ''];

  if (!endpoint) {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not found', available: Object.keys(ENDPOINTS) }));
    return;
  }

  // Check for payment proof
  const paymentProof = req.headers['x-402-payment'];

  if (!paymentProof) {
    // Return 402 with x402 requirements
    const requirements: X402Requirements = {
      scheme: 'x402',
      network: 'base-sepolia',
      asset: 'USDC',
      amount: String(endpoint.price),
      recipient: '0xVendor7f3a...8bDe',
      description: endpoint.desc,
    };

    res.writeHead(402, {
      'Content-Type': 'application/json',
      'X-402-Requirements': JSON.stringify(requirements),
    });
    res.end(JSON.stringify({
      error: 'Payment Required',
      requirements,
      message: `This endpoint costs $${(endpoint.price / 100).toFixed(2)} USDC. Include X-402-Payment header.`,
    }));
    return;
  }

  // Payment proof present — return data
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({
    data: endpoint.data,
    payment: { verified: true, amount: endpoint.price, asset: 'USDC', network: 'base-sepolia' },
  }));
});

server.listen(PORT, () => {
  console.log(`x402 Paid API server on http://localhost:${PORT}`);
  console.log(`Endpoints: ${Object.entries(ENDPOINTS).map(([k, v]) => `${k} ($${(v.price / 100).toFixed(2)})`).join(', ')}`);
});

export { server, PORT };
