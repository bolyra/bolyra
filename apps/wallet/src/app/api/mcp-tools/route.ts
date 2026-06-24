import { NextRequest, NextResponse } from 'next/server';

export async function GET(req: NextRequest) {
  const url = req.nextUrl.searchParams.get('url');
  if (!url) {
    return NextResponse.json({ error: 'url param required' }, { status: 400 });
  }

  try {
    // Try initialize first
    await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0', method: 'initialize', id: 0,
        params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'bolyra-benchmark', version: '0.1.0' } }
      }),
    }).catch(() => {});

    // Fetch tools/list
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', method: 'tools/list', id: 1 }),
    });

    const data = await res.json();
    return NextResponse.json(data, {
      headers: { 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'public, max-age=60' },
    });
  } catch (err) {
    return NextResponse.json(
      { error: (err as Error).message },
      { status: 502, headers: { 'Access-Control-Allow-Origin': '*' } }
    );
  }
}
