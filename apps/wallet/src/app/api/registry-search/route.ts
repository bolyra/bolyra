import { NextRequest, NextResponse } from 'next/server';

export async function GET(req: NextRequest) {
  const q = req.nextUrl.searchParams.get('q') || '';
  const limit = req.nextUrl.searchParams.get('limit') || '10';

  try {
    const res = await fetch(
      `https://registry.modelcontextprotocol.io/v0/servers?search=${encodeURIComponent(q)}&limit=${limit}`,
      { headers: { 'Accept': 'application/json' } }
    );
    const data = await res.json();
    return NextResponse.json(data, {
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Cache-Control': 'public, max-age=60',
      },
    });
  } catch (err) {
    return NextResponse.json(
      { error: (err as Error).message },
      { status: 502, headers: { 'Access-Control-Allow-Origin': '*' } }
    );
  }
}
