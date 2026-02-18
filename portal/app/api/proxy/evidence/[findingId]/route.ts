import { NextRequest, NextResponse } from 'next/server';

import { API_URL } from '@/lib/config';

export async function GET(request: NextRequest, { params }: { params: { findingId: string } }) {
  const token = request.cookies.get('vv_access_token')?.value;
  const res = await fetch(`${API_URL}/api/v1/client/evidence/${params.findingId}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    cache: 'no-store'
  });

  return new NextResponse(await res.text(), {
    status: res.status,
    headers: { 'content-type': res.headers.get('content-type') ?? 'application/json' }
  });
}
