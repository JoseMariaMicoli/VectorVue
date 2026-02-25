/*
Copyright (c) 2026 NyxeraLabs
Author: José María Micoli
Licensed under BSL 1.1
Change Date: 2033-02-17 → Apache-2.0
*/

import { NextRequest, NextResponse } from 'next/server';

import { API_URL } from '@/lib/config';

export async function GET(request: NextRequest) {
  const mode = request.nextUrl.searchParams.get('mode') ?? 'self-hosted';
  const upstream = await fetch(`${API_URL}/api/v1/client/legal/documents?mode=${encodeURIComponent(mode)}`, {
    cache: 'no-store'
  });

  const body = await upstream.text();
  return new NextResponse(body, {
    status: upstream.status,
    headers: { 'content-type': upstream.headers.get('content-type') ?? 'application/json' }
  });
}
