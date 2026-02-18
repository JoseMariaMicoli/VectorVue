import type { NextRequest } from 'next/server';

import { API_URL } from '@/lib/config';

export async function proxyClientApi(request: NextRequest, path: string): Promise<Response> {
  const token = request.cookies.get('vv_access_token')?.value;
  const upstreamHeaders = new Headers();
  const accept = request.headers.get('accept');
  if (accept) upstreamHeaders.set('accept', accept);
  if (token) upstreamHeaders.set('Authorization', `Bearer ${token}`);

  const timeoutMs = Number(process.env.VV_PROXY_TIMEOUT_MS ?? 8000);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let res: Response;
  try {
    res = await fetch(`${API_URL}${path}`, {
      method: request.method,
      headers: upstreamHeaders,
      cache: 'no-store',
      signal: controller.signal
    });
  } catch {
    return Response.json(
      { detail: 'Upstream API unavailable' },
      { status: 502, headers: { 'cache-control': 'no-store' } }
    );
  } finally {
    clearTimeout(timer);
  }

  const body = await res.arrayBuffer();
  const headers = new Headers();
  const passthrough = ['content-type', 'content-disposition', 'cache-control', 'etag'];
  for (const key of passthrough) {
    const value = res.headers.get(key);
    if (value) headers.set(key, value);
  }

  return new Response(body, {
    status: res.status,
    headers
  });
}
