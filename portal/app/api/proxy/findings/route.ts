import { NextRequest } from 'next/server';
import { proxyClientApi } from '@/lib/proxy';

export async function GET(request: NextRequest) {
  const q = request.nextUrl.searchParams.toString();
  return proxyClientApi(request, `/api/v1/client/findings${q ? `?${q}` : ''}`);
}
