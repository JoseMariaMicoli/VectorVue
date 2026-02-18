import { NextRequest } from 'next/server';

import { proxyClientApi } from '@/lib/proxy';

export async function GET(request: NextRequest) {
  return proxyClientApi(request, '/api/v1/client/risk-trend');
}
