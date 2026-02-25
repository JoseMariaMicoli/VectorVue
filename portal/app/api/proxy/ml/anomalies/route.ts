import { NextRequest } from 'next/server';

import { proxyClientApi } from '@/lib/proxy';

export async function GET(request: NextRequest) {
  return proxyClientApi(request, '/ml/client/anomalies');
}
