import { NextRequest } from 'next/server';

import { proxyClientApi } from '@/lib/proxy';

export async function POST(request: NextRequest) {
  return proxyClientApi(request, '/api/v1/client/events');
}

