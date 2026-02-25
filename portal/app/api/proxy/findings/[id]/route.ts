import { NextRequest } from 'next/server';
import { proxyClientApi } from '@/lib/proxy';

export async function GET(request: NextRequest, { params }: { params: { id: string } }) {
  return proxyClientApi(request, `/api/v1/client/findings/${params.id}`);
}
