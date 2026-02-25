import { NextRequest } from 'next/server';

import { proxyClientApi } from '@/lib/proxy';

type RouteContext = {
  params: {
    campaignId: string;
  };
};

export async function GET(request: NextRequest, context: RouteContext) {
  return proxyClientApi(request, `/ml/operator/suggestions/${context.params.campaignId}`);
}
