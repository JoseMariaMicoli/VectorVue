/*
Copyright (c) 2026 NyxeraLabs
Author: José María Micoli
Licensed under BSL 1.1
Change Date: 2033-02-17 → Apache-2.0

You may:
✔ Study
✔ Modify
✔ Use for internal security testing

You may NOT:
✘ Offer as a commercial service
✘ Sell derived competing products
*/

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
