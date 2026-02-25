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

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

const TOKEN_COOKIE = 'vv_access_token';

function externalBaseUrl(request: NextRequest): string {
  const proto = request.headers.get('x-forwarded-proto') ?? request.nextUrl.protocol.replace(':', '');
  const host = request.headers.get('x-forwarded-host') ?? request.headers.get('host') ?? request.nextUrl.host;
  return `${proto}://${host}`;
}

export async function POST(request: NextRequest) {
  const res = NextResponse.redirect(new URL('/login', externalBaseUrl(request)), { status: 303 });
  res.cookies.set(TOKEN_COOKIE, '', {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    expires: new Date(0),
    path: '/'
  });
  res.cookies.set('vv_tenant_name', '', {
    httpOnly: false,
    secure: true,
    sameSite: 'lax',
    expires: new Date(0),
    path: '/'
  });
  return res;
}
