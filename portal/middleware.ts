import { NextResponse, type NextRequest } from 'next/server';

import { resolveTenantFromHost } from '@/lib/tenant-host';

const TOKEN_COOKIE = 'vv_access_token';

export function middleware(request: NextRequest) {
  const token = request.cookies.get(TOKEN_COOKIE)?.value;
  const isPortal = request.nextUrl.pathname.startsWith('/portal');
  const host = request.headers.get('x-forwarded-host') ?? request.headers.get('host') ?? request.nextUrl.host;
  const tenantCfg = resolveTenantFromHost(host);

  if (isPortal && !tenantCfg) {
    const loginUrl = new URL('/login', request.url);
    loginUrl.searchParams.set('error', 'unknown_tenant_host');
    return NextResponse.redirect(loginUrl);
  }

  if (isPortal && !token) {
    const loginUrl = new URL('/login', request.url);
    loginUrl.searchParams.set('redirect', request.nextUrl.pathname);
    return NextResponse.redirect(loginUrl);
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/portal/:path*']
};
