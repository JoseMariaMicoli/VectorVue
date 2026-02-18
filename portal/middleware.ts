import { NextResponse, type NextRequest } from 'next/server';

const TOKEN_COOKIE = 'vv_access_token';

export function middleware(request: NextRequest) {
  const token = request.cookies.get(TOKEN_COOKIE)?.value;
  const isPortal = request.nextUrl.pathname.startsWith('/portal');

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
