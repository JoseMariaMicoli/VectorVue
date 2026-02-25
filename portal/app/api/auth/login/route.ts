import { NextRequest, NextResponse } from 'next/server';

import { API_URL } from '@/lib/config';
import { resolveTenantFromHost } from '@/lib/tenant-host';

const COOKIE_NAME = 'vv_access_token';

function externalBaseUrl(request: NextRequest): string {
  const proto = request.headers.get('x-forwarded-proto') ?? request.nextUrl.protocol.replace(':', '');
  const host = request.headers.get('x-forwarded-host') ?? request.headers.get('host') ?? request.nextUrl.host;
  return `${proto}://${host}`;
}

export async function POST(request: NextRequest) {
  const form = await request.formData();
  const username = String(form.get('username') ?? '').trim();
  const password = String(form.get('password') ?? '');
  const redirectPath = String(form.get('redirect') ?? '/portal/findings') || '/portal/findings';
  const host = request.headers.get('x-forwarded-host') ?? request.headers.get('host') ?? request.nextUrl.host;
  const tenantCfg = resolveTenantFromHost(host);

  if (!tenantCfg) {
    const url = new URL('/login', externalBaseUrl(request));
    url.searchParams.set('error', 'unknown_tenant_host');
    return NextResponse.redirect(url, { status: 303 });
  }

  if (!username || !password) {
    const url = new URL('/login', externalBaseUrl(request));
    url.searchParams.set('error', 'username_password_required');
    return NextResponse.redirect(url, { status: 303 });
  }

  const upstream = await fetch(`${API_URL}/api/v1/client/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password, tenant_id: tenantCfg.tenantId }),
    cache: 'no-store'
  });

  if (!upstream.ok) {
    const url = new URL('/login', externalBaseUrl(request));
    url.searchParams.set('error', 'invalid_credentials_or_tenant');
    return NextResponse.redirect(url, { status: 303 });
  }

  const payload = (await upstream.json()) as { access_token: string; expires_in: number };

  const target = redirectPath.startsWith('/') ? redirectPath : '/portal/findings';
  const response = NextResponse.redirect(new URL(target, externalBaseUrl(request)), { status: 303 });
  response.cookies.set({
    name: 'vv_tenant_name',
    value: tenantCfg.tenantName ?? tenantCfg.tenantId,
    httpOnly: false,
    secure: true,
    sameSite: 'lax',
    path: '/',
    maxAge: Number.isFinite(payload.expires_in) ? payload.expires_in : 12 * 60 * 60
  });
  response.cookies.set({
    name: COOKIE_NAME,
    value: payload.access_token,
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    path: '/',
    maxAge: Number.isFinite(payload.expires_in) ? payload.expires_in : 12 * 60 * 60
  });
  return response;
}
