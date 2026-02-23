/*
Copyright (c) 2026 NyxeraLabs
Author: José María Micoli
Licensed under BSL 1.1
Change Date: 2033-02-17 → Apache-2.0
*/

import { NextRequest, NextResponse } from 'next/server';

import { API_URL } from '@/lib/config';
import { resolveTenantFromHost } from '@/lib/tenant-host';

const COOKIE_NAME = 'vv_access_token';

function externalBaseUrl(request: NextRequest): string {
  const proto = request.headers.get('x-forwarded-proto') ?? request.nextUrl.protocol.replace(':', '');
  const host = request.headers.get('x-forwarded-host') ?? request.headers.get('host') ?? request.nextUrl.host;
  return `${proto}://${host}`;
}

function isHttpsRequest(request: NextRequest): boolean {
  const forwardedProto = request.headers.get('x-forwarded-proto');
  if (forwardedProto) {
    return forwardedProto.split(',')[0].trim().toLowerCase() === 'https';
  }
  return request.nextUrl.protocol.replace(':', '').toLowerCase() === 'https';
}

export async function POST(request: NextRequest) {
  const form = await request.formData();
  const username = String(form.get('username') ?? '').trim();
  const password = String(form.get('password') ?? '');
  const confirm = String(form.get('confirm_password') ?? '');
  const accepted = String(form.get('accepted') ?? '') === 'on';
  const documentHash = String(form.get('document_hash') ?? '').trim();
  const version = String(form.get('version') ?? '').trim();
  const deploymentMode = String(form.get('deployment_mode') ?? 'self-hosted').trim() || 'self-hosted';
  const redirectPath = String(form.get('redirect') ?? '/portal/overview') || '/portal/overview';
  const host = request.headers.get('x-forwarded-host') ?? request.headers.get('host') ?? request.nextUrl.host;
  const tenantCfg = resolveTenantFromHost(host);
  const tenantId = String(form.get('tenant_id') ?? tenantCfg?.tenantId ?? '').trim();
  const secureCookies = isHttpsRequest(request);

  if (!username || !password || !confirm) {
    const url = new URL('/register', externalBaseUrl(request));
    url.searchParams.set('error', 'username_password_required');
    return NextResponse.redirect(url, { status: 303 });
  }
  if (password !== confirm) {
    const url = new URL('/register', externalBaseUrl(request));
    url.searchParams.set('error', 'password_mismatch');
    return NextResponse.redirect(url, { status: 303 });
  }
  if (!accepted || !documentHash || !version) {
    const url = new URL('/register', externalBaseUrl(request));
    url.searchParams.set('error', 'legal_acceptance_required');
    return NextResponse.redirect(url, { status: 303 });
  }
  if (!tenantId) {
    const url = new URL('/register', externalBaseUrl(request));
    url.searchParams.set('error', 'tenant_id_required');
    return NextResponse.redirect(url, { status: 303 });
  }

  const legalRes = await fetch(`${API_URL}/api/v1/client/legal/accept`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username,
      tenant_id: tenantId || null,
      deployment_mode: deploymentMode,
      accepted: true,
      document_hash: documentHash,
      version
    }),
    cache: 'no-store'
  });
  if (!legalRes.ok) {
    const url = new URL('/register', externalBaseUrl(request));
    url.searchParams.set('error', 'legal_record_failed');
    return NextResponse.redirect(url, { status: 303 });
  }
  const legalPayload = (await legalRes.json()) as { acceptance_id: number };

  const registerRes = await fetch(`${API_URL}/api/v1/client/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username,
      password,
      tenant_id: tenantId || null,
      deployment_mode: deploymentMode,
      legal_acceptance_id: legalPayload.acceptance_id
    }),
    cache: 'no-store'
  });
  if (!registerRes.ok) {
    const url = new URL('/register', externalBaseUrl(request));
    url.searchParams.set('error', 'registration_failed');
    return NextResponse.redirect(url, { status: 303 });
  }

  const loginRes = await fetch(`${API_URL}/api/v1/client/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password, tenant_id: tenantId }),
    cache: 'no-store'
  });
  if (!loginRes.ok) {
    const url = new URL('/login', externalBaseUrl(request));
    url.searchParams.set('error', 'registered_login_required');
    return NextResponse.redirect(url, { status: 303 });
  }
  const loginPayload = (await loginRes.json()) as { access_token: string; expires_in: number };

  const response = NextResponse.redirect(new URL(redirectPath, externalBaseUrl(request)), { status: 303 });
  response.cookies.set({
    name: 'vv_tenant_name',
    value: tenantCfg?.tenantName ?? tenantId,
    httpOnly: false,
    secure: secureCookies,
    sameSite: 'lax',
    path: '/',
    maxAge: Number.isFinite(loginPayload.expires_in) ? loginPayload.expires_in : 12 * 60 * 60
  });
  response.cookies.set({
    name: COOKIE_NAME,
    value: loginPayload.access_token,
    httpOnly: true,
    secure: secureCookies,
    sameSite: 'lax',
    path: '/',
    maxAge: Number.isFinite(loginPayload.expires_in) ? loginPayload.expires_in : 12 * 60 * 60
  });
  return response;
}
