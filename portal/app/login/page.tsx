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

import { cookies, headers } from 'next/headers';
import { redirect } from 'next/navigation';

import { Card } from '@/components/ui/card';
import { resolveTenantFromHost } from '@/lib/tenant-host';

type LoginPageProps = {
  searchParams?: {
    redirect?: string;
    error?: string;
  };
};

function renderError(code?: string): string | null {
  if (!code) return null;
  if (code === 'username_password_required') return 'Username and password are required.';
  if (code === 'invalid_credentials_or_tenant') return 'Invalid credentials or tenant ID.';
  if (code === 'unknown_tenant_host') return 'This host is not mapped to a tenant. Contact support.';
  return 'Authentication failed.';
}

export default function LoginPage({ searchParams }: LoginPageProps) {
  if (cookies().get('vv_access_token')?.value) {
    redirect('/portal/overview');
  }
  const host = headers().get('x-forwarded-host') ?? headers().get('host');
  const mappedTenant = resolveTenantFromHost(host);
  const redirectPath = searchParams?.redirect ?? '/portal/overview';
  const error = renderError(searchParams?.error) ?? (!mappedTenant ? 'This host is not mapped to a tenant.' : null);

  return (
    <main className="flex min-h-screen items-center justify-center p-6">
      <Card>
        <h1 className="mb-2 text-xl font-semibold">Client Login</h1>
        <p className="mb-4 text-sm text-muted">Sign in with your assigned portal credentials.</p>
        <p className="mb-4 text-xs text-muted">Host: {host ?? 'unknown'}</p>
        {mappedTenant ? (
          <p className="mb-4 rounded border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-muted">
            Tenant: {mappedTenant.tenantName ?? mappedTenant.tenantId}
          </p>
        ) : null}
        {error ? <p className="mb-4 text-sm text-red-400">{error}</p> : null}
        <form action="/api/auth/login" method="post" className="space-y-3">
          <input type="hidden" name="redirect" value={redirectPath} />
          <input type="hidden" name="tenant_id" value={mappedTenant?.tenantId ?? ''} />
          <label className="block text-sm">
            <span className="mb-1 block text-muted">Username</span>
            <input
              type="text"
              name="username"
              required
              className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2"
            />
          </label>
          <label className="block text-sm">
            <span className="mb-1 block text-muted">Password</span>
            <input
              type="password"
              name="password"
              required
              className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2"
            />
          </label>
          <button
            type="submit"
            disabled={!mappedTenant}
            className="w-full rounded bg-accent px-4 py-2 font-medium text-slate-950 hover:opacity-90"
          >
            Login
          </button>
        </form>
      </Card>
    </main>
  );
}
