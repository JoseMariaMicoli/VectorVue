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
  if (code === 'tenant_id_required') return 'Tenant ID is required when host mapping is unavailable.';
  if (code === 'registered_login_required') return 'Registration completed. Please login.';
  if (code === 'unknown_tenant_host') return 'This host is not mapped. Provide Tenant ID manually.';
  return 'Authentication failed.';
}

export default function LoginPage({ searchParams }: LoginPageProps) {
  if (cookies().get('vv_access_token')?.value) {
    redirect('/portal/overview');
  }
  const host = headers().get('x-forwarded-host') ?? headers().get('host');
  const mappedTenant = resolveTenantFromHost(host);
  const redirectPath = searchParams?.redirect ?? '/portal/overview';
  const error = renderError(searchParams?.error) ?? (!mappedTenant ? 'Host not mapped. Enter Tenant ID manually.' : null);

  return (
    <main className="flex min-h-screen items-center justify-center bg-bg-primary p-6">
      <Card>
        <h1 className="mb-2 text-xl font-semibold text-metallic">Client Login</h1>
        <p className="mb-4 text-sm text-text-secondary">Sign in with your assigned portal credentials.</p>
        <p className="mb-4 text-xs text-text-secondary">Host: {host ?? 'unknown'}</p>
        {mappedTenant ? (
          <p className="mb-4 rounded-lg border border-[color:var(--vv-border-subtle)] bg-bg-primary px-3 py-2 text-xs text-text-secondary">
            Tenant: {mappedTenant.tenantName ?? mappedTenant.tenantId}
          </p>
        ) : null}
        {error ? <p className="mb-4 text-sm text-danger">{error}</p> : null}
        <form action="/api/auth/login" method="post" className="space-y-3">
          <input type="hidden" name="redirect" value={redirectPath} />
          <label className="block text-sm">
            <span className="mb-1 block text-text-secondary">Tenant ID</span>
            <input
              type="text"
              name="tenant_id"
              defaultValue={mappedTenant?.tenantId ?? ''}
              required={!mappedTenant}
              className="w-full rounded-lg border border-[color:var(--vv-border-subtle)] bg-bg-primary px-3 py-2 text-text-primary"
            />
          </label>
          <label className="block text-sm">
            <span className="mb-1 block text-text-secondary">Username</span>
            <input
              type="text"
              name="username"
              required
              className="w-full rounded-lg border border-[color:var(--vv-border-subtle)] bg-bg-primary px-3 py-2 text-text-primary"
            />
          </label>
          <label className="block text-sm">
            <span className="mb-1 block text-text-secondary">Password</span>
            <input
              type="password"
              name="password"
              required
              className="w-full rounded-lg border border-[color:var(--vv-border-subtle)] bg-bg-primary px-3 py-2 text-text-primary"
            />
          </label>
          <button
            type="submit"
            className="w-full rounded-lg bg-accent px-4 py-2 font-medium text-white shadow-accent-glow transition-colors hover:bg-accent-hover"
          >
            Login
          </button>
          <a
            href={mappedTenant?.tenantId ? `/register?tenant_id=${encodeURIComponent(mappedTenant.tenantId)}` : '/register'}
            className="block text-center text-xs text-text-secondary underline"
          >
            Register new account
          </a>
        </form>
      </Card>
    </main>
  );
}
