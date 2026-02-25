import { cookies, headers } from 'next/headers';
import type { ReactNode } from 'react';

import ThemeBootstrap from '@/components/ThemeBootstrap';
import { Sidebar } from '@/components/layout/sidebar';
import { Topbar } from '@/components/layout/topbar';
import { API_URL } from '@/lib/config';
import { resolveTenantFromHost } from '@/lib/tenant-host';
import type { ClientTheme } from '@/lib/types';

async function loadInitialTheme(token: string | undefined): Promise<ClientTheme | null> {
  if (!token) return null;
  try {
    const res = await fetch(`${API_URL}/api/v1/client/theme`, {
      cache: 'no-store',
      headers: { Authorization: `Bearer ${token}` }
    });
    if (!res.ok) return null;
    return (await res.json()) as ClientTheme;
  } catch {
    return null;
  }
}

export default async function PortalLayout({ children }: { children: ReactNode }) {
  const host = headers().get('x-forwarded-host') ?? headers().get('host') ?? '';
  const tenantCfg = resolveTenantFromHost(host);
  const fallbackTenant = tenantCfg?.tenantName ?? 'Customer Tenant';
  const tenant = cookies().get('vv_tenant_name')?.value ?? fallbackTenant;
  const theme = await loadInitialTheme(cookies().get('vv_access_token')?.value);

  return (
    <ThemeBootstrap initialTheme={theme}>
      <div className="flex min-h-screen">
        <Sidebar />
        <div className="flex min-h-screen flex-1 flex-col">
          <Topbar tenantName={tenant} theme={theme} />
          <main className="flex-1 p-6">{children}</main>
        </div>
      </div>
    </ThemeBootstrap>
  );
}
