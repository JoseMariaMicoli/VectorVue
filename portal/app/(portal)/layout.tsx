import { cookies } from 'next/headers';
import type { ReactNode } from 'react';

import { Sidebar } from '@/components/layout/sidebar';
import { Topbar } from '@/components/layout/topbar';

export default function PortalLayout({ children }: { children: ReactNode }) {
  const tenant = cookies().get('vv_tenant_name')?.value ?? 'Customer Tenant';

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <div className="flex min-h-screen flex-1 flex-col">
        <Topbar tenantName={tenant} />
        <main className="flex-1 p-6">{children}</main>
      </div>
    </div>
  );
}
