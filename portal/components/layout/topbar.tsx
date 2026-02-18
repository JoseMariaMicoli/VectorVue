import { Button } from '@/components/ui/button';

type TopbarProps = {
  tenantName: string;
};

export function Topbar({ tenantName }: TopbarProps) {
  return (
    <header className="flex items-center justify-between border-b border-slate-800 bg-panel px-6 py-3">
      <div>
        <p className="text-xs uppercase tracking-wide text-muted">Tenant</p>
        <p className="text-sm font-semibold">{tenantName}</p>
      </div>
      <form action="/api/auth/logout" method="post">
        <Button type="submit">Logout</Button>
      </form>
    </header>
  );
}
