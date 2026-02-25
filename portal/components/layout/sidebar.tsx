import Link from 'next/link';

const links = [
  { href: '/portal/overview', label: 'Overview' },
  { href: '/portal/analytics', label: 'Analytics' },
  { href: '/portal/findings', label: 'Findings' },
  { href: '/portal/reports', label: 'Reports' },
  { href: '/portal/risk', label: 'Risk' },
  { href: '/portal/remediation', label: 'Remediation' }
];

export function Sidebar() {
  return (
    <aside className="w-64 border-r border-slate-800 bg-panel p-4">
      <p className="mb-4 text-xs uppercase tracking-wide text-muted">Client Portal</p>
      <nav className="space-y-1">
        {links.map((item) => (
          <Link key={item.href} href={item.href} className="block rounded px-3 py-2 text-sm hover:bg-slate-800">
            {item.label}
          </Link>
        ))}
      </nav>
    </aside>
  );
}
