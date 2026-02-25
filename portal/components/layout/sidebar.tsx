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
    <aside className="w-64 border-r border-[color:var(--vv-border-subtle)] bg-bg-secondary p-4">
      <p className="mb-4 text-xs uppercase tracking-[0.16em] text-text-secondary">Client Portal</p>
      <nav className="space-y-1">
        {links.map((item) => (
          <Link
            key={item.href}
            href={item.href}
            className="block rounded-lg px-3 py-2 text-sm text-text-primary transition-colors hover:bg-bg-primary hover:text-metallic"
          >
            {item.label}
          </Link>
        ))}
      </nav>
    </aside>
  );
}
