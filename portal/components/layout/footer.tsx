/*
Copyright (c) 2026 NyxeraLabs
Author: José María Micoli
Licensed under BSL 1.1
Change Date: 2033-02-17 -> Apache-2.0
*/

import { brandTheme } from '@/styles/theme';

export function Footer() {
  return (
    <footer className="border-t border-[color:var(--vv-border-subtle)] bg-bg-primary py-4 text-center text-sm text-text-secondary">
      <p>{brandTheme.attribution.line1}</p>
      <p>{brandTheme.attribution.line2}</p>
    </footer>
  );
}
