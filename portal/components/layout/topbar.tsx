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

/* eslint-disable @next/next/no-img-element */
'use client';

import { useEffect, useState } from 'react';

import { Button } from '@/components/ui/button';
import NotificationCenter from '@/components/NotificationCenter';
import { type PortalLang, t } from '@/lib/i18n';
import type { ClientTheme } from '@/lib/types';
import TenantLogo from '@/components/TenantLogo';
import { BrandLogo } from '@/components/layout/brand-logo';

type TopbarProps = {
  tenantName: string;
  theme?: ClientTheme | null;
};

export function Topbar({ tenantName, theme }: TopbarProps) {
  const [lang, setLang] = useState<PortalLang>('en');

  useEffect(() => {
    const stored = localStorage.getItem('vv_portal_lang');
    if (stored === 'en' || stored === 'es') setLang(stored);
  }, []);

  function changeLang(next: PortalLang) {
    setLang(next);
    localStorage.setItem('vv_portal_lang', next);
  }

  return (
    <header className="flex min-h-navbar items-center justify-between border-b border-[color:var(--vv-border-subtle)] bg-bg-primary px-6 py-2">
      <div className="flex items-center gap-4">
        <BrandLogo />
        <TenantLogo companyName={theme?.company_name ?? tenantName} logoUrl={theme?.logo_url} />
        <div>
          <p className="text-xs uppercase tracking-[0.14em] text-text-secondary">{t(lang, 'tenant')}</p>
          <p className="text-sm font-semibold text-metallic">{theme?.company_name ?? tenantName}</p>
        </div>
      </div>
      <div className="flex items-center gap-2">
        <select
          value={lang}
          onChange={(e) => changeLang((e.target.value as PortalLang) ?? 'en')}
          className="rounded-lg border border-[color:var(--vv-border-subtle)] bg-bg-secondary px-2 py-2 text-xs text-text-primary"
          aria-label="language"
        >
          <option value="en">EN</option>
          <option value="es">ES</option>
        </select>
        <NotificationCenter lang={lang} />
        <form action="/api/auth/logout" method="post">
          <Button type="submit">{t(lang, 'logout')}</Button>
        </form>
      </div>
    </header>
  );
}
