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

import { useState } from 'react';

type TenantLogoProps = {
  companyName: string;
  logoUrl?: string | null;
};

export default function TenantLogo({ companyName, logoUrl }: TenantLogoProps) {
  const [failed, setFailed] = useState(false);
  const initials = companyName
    .split(' ')
    .filter(Boolean)
    .slice(0, 2)
    .map((x) => x[0]?.toUpperCase() ?? '')
    .join('') || 'VV';

  if (!logoUrl || failed) {
    return (
      <div className="flex h-10 w-10 items-center justify-center rounded border border-slate-700 bg-slate-900 text-xs font-semibold text-muted">
        {initials}
      </div>
    );
  }

  return (
    <img
      src={logoUrl}
      alt={`${companyName} logo`}
      className="h-10 w-10 rounded border border-slate-700 object-contain bg-slate-900"
      onError={() => setFailed(true)}
    />
  );
}

