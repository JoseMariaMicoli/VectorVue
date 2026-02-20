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

'use client';

type RiskCardProps = {
  label: string;
  value: string | number;
  tone?: 'neutral' | 'high' | 'critical';
};

export default function RiskCard({ label, value, tone = 'neutral' }: RiskCardProps) {
  const toneClass =
    tone === 'critical'
      ? 'border-red-600/40 bg-red-950/40'
      : tone === 'high'
      ? 'border-amber-500/40 bg-amber-950/30'
      : 'border-slate-700 bg-panel';

  return (
    <div className={`rounded-lg border p-4 ${toneClass}`}>
      <p className="text-xs uppercase tracking-wide text-muted">{label}</p>
      <p className="mt-2 text-2xl font-semibold">{value}</p>
    </div>
  );
}
