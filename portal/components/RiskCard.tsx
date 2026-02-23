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
      ? 'border-danger/40 bg-danger/10'
      : tone === 'high'
      ? 'border-warning/40 bg-warning/10'
      : 'border-[color:var(--vv-border-subtle)] bg-panel';

  return (
    <div className={`rounded-xl border p-4 ${toneClass}`}>
      <p className="text-xs uppercase tracking-wide text-text-secondary">{label}</p>
      <p className="mt-2 text-2xl font-semibold">{value}</p>
    </div>
  );
}
