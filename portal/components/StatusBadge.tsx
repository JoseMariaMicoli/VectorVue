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

type StatusBadgeProps = {
  status: string;
};

export default function StatusBadge({ status }: StatusBadgeProps) {
  const normalized = status.toLowerCase();
  let cls = 'border-slate-700 bg-slate-900 text-slate-300';

  if (normalized.includes('open') || normalized.includes('todo')) {
    cls = 'border-amber-500/40 bg-amber-950/40 text-amber-300';
  } else if (normalized.includes('progress') || normalized.includes('active') || normalized.includes('doing')) {
    cls = 'border-blue-500/40 bg-blue-950/40 text-blue-300';
  } else if (normalized.includes('done') || normalized.includes('complete') || normalized.includes('closed')) {
    cls = 'border-emerald-500/40 bg-emerald-950/40 text-emerald-300';
  } else if (normalized.includes('block') || normalized.includes('stalled')) {
    cls = 'border-red-500/40 bg-red-950/40 text-red-300';
  }

  return <span className={`inline-flex rounded border px-2 py-1 text-xs font-medium ${cls}`}>{status}</span>;
}
