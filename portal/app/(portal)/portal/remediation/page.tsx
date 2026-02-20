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

import { useEffect, useState } from 'react';

import StatusBadge from '@/components/StatusBadge';
import { trackRemediationAction } from '@/lib/telemetry';
import type { RemediationTask } from '@/lib/types';

type RemediationResponse = { items: RemediationTask[] };

function formatDate(value?: string | null): string {
  if (!value) return 'Not set';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleDateString();
}

function isCompleted(status: string): boolean {
  const s = status.toLowerCase();
  return s.includes('done') || s.includes('complete') || s.includes('closed');
}

export default function RemediationPage() {
  const [data, setData] = useState<RemediationTask[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;

    async function run() {
      try {
        setLoading(true);
        const res = await fetch('/api/proxy/remediation', { credentials: 'include', cache: 'no-store' });
        if (!res.ok) throw new Error(`Remediation API ${res.status}`);
        const payload = (await res.json()) as RemediationResponse;
        if (active) setData(payload.items ?? []);
      } catch (err) {
        if (active) setError(err instanceof Error ? err.message : 'Failed to load remediation tasks');
      } finally {
        if (active) setLoading(false);
      }
    }

    run();
    return () => {
      active = false;
    };
  }, []);

  if (loading) {
    return <p className="text-sm text-muted">Loading remediation tasks...</p>;
  }
  if (error) {
    return <p className="text-sm text-red-400">Unable to load remediation: {error}</p>;
  }

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">Remediation Tracking</h1>

      <div className="overflow-x-auto rounded-lg border border-slate-700 bg-panel">
        <table className="w-full text-sm">
          <thead className="border-b border-slate-800 text-left text-muted">
            <tr>
              <th className="px-4 py-3">Finding</th>
              <th className="px-4 py-3">Priority</th>
              <th className="px-4 py-3">Owner</th>
              <th className="px-4 py-3">Due Date</th>
              <th className="px-4 py-3">Timeline</th>
              <th className="px-4 py-3">Verification</th>
              <th className="px-4 py-3">Status</th>
            </tr>
          </thead>
          <tbody>
            {data.map((task) => (
              <tr
                key={task.id}
                className="cursor-pointer border-b border-slate-900"
                onClick={() => trackRemediationAction(task.id, task.status)}
              >
                <td className="px-4 py-3">{task.title}</td>
                <td className="px-4 py-3">{task.priority ?? 'Medium'}</td>
                <td className="px-4 py-3">{task.owner ?? 'Unassigned'}</td>
                <td className="px-4 py-3">{formatDate(task.due_date)}</td>
                <td className="px-4 py-3">{task.due_date ? 'In timeline' : 'Backlog'}</td>
                <td className="px-4 py-3">{isCompleted(task.status) ? 'Verified' : 'Pending verification'}</td>
                <td className="px-4 py-3">
                  <StatusBadge status={task.status} />
                </td>
              </tr>
            ))}
            {data.length === 0 ? (
              <tr>
                <td className="px-4 py-6 text-muted" colSpan={7}>
                  No remediation tasks available.
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
    </div>
  );
}
