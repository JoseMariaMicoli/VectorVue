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

import Link from 'next/link';
import { useEffect, useMemo, useState } from 'react';

import { Card } from '@/components/ui/card';
import type { ClientFinding, Paginated } from '@/lib/types';

type SeverityFilter = 'all' | 'critical' | 'high' | 'medium' | 'low';

function severityFromCvss(score?: number | null): SeverityFilter {
  if (score == null) return 'low';
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}

function campaignLabel(title: string): string {
  const m = title.match(/\[campaign:(\d+)\]/i);
  return m ? `Campaign ${m[1]}` : 'Campaign N/A';
}

function toCsv(items: ClientFinding[]): string {
  const rows = [['id', 'title', 'campaign', 'cvss', 'severity', 'approval']];
  for (const f of items) {
    rows.push([
      String(f.id),
      f.title.replaceAll('"', '""'),
      campaignLabel(f.title),
      String(f.cvss_score ?? ''),
      severityFromCvss(f.cvss_score),
      f.approval_status
    ]);
  }
  return rows.map((r) => r.map((v) => `"${v}"`).join(',')).join('\n');
}

export default function FindingsPage() {
  const [data, setData] = useState<ClientFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [severity, setSeverity] = useState<SeverityFilter>('all');

  useEffect(() => {
    let active = true;

    async function run() {
      try {
        setLoading(true);
        const res = await fetch('/api/proxy/findings?page=1&page_size=200', {
          credentials: 'include',
          cache: 'no-store'
        });
        if (!res.ok) throw new Error(`Findings API ${res.status}`);
        const payload = (await res.json()) as Paginated<ClientFinding>;
        if (active) setData(payload.items ?? []);
      } catch (err) {
        if (active) setError(err instanceof Error ? err.message : 'Failed to load findings');
      } finally {
        if (active) setLoading(false);
      }
    }

    run();
    return () => {
      active = false;
    };
  }, []);

  const filtered = useMemo(() => {
    const list = severity === 'all' ? data : data.filter((f) => severityFromCvss(f.cvss_score) === severity);
    return [...list].sort((a, b) => (b.cvss_score ?? 0) - (a.cvss_score ?? 0));
  }, [data, severity]);

  function exportJson() {
    const blob = new Blob([JSON.stringify(filtered, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'findings-export.json';
    a.click();
    URL.revokeObjectURL(url);
  }

  function exportCsv() {
    const blob = new Blob([toCsv(filtered)], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'findings-export.csv';
    a.click();
    URL.revokeObjectURL(url);
  }

  if (loading) return <p className="text-sm text-muted">Loading findings...</p>;
  if (error) return <p className="text-sm text-red-400">Unable to load findings: {error}</p>;

  return (
    <Card>
      <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-xl font-semibold">Findings</h1>
        <div className="flex items-center gap-2">
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value as SeverityFilter)}
            className="rounded border border-slate-700 bg-slate-950 px-2 py-2 text-xs"
          >
            <option value="all">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <button type="button" onClick={exportJson} className="rounded border border-slate-700 px-3 py-2 text-xs hover:bg-slate-800">
            Export JSON
          </button>
          <button type="button" onClick={exportCsv} className="rounded border border-slate-700 px-3 py-2 text-xs hover:bg-slate-800">
            Export CSV
          </button>
        </div>
      </div>

      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-muted">
            <th className="py-2">Title</th>
            <th className="py-2">Campaign</th>
            <th className="py-2">CVSS</th>
            <th className="py-2">Severity</th>
            <th className="py-2">Approval</th>
            <th className="py-2">Action</th>
          </tr>
        </thead>
        <tbody>
          {filtered.map((f) => (
            <tr key={f.id} className="border-t border-slate-800">
              <td className="py-2">{f.title}</td>
              <td className="py-2">{campaignLabel(f.title)}</td>
              <td className="py-2">{f.cvss_score ?? '-'}</td>
              <td className="py-2">{severityFromCvss(f.cvss_score)}</td>
              <td className="py-2">{f.approval_status}</td>
              <td className="py-2">
                <Link href={`/portal/findings/${f.id}`} className="text-accent hover:underline">
                  View
                </Link>
              </td>
            </tr>
          ))}
          {filtered.length === 0 ? (
            <tr>
              <td className="py-5 text-muted" colSpan={6}>
                No findings for selected filter.
              </td>
            </tr>
          ) : null}
        </tbody>
      </table>
    </Card>
  );
}
