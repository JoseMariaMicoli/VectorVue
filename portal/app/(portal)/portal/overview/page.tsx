'use client';

import { useEffect, useMemo, useState } from 'react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from 'recharts';

import RiskCard from '@/components/RiskCard';
import TrendChart from '@/components/TrendChart';
import { Card } from '@/components/ui/card';
import type { ClientFinding, ClientReport, Paginated, RemediationTask, RiskSummary } from '@/lib/types';

type TrendPoint = { day: string; score: number };
type RemediationResponse = { items: RemediationTask[] };
type RemediationSummary = {
  total_tasks: number;
  open_tasks: number;
  in_progress_tasks: number;
  completed_tasks: number;
  blocked_tasks: number;
};

type TimelineEvent = {
  key: string;
  label: string;
  meta: string;
  kind: 'finding' | 'report' | 'remediation';
  sortId: number;
};

function severityFromCvss(score?: number | null): 'critical' | 'high' | 'medium' | 'low' {
  if (score == null) return 'low';
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}

function campaignLabel(text: string): string {
  const m = text.match(/\[campaign:(\d+)\]/i);
  return m ? `Campaign ${m[1]}` : 'Campaign N/A';
}

function normalizeStatus(status?: string | null): 'open' | 'in_progress' | 'completed' | 'blocked' | 'other' {
  const s = (status ?? '').trim().toLowerCase();
  if (!s) return 'other';
  if (s.includes('progress')) return 'in_progress';
  if (s.includes('done') || s.includes('complete') || s.includes('closed') || s.includes('verified')) return 'completed';
  if (s.includes('block')) return 'blocked';
  if (s.includes('open') || s.includes('todo') || s.includes('new')) return 'open';
  return 'other';
}

export default function OverviewPage() {
  const [risk, setRisk] = useState<RiskSummary | null>(null);
  const [riskTrend, setRiskTrend] = useState<TrendPoint[]>([]);
  const [findings, setFindings] = useState<ClientFinding[]>([]);
  const [reports, setReports] = useState<ClientReport[]>([]);
  const [remediation, setRemediation] = useState<RemediationTask[]>([]);
  const [remediationSummary, setRemediationSummary] = useState<RemediationSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;

    async function run() {
      try {
        setLoading(true);
        const [riskRes, trendRes, findingsRes, reportsRes, remediationRes, remediationStatusRes] = await Promise.all([
          fetch('/api/proxy/risk', { credentials: 'include', cache: 'no-store' }),
          fetch('/api/proxy/risk-trend', { credentials: 'include', cache: 'no-store' }),
          fetch('/api/proxy/findings?page=1&page_size=200', { credentials: 'include', cache: 'no-store' }),
          fetch('/api/proxy/reports?page=1&page_size=200', { credentials: 'include', cache: 'no-store' }),
          fetch('/api/proxy/remediation', { credentials: 'include', cache: 'no-store' }),
          fetch('/api/proxy/remediation-status', { credentials: 'include', cache: 'no-store' })
        ]);

        if (!riskRes.ok) throw new Error(`Risk API ${riskRes.status}`);
        if (!trendRes.ok) throw new Error(`Trend API ${trendRes.status}`);
        if (!findingsRes.ok) throw new Error(`Findings API ${findingsRes.status}`);
        if (!reportsRes.ok) throw new Error(`Reports API ${reportsRes.status}`);
        if (!remediationRes.ok) throw new Error(`Remediation API ${remediationRes.status}`);
        if (!remediationStatusRes.ok) throw new Error(`Remediation status API ${remediationStatusRes.status}`);

        const riskData = (await riskRes.json()) as RiskSummary;
        const trendData = (await trendRes.json()) as TrendPoint[];
        const findingsData = (await findingsRes.json()) as Paginated<ClientFinding>;
        const reportsData = (await reportsRes.json()) as Paginated<ClientReport>;
        const remediationData = (await remediationRes.json()) as RemediationResponse;
        const remediationStatusData = (await remediationStatusRes.json()) as RemediationSummary;

        if (!active) return;
        setRisk(riskData);
        setRiskTrend(trendData ?? []);
        setFindings(findingsData.items ?? []);
        setReports(reportsData.items ?? []);
        setRemediation(remediationData.items ?? []);
        setRemediationSummary(remediationStatusData);
      } catch (err) {
        if (active) setError(err instanceof Error ? err.message : 'Failed to load overview');
      } finally {
        if (active) setLoading(false);
      }
    }

    run();
    return () => {
      active = false;
    };
  }, []);

  const findingsByCampaign = useMemo(() => {
    const counts = new Map<string, number>();
    for (const finding of findings) {
      const key = campaignLabel(finding.title);
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    return [...counts.entries()]
      .map(([campaign, findingsCount]) => ({ campaign, findings: findingsCount }))
      .sort((a, b) => b.findings - a.findings);
  }, [findings]);

  const remediationByStatus = useMemo(() => {
    const counts: Record<'open' | 'in_progress' | 'completed' | 'blocked' | 'other', number> = {
      open: 0,
      in_progress: 0,
      completed: 0,
      blocked: 0,
      other: 0
    };
    for (const task of remediation) {
      counts[normalizeStatus(task.status)] += 1;
    }
    return [
      { status: 'Open', total: counts.open },
      { status: 'In Progress', total: counts.in_progress },
      { status: 'Completed', total: counts.completed },
      { status: 'Blocked', total: counts.blocked },
      { status: 'Other', total: counts.other }
    ];
  }, [remediation]);

  const timeline = useMemo(() => {
    const findingEvents: TimelineEvent[] = findings.slice(0, 8).map((finding) => ({
      key: `f-${finding.id}`,
      label: finding.title,
      meta: `${campaignLabel(finding.title)} | ${severityFromCvss(finding.cvss_score)} | id:${finding.id}`,
      kind: 'finding',
      sortId: finding.id
    }));
    const reportEvents: TimelineEvent[] = reports.slice(0, 6).map((report) => ({
      key: `r-${report.id}`,
      label: report.title,
      meta: `Report status: ${report.status} | id:${report.id}`,
      kind: 'report',
      sortId: report.id
    }));
    const remediationEvents: TimelineEvent[] = remediation.slice(0, 8).map((task) => ({
      key: `t-${task.id}`,
      label: task.title,
      meta: `Task status: ${task.status} | id:${task.id}`,
      kind: 'remediation',
      sortId: task.id
    }));
    return [...findingEvents, ...reportEvents, ...remediationEvents]
      .sort((a, b) => b.sortId - a.sortId)
      .slice(0, 14);
  }, [findings, remediation, reports]);

  if (loading) return <p className="text-sm text-muted">Loading centralized dashboard...</p>;
  if (error || !risk) return <p className="text-sm text-red-400">Unable to load overview: {error ?? 'unknown error'}</p>;

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">Centralized Overview</h1>

      <div className="grid gap-3 md:grid-cols-4">
        <RiskCard label="Overall Risk Score" value={risk.score.toFixed(2)} tone={risk.score >= 9 ? 'critical' : risk.score >= 7 ? 'high' : 'neutral'} />
        <RiskCard label="Total Findings" value={findings.length} tone={(risk.critical + risk.high) > 0 ? 'high' : 'neutral'} />
        <RiskCard label="Active Remediation" value={(remediationSummary?.open_tasks ?? 0) + (remediationSummary?.in_progress_tasks ?? 0)} tone="high" />
        <RiskCard label="Published Reports" value={reports.length} />
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card>
          <h2 className="mb-3 text-sm font-semibold">Findings by Campaign (Bar)</h2>
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={findingsByCampaign}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis dataKey="campaign" tick={{ fontSize: 12 }} />
                <YAxis allowDecimals={false} tick={{ fontSize: 12 }} />
                <Tooltip />
                <Bar dataKey="findings" fill="#22d3ee" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>

        <Card>
          <h2 className="mb-3 text-sm font-semibold">Remediation by Status (Bar)</h2>
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={remediationByStatus}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis dataKey="status" tick={{ fontSize: 12 }} />
                <YAxis allowDecimals={false} tick={{ fontSize: 12 }} />
                <Tooltip />
                <Bar dataKey="total" fill="#f59e0b" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <TrendChart points={riskTrend} />

        <Card>
          <h2 className="mb-3 text-sm font-semibold">Operational Timeline</h2>
          <ol className="space-y-3">
            {timeline.map((item) => (
              <li key={item.key} className="rounded border border-slate-800 px-3 py-2">
                <p className="text-sm font-medium">
                  <span className="mr-2 rounded border border-slate-700 px-2 py-0.5 text-[11px] uppercase tracking-wide text-muted">{item.kind}</span>
                  {item.label}
                </p>
                <p className="mt-1 text-xs text-muted">{item.meta}</p>
              </li>
            ))}
            {timeline.length === 0 ? <li className="text-sm text-muted">No timeline events available.</li> : null}
          </ol>
        </Card>
      </div>
    </div>
  );
}
