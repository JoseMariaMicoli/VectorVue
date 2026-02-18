'use client';

import { useEffect, useState } from 'react';

import RiskCard from '@/components/RiskCard';
import SeverityChart from '@/components/SeverityChart';
import TrendChart from '@/components/TrendChart';
import type { RiskSummary } from '@/lib/types';

type TrendPoint = { day: string; score: number };
type RemediationSummary = {
  total_tasks: number;
  open_tasks: number;
  in_progress_tasks: number;
  completed_tasks: number;
  blocked_tasks: number;
};

export default function RiskPage() {
  const [risk, setRisk] = useState<RiskSummary | null>(null);
  const [trend, setTrend] = useState<TrendPoint[]>([]);
  const [remediation, setRemediation] = useState<RemediationSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;

    async function run() {
      try {
        setLoading(true);
        const [riskRes, trendRes, remediationRes] = await Promise.all([
          fetch('/api/proxy/risk', { credentials: 'include', cache: 'no-store' }),
          fetch('/api/proxy/risk-trend', { credentials: 'include', cache: 'no-store' }),
          fetch('/api/proxy/remediation-status', { credentials: 'include', cache: 'no-store' })
        ]);
        if (!riskRes.ok) throw new Error(`Risk API ${riskRes.status}`);
        if (!trendRes.ok) throw new Error(`Risk Trend API ${trendRes.status}`);
        if (!remediationRes.ok) throw new Error(`Remediation Status API ${remediationRes.status}`);
        const data = (await riskRes.json()) as RiskSummary;
        const trendData = (await trendRes.json()) as Array<{ day: string; score: number }>;
        const remSummary = (await remediationRes.json()) as RemediationSummary;
        if (active) setRisk(data);
        if (active) setTrend(trendData ?? []);
        if (active) setRemediation(remSummary);
      } catch (err) {
        if (active) setError(err instanceof Error ? err.message : 'Failed to load risk data');
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
    return <p className="text-sm text-muted">Loading risk analytics...</p>;
  }
  if (error || !risk) {
    return <p className="text-sm text-red-400">Unable to load risk dashboard: {error ?? 'unknown error'}</p>;
  }

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">Risk Analytics</h1>

      <div className="grid gap-3 md:grid-cols-3">
        <RiskCard label="Overall Score" value={risk.score.toFixed(2)} tone={risk.score >= 9 ? 'critical' : risk.score >= 7 ? 'high' : 'neutral'} />
        <RiskCard label="Critical Findings" value={risk.critical} tone="critical" />
        <RiskCard label="High Findings" value={risk.high} tone="high" />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <SeverityChart critical={risk.critical} high={risk.high} medium={risk.medium} low={risk.low} />
        <TrendChart points={trend} />
      </div>

      <div className="grid gap-3 md:grid-cols-4">
        <RiskCard label="Remediation Total" value={remediation?.total_tasks ?? 0} />
        <RiskCard label="Open Tasks" value={remediation?.open_tasks ?? 0} tone="high" />
        <RiskCard label="In Progress" value={remediation?.in_progress_tasks ?? 0} />
        <RiskCard label="Completed" value={remediation?.completed_tasks ?? 0} />
      </div>
    </div>
  );
}
