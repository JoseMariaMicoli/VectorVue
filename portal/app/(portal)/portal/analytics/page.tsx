'use client';

import { useEffect, useMemo, useState } from 'react';
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';

import { Card } from '@/components/ui/card';
import { trackDashboardView } from '@/lib/telemetry';
import type { ClientFinding, ClientMLInsight, Paginated } from '@/lib/types';

type MlPoint = {
  name: string;
  score: number;
  confidence: number;
};

const FALLBACK_ML: ClientMLInsight = {
  score: 0,
  confidence: 0,
  explanation: 'Model output is being generated.',
  model_version: 'pending',
  generated_at: new Date(0).toISOString()
};

function extractCampaignIdFromTitle(title: string): number | null {
  const m = title.match(/\[campaign:(\d+)\]/i);
  return m ? Number(m[1]) : null;
}

function confidenceLabel(confidence: number): string {
  if (confidence >= 0.8) return 'high';
  if (confidence >= 0.6) return 'medium';
  return 'low';
}

export default function AnalyticsPage() {
  const [securityScore, setSecurityScore] = useState<ClientMLInsight>(FALLBACK_ML);
  const [residualRisk, setResidualRisk] = useState<ClientMLInsight>(FALLBACK_ML);
  const [detectionGaps, setDetectionGaps] = useState<ClientMLInsight>(FALLBACK_ML);
  const [anomalies, setAnomalies] = useState<ClientMLInsight>(FALLBACK_ML);
  const [operatorSuggestion, setOperatorSuggestion] = useState<ClientMLInsight>(FALLBACK_ML);
  const [campaignId, setCampaignId] = useState<number | null>(null);
  const [simulating, setSimulating] = useState(false);
  const [simulation, setSimulation] = useState<ClientMLInsight | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    trackDashboardView('analytics');
  }, []);

  useEffect(() => {
    let active = true;

    async function run() {
      try {
        setLoading(true);
        const findingsRes = await fetch('/api/proxy/findings?page=1&page_size=25', { credentials: 'include', cache: 'no-store' });
        if (!findingsRes.ok) throw new Error(`Findings API ${findingsRes.status}`);
        const findingsData = (await findingsRes.json()) as Paginated<ClientFinding>;
        const firstCampaignId = (findingsData.items ?? [])
          .map((f) => extractCampaignIdFromTitle(f.title))
          .find((id): id is number => id != null) ?? null;
        if (active) setCampaignId(firstCampaignId);

        const [securityRes, riskRes, gapsRes, anomaliesRes] = await Promise.all([
          fetch('/api/proxy/ml/security-score', { credentials: 'include', cache: 'no-store' }),
          fetch('/api/proxy/ml/risk', { credentials: 'include', cache: 'no-store' }),
          fetch('/api/proxy/ml/detection-gaps', { credentials: 'include', cache: 'no-store' }),
          fetch('/api/proxy/ml/anomalies', { credentials: 'include', cache: 'no-store' })
        ]);
        if (!securityRes.ok) throw new Error(`ML security-score API ${securityRes.status}`);
        if (!riskRes.ok) throw new Error(`ML risk API ${riskRes.status}`);
        if (!gapsRes.ok) throw new Error(`ML detection-gaps API ${gapsRes.status}`);
        if (!anomaliesRes.ok) throw new Error(`ML anomalies API ${anomaliesRes.status}`);

        const [securityData, riskData, gapsData, anomaliesData] = await Promise.all([
          securityRes.json(),
          riskRes.json(),
          gapsRes.json(),
          anomaliesRes.json()
        ]);
        if (!active) return;
        setSecurityScore((securityData as ClientMLInsight) ?? FALLBACK_ML);
        setResidualRisk((riskData as ClientMLInsight) ?? FALLBACK_ML);
        setDetectionGaps((gapsData as ClientMLInsight) ?? FALLBACK_ML);
        setAnomalies((anomaliesData as ClientMLInsight) ?? FALLBACK_ML);

        if (firstCampaignId != null) {
          const opRes = await fetch(`/api/proxy/ml/operator-suggestions/${firstCampaignId}`, { credentials: 'include', cache: 'no-store' });
          if (opRes.ok) {
            const opData = (await opRes.json()) as ClientMLInsight;
            if (active) setOperatorSuggestion(opData);
          }
        }
      } catch (err) {
        if (active) setError(err instanceof Error ? err.message : 'Failed to load analytics');
      } finally {
        if (active) setLoading(false);
      }
    }

    run();
    return () => {
      active = false;
    };
  }, []);

  const bars = useMemo<MlPoint[]>(
    () => [
      { name: 'Security Score', score: securityScore.score, confidence: securityScore.confidence },
      { name: 'Residual Risk', score: residualRisk.score, confidence: residualRisk.confidence },
      { name: 'Detection Coverage', score: detectionGaps.score, confidence: detectionGaps.confidence },
      { name: 'Anomaly Baseline', score: anomalies.score, confidence: anomalies.confidence },
      { name: 'Operator Suggestion', score: operatorSuggestion.score, confidence: operatorSuggestion.confidence }
    ],
    [anomalies, detectionGaps, operatorSuggestion, residualRisk, securityScore]
  );

  const timeline = useMemo(
    () =>
      [
        { label: 'Security Score generated', insight: securityScore },
        { label: 'Residual Risk generated', insight: residualRisk },
        { label: 'Detection Gap analysis generated', insight: detectionGaps },
        { label: 'Anomaly baseline generated', insight: anomalies },
        { label: 'Operator suggestions generated', insight: operatorSuggestion },
        simulation ? { label: 'Simulation generated', insight: simulation } : null
      ]
        .filter((item): item is { label: string; insight: ClientMLInsight } => item != null)
        .sort((a, b) => Date.parse(b.insight.generated_at) - Date.parse(a.insight.generated_at)),
    [anomalies, detectionGaps, operatorSuggestion, residualRisk, securityScore, simulation]
  );

  async function runSimulation() {
    try {
      setSimulating(true);
      const res = await fetch('/api/proxy/ml/simulate', {
        method: 'POST',
        credentials: 'include',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          scenario: 'hardening-sprint',
          controls_improvement: 0.18,
          detection_improvement: 0.14
        })
      });
      if (!res.ok) throw new Error(`ML simulate API ${res.status}`);
      const data = (await res.json()) as ClientMLInsight;
      setSimulation(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Simulation failed');
    } finally {
      setSimulating(false);
    }
  }

  if (loading) return <p className="text-sm text-muted">Loading Phase 8 analytics...</p>;
  if (error) return <p className="text-sm text-red-400">Unable to load analytics: {error}</p>;

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">Advanced Analytics</h1>
      <p className="text-sm text-muted">
        Tenant-scoped phase-8 intelligence with explainable outputs, model versions, and confidence ratings.
        {campaignId ? ` Campaign context: ${campaignId}.` : ''}
      </p>

      <div className="grid gap-3 md:grid-cols-5">
        {bars.map((bar) => (
          <Card key={bar.name}>
            <p className="text-xs uppercase tracking-wide text-muted">{bar.name}</p>
            <p className="mt-2 text-2xl font-semibold">{bar.score.toFixed(2)}</p>
            <p className="mt-1 text-xs text-muted">Confidence: {confidenceLabel(bar.confidence)} ({bar.confidence.toFixed(2)})</p>
          </Card>
        ))}
      </div>

      <Card>
        <h2 className="mb-3 text-sm font-semibold">Phase 8 Score Comparison (Bar)</h2>
        <div className="h-72">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={bars}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="name" tick={{ fontSize: 12 }} />
              <YAxis domain={[0, 1]} tick={{ fontSize: 12 }} />
              <Tooltip />
              <Bar dataKey="score" fill="#22d3ee" radius={[4, 4, 0, 0]} />
              <Bar dataKey="confidence" fill="#f59e0b" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </Card>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card>
          <h2 className="mb-3 text-sm font-semibold">Latest Explanations</h2>
          <ul className="space-y-3">
            <li className="text-sm"><strong>Security score:</strong> {securityScore.explanation}</li>
            <li className="text-sm"><strong>Residual risk:</strong> {residualRisk.explanation}</li>
            <li className="text-sm"><strong>Detection gaps:</strong> {detectionGaps.explanation}</li>
            <li className="text-sm"><strong>Anomalies:</strong> {anomalies.explanation}</li>
            <li className="text-sm"><strong>Operator suggestions:</strong> {operatorSuggestion.explanation}</li>
          </ul>
        </Card>

        <Card>
          <h2 className="mb-3 text-sm font-semibold">Model Timeline</h2>
          <ol className="space-y-2">
            {timeline.map((item) => (
              <li key={`${item.label}-${item.insight.model_version}-${item.insight.generated_at}`} className="rounded border border-slate-800 px-3 py-2">
                <p className="text-sm font-medium">{item.label}</p>
                <p className="text-xs text-muted">version={item.insight.model_version} | generated_at={item.insight.generated_at}</p>
              </li>
            ))}
          </ol>
        </Card>
      </div>

      <Card>
        <h2 className="mb-3 text-sm font-semibold">Defensive Simulation</h2>
        <p className="mb-3 text-sm text-muted">Run a what-if projection using phase-8 defensive intelligence models.</p>
        <button
          type="button"
          onClick={runSimulation}
          disabled={simulating}
          className="rounded bg-cyan-500 px-3 py-2 text-sm font-medium text-slate-950 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {simulating ? 'Running simulation...' : 'Run Hardening Simulation'}
        </button>
        {simulation ? (
          <p className="mt-3 text-sm text-muted">
            Projection score: {simulation.score.toFixed(2)} (confidence {simulation.confidence.toFixed(2)}) | version {simulation.model_version}
          </p>
        ) : null}
      </Card>
    </div>
  );
}
