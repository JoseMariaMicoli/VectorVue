'use client';

import { useEffect, useState } from 'react';

import { Card } from '@/components/ui/card';
import { trackFindingAcknowledged, trackFindingView } from '@/lib/telemetry';
import type { ClientEvidenceItem, ClientFindingDetail } from '@/lib/types';

type EvidenceResponse = { finding_id: number; items: ClientEvidenceItem[] };

export default function FindingDetailPage({ params }: { params: { id: string } }) {
  const [finding, setFinding] = useState<ClientFindingDetail | null>(null);
  const [evidence, setEvidence] = useState<ClientEvidenceItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;

    async function run() {
      try {
        setLoading(true);
        const [fRes, eRes] = await Promise.all([
          fetch(`/api/proxy/findings/${params.id}`, { credentials: 'include', cache: 'no-store' }),
          fetch(`/api/proxy/evidence/${params.id}`, { credentials: 'include', cache: 'no-store' })
        ]);
        if (!fRes.ok) throw new Error(`Finding API ${fRes.status}`);
        if (!eRes.ok) throw new Error(`Evidence API ${eRes.status}`);
        const fData = (await fRes.json()) as ClientFindingDetail;
        const eData = (await eRes.json()) as EvidenceResponse;
        if (!active) return;
        setFinding(fData);
        setEvidence(eData.items ?? []);
      } catch (err) {
        if (active) setError(err instanceof Error ? err.message : 'Failed to load finding detail');
      } finally {
        if (active) setLoading(false);
      }
    }

    run();
    return () => {
      active = false;
    };
  }, [params.id]);

  useEffect(() => {
    if (!finding?.id) return;
    trackFindingView(finding.id, finding.cvss_score ?? null);
    const timer = window.setTimeout(() => {
      trackFindingAcknowledged(finding.id, finding.cvss_score ?? null);
    }, 5000);
    return () => window.clearTimeout(timer);
  }, [finding]);

  if (loading) return <p className="text-sm text-muted">Loading finding detail...</p>;
  if (error || !finding) return <p className="text-sm text-red-400">Unable to load finding detail: {error ?? 'unknown'}</p>;

  return (
    <div className="space-y-4">
      <Card>
        <h1 className="mb-2 text-xl font-semibold">{finding.title}</h1>
        <p className="text-sm text-muted">Status: {finding.status} | CVSS: {finding.cvss_score ?? '-'}</p>
        <p className="mt-3 text-sm">{finding.description ?? 'No description provided.'}</p>
      </Card>

      <Card>
        <h2 className="mb-3 text-lg font-semibold">Evidence Gallery</h2>
        <ul className="space-y-2 text-sm">
          {evidence.map((item) => (
            <li key={item.id} className="rounded border border-slate-800 p-3">
              <p>{item.artifact_type}</p>
              <p className="text-muted">{item.description ?? 'No description'}</p>
              <a href={item.download_url} className="text-accent hover:underline">
                Open Evidence
              </a>
            </li>
          ))}
        </ul>
      </Card>

      <Card>
        <h2 className="mb-3 text-lg font-semibold">Timeline Visualization</h2>
        <ol className="space-y-2 text-sm">
          {evidence.map((item, idx) => (
            <li key={`timeline-${item.id}`} className="rounded border border-slate-800 p-3">
              <p className="font-medium">Step {idx + 1}: {item.artifact_type}</p>
              <p className="text-muted">{item.description ?? 'Evidence artifact captured.'}</p>
            </li>
          ))}
          {evidence.length === 0 ? <li className="text-muted">No evidence timeline available.</li> : null}
        </ol>
      </Card>
    </div>
  );
}
