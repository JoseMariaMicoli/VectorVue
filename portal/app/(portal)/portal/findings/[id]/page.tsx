import { Card } from '@/components/ui/card';
import { apiFetch } from '@/lib/api';
import type { ClientEvidenceItem, ClientFindingDetail } from '@/lib/types';

export default async function FindingDetailPage({ params }: { params: { id: string } }) {
  const finding = await apiFetch<ClientFindingDetail>(`/api/v1/client/findings/${params.id}`);
  const evidence = await apiFetch<{ finding_id: number; items: ClientEvidenceItem[] }>(
    `/api/v1/client/evidence/${params.id}`
  );

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
          {evidence.items.map((item) => (
            <li key={item.id} className="rounded border border-slate-800 p-3">
              <p>{item.artifact_type}</p>
              <p className="text-muted">{item.description ?? 'No description'}</p>
              <a href={item.download_url} className="text-accent hover:underline">Open Evidence</a>
            </li>
          ))}
        </ul>
      </Card>
    </div>
  );
}
