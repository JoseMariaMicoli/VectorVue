import Link from 'next/link';

import { Card } from '@/components/ui/card';
import { apiFetch } from '@/lib/api';
import type { ClientFinding, Paginated } from '@/lib/types';

type FindingsPageProps = {
  searchParams?: {
    severity?: string;
    status?: string;
    page?: string;
    page_size?: string;
  };
};

export default async function FindingsPage({ searchParams }: FindingsPageProps) {
  const params = new URLSearchParams();
  if (searchParams?.severity) params.set('severity', searchParams.severity);
  if (searchParams?.status) params.set('status', searchParams.status);
  if (searchParams?.page) params.set('page', searchParams.page);
  if (searchParams?.page_size) params.set('page_size', searchParams.page_size);

  const qs = params.toString();
  const data = await apiFetch<Paginated<ClientFinding>>(`/api/v1/client/findings${qs ? `?${qs}` : ''}`);

  return (
    <Card>
      <h1 className="mb-4 text-xl font-semibold">Findings</h1>
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-muted">
            <th className="py-2">Title</th>
            <th className="py-2">CVSS</th>
            <th className="py-2">Approval</th>
            <th className="py-2">Action</th>
          </tr>
        </thead>
        <tbody>
          {data.items.map((f) => (
            <tr key={f.id} className="border-t border-slate-800">
              <td className="py-2">{f.title}</td>
              <td className="py-2">{f.cvss_score ?? '-'}</td>
              <td className="py-2">{f.approval_status}</td>
              <td className="py-2">
                <Link href={`/portal/findings/${f.id}`} className="text-accent hover:underline">View</Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}
