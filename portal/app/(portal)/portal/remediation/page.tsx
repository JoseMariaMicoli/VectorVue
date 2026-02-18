import { Card } from '@/components/ui/card';
import { apiFetch } from '@/lib/api';
import type { RemediationTask } from '@/lib/types';

export default async function RemediationPage() {
  const data = await apiFetch<{ items: RemediationTask[] }>('/api/v1/client/remediation');

  return (
    <Card>
      <h1 className="mb-4 text-xl font-semibold">Remediation</h1>
      <ul className="space-y-2 text-sm">
        {data.items.map((task) => (
          <li key={task.id} className="rounded border border-slate-800 p-3">
            <p className="font-medium">{task.title}</p>
            <p className="text-muted">Status: {task.status}</p>
          </li>
        ))}
      </ul>
    </Card>
  );
}
