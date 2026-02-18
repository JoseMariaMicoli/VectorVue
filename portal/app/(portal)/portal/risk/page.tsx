import { Card } from '@/components/ui/card';
import { apiFetch } from '@/lib/api';
import type { RiskSummary } from '@/lib/types';

export default async function RiskPage() {
  const risk = await apiFetch<RiskSummary>('/api/v1/client/risk');

  return (
    <Card>
      <h1 className="mb-4 text-xl font-semibold">Risk Summary</h1>
      <div className="grid grid-cols-2 gap-3 text-sm">
        <p>Critical: {risk.critical}</p>
        <p>High: {risk.high}</p>
        <p>Medium: {risk.medium}</p>
        <p>Low: {risk.low}</p>
        <p className="col-span-2 font-semibold">Score: {risk.score}</p>
      </div>
    </Card>
  );
}
