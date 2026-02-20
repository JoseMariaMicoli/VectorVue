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

import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts';

type SeverityChartProps = {
  critical: number;
  high: number;
  medium: number;
  low: number;
};

const COLORS = ['#ef4444', '#f59e0b', '#22c55e', '#38bdf8'];

export default function SeverityChart({ critical, high, medium, low }: SeverityChartProps) {
  const data = [
    { name: 'Critical', value: critical },
    { name: 'High', value: high },
    { name: 'Medium', value: medium },
    { name: 'Low', value: low }
  ].filter((item) => item.value > 0);

  return (
    <div className="rounded-lg border border-slate-700 bg-panel p-4">
      <h2 className="mb-3 text-sm font-semibold">Severity Distribution</h2>
      <div className="h-60">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie data={data} dataKey="value" nameKey="name" outerRadius={90} label>
              {data.map((entry, index) => (
                <Cell key={entry.name} fill={COLORS[index % COLORS.length]} />
              ))}
            </Pie>
            <Tooltip />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
