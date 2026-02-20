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

import { Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';

type TrendPoint = {
  day: string;
  score: number;
};

type TrendChartProps = {
  points: TrendPoint[];
};

export default function TrendChart({ points }: TrendChartProps) {
  if (points.length === 0) {
    return (
      <div className="rounded-lg border border-slate-700 bg-panel p-4">
        <h2 className="mb-3 text-sm font-semibold">30-Day Risk Trend</h2>
        <p className="text-sm text-muted">No trend data available yet.</p>
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-slate-700 bg-panel p-4">
      <h2 className="mb-3 text-sm font-semibold">30-Day Risk Trend</h2>
      <div className="h-60">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={points}>
            <XAxis dataKey="day" tick={{ fontSize: 12 }} />
            <YAxis domain={[0, 10]} tick={{ fontSize: 12 }} />
            <Tooltip />
            <Line type="monotone" dataKey="score" stroke="#22d3ee" strokeWidth={2} dot={false} />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
