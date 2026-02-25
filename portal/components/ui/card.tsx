import { PropsWithChildren } from 'react';

export function Card({ children }: PropsWithChildren) {
  return <div className="rounded-xl border border-slate-700 bg-panel p-4">{children}</div>;
}
