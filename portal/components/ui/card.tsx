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

import { PropsWithChildren } from 'react';

export function Card({ children }: PropsWithChildren) {
  return <div className="rounded-xl border border-slate-700 bg-panel p-4">{children}</div>;
}
