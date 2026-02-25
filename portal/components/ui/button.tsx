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

import { ButtonHTMLAttributes } from 'react';

export function Button(props: ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      {...props}
      className={`rounded-lg bg-accent px-4 py-2 text-sm font-semibold text-white shadow-accent-glow transition-colors hover:bg-accent-hover disabled:cursor-not-allowed disabled:opacity-60 ${props.className ?? ''}`}
    />
  );
}
