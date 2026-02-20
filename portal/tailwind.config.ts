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

import type { Config } from 'tailwindcss';

const config: Config = {
  content: [
    './app/**/*.{ts,tsx}',
    './components/**/*.{ts,tsx}',
    './lib/**/*.{ts,tsx}'
  ],
  theme: {
    extend: {
      colors: {
        bg: 'rgb(var(--background-rgb) / <alpha-value>)',
        panel: 'rgb(var(--primary-rgb) / <alpha-value>)',
        accent: 'rgb(var(--accent-rgb) / <alpha-value>)',
        text: 'rgb(var(--foreground-rgb) / <alpha-value>)',
        muted: 'rgb(var(--foreground-rgb) / 0.65)',
        danger: 'rgb(var(--danger-rgb) / <alpha-value>)',
        success: 'rgb(var(--success-rgb) / <alpha-value>)'
      }
    }
  },
  plugins: []
};

export default config;
