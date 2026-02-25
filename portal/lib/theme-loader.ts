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

import type { ClientTheme } from '@/lib/types';

let cachedTheme: ClientTheme | null = null;

const DEFAULT_THEME: ClientTheme = {
  company_name: 'VectorVue Customer',
  logo_url: null,
  colors: {
    primary: '#121735',
    accent: '#8A2BE2',
    background: '#0A0F2D',
    foreground: '#E6E9F2',
    danger: '#FF4D4F',
    success: '#00C896'
  }
};

function hexToRgb(hex: string): string {
  const raw = hex.trim().replace('#', '');
  const expanded = raw.length === 3 ? raw.split('').map((x) => `${x}${x}`).join('') : raw;
  if (!/^[0-9a-fA-F]{6}$/.test(expanded)) return '0 0 0';
  const n = Number.parseInt(expanded, 16);
  const r = (n >> 16) & 255;
  const g = (n >> 8) & 255;
  const b = n & 255;
  return `${r} ${g} ${b}`;
}

function applyTheme(theme: ClientTheme): void {
  const root = document.documentElement;
  const { colors } = theme;

  root.style.setProperty('--vv-bg-primary', colors.background);
  root.style.setProperty('--vv-bg-secondary', colors.primary);
  root.style.setProperty('--vv-accent', colors.accent);
  root.style.setProperty('--vv-text-primary', colors.foreground);
  root.style.setProperty('--vv-error', colors.danger);
  root.style.setProperty('--vv-success', colors.success);
  root.style.setProperty('--vv-bg-primary-rgb', hexToRgb(colors.background));
  root.style.setProperty('--vv-bg-secondary-rgb', hexToRgb(colors.primary));
  root.style.setProperty('--vv-accent-rgb', hexToRgb(colors.accent));
  root.style.setProperty('--vv-text-primary-rgb', hexToRgb(colors.foreground));
  root.style.setProperty('--vv-error-rgb', hexToRgb(colors.danger));
  root.style.setProperty('--vv-success-rgb', hexToRgb(colors.success));
}

export function getCachedTheme(): ClientTheme | null {
  return cachedTheme;
}

export function applyCachedOrDefaultTheme(): ClientTheme {
  const theme = cachedTheme ?? DEFAULT_THEME;
  if (typeof document !== 'undefined') {
    applyTheme(theme);
  }
  return theme;
}

export async function loadTheme(): Promise<ClientTheme> {
  if (cachedTheme) {
    applyTheme(cachedTheme);
    return cachedTheme;
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3500);
    let res: Response;
    try {
      res = await fetch('/api/proxy/theme', {
        credentials: 'include',
        cache: 'no-store',
        signal: controller.signal
      });
    } finally {
      clearTimeout(timer);
    }
    if (!res.ok) throw new Error(`Theme API ${res.status}`);
    const payload = (await res.json()) as ClientTheme;
    cachedTheme = payload;
    applyTheme(payload);
    return payload;
  } catch {
    cachedTheme = DEFAULT_THEME;
    applyTheme(DEFAULT_THEME);
    return DEFAULT_THEME;
  }
}
