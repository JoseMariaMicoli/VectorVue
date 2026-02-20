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

import { useEffect, useState } from 'react';

import { applyCachedOrDefaultTheme, loadTheme } from '@/lib/theme-loader';
import type { ClientTheme } from '@/lib/types';

type ThemeBootstrapProps = {
  initialTheme?: ClientTheme | null;
  children: React.ReactNode;
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

function applyThemeFromServer(theme: ClientTheme | null | undefined): void {
  if (!theme) return;
  const root = document.documentElement;
  const pairs: Array<[string, string]> = [
    ['--primary', theme.colors.primary],
    ['--accent', theme.colors.accent],
    ['--background', theme.colors.background],
    ['--foreground', theme.colors.foreground],
    ['--danger', theme.colors.danger],
    ['--success', theme.colors.success],
    ['--primary-rgb', hexToRgb(theme.colors.primary)],
    ['--accent-rgb', hexToRgb(theme.colors.accent)],
    ['--background-rgb', hexToRgb(theme.colors.background)],
    ['--foreground-rgb', hexToRgb(theme.colors.foreground)],
    ['--danger-rgb', hexToRgb(theme.colors.danger)],
    ['--success-rgb', hexToRgb(theme.colors.success)]
  ];
  for (const [k, v] of pairs) {
    root.style.setProperty(k, v);
  }
}

export default function ThemeBootstrap({ initialTheme, children }: ThemeBootstrapProps) {
  const [ready, setReady] = useState(false);

  useEffect(() => {
    let active = true;
    const failSafe = window.setTimeout(() => {
      if (active) {
        applyCachedOrDefaultTheme();
        setReady(true);
      }
    }, 4000);
    applyThemeFromServer(initialTheme);
    if (!initialTheme) {
      applyCachedOrDefaultTheme();
    }
    loadTheme().finally(() => {
      if (active) setReady(true);
    });
    return () => {
      active = false;
      window.clearTimeout(failSafe);
    };
  }, [initialTheme]);

  if (!ready) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-bg text-sm text-muted">
        Loading tenant theme...
      </div>
    );
  }

  return <>{children}</>;
}
