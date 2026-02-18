import type { ClientTheme } from '@/lib/types';

let cachedTheme: ClientTheme | null = null;

const DEFAULT_THEME: ClientTheme = {
  company_name: 'VectorVue Customer',
  logo_url: null,
  colors: {
    primary: '#0f172a',
    accent: '#22d3ee',
    background: '#0b0e14',
    foreground: '#e5e7eb',
    danger: '#ef4444',
    success: '#22c55e'
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

  root.style.setProperty('--primary', colors.primary);
  root.style.setProperty('--accent', colors.accent);
  root.style.setProperty('--background', colors.background);
  root.style.setProperty('--foreground', colors.foreground);
  root.style.setProperty('--danger', colors.danger);
  root.style.setProperty('--success', colors.success);
  root.style.setProperty('--primary-rgb', hexToRgb(colors.primary));
  root.style.setProperty('--accent-rgb', hexToRgb(colors.accent));
  root.style.setProperty('--background-rgb', hexToRgb(colors.background));
  root.style.setProperty('--foreground-rgb', hexToRgb(colors.foreground));
  root.style.setProperty('--danger-rgb', hexToRgb(colors.danger));
  root.style.setProperty('--success-rgb', hexToRgb(colors.success));
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
