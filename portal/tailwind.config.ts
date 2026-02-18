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
