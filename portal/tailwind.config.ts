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
        bg: '#0b0e14',
        panel: '#111827',
        accent: '#22d3ee',
        text: '#e5e7eb',
        muted: '#94a3b8'
      }
    }
  },
  plugins: []
};

export default config;
