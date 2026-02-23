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
      fontFamily: {
        sans: ['var(--font-inter)', 'Inter', 'sans-serif'],
        heading: ['var(--font-sora)', 'Inter', 'sans-serif']
      },
      colors: {
        bg: {
          primary: 'rgb(var(--vv-bg-primary-rgb) / <alpha-value>)',
          secondary: 'rgb(var(--vv-bg-secondary-rgb) / <alpha-value>)'
        },
        panel: 'rgb(var(--vv-bg-secondary-rgb) / <alpha-value>)',
        accent: {
          DEFAULT: 'rgb(var(--vv-accent-rgb) / <alpha-value>)',
          hover: 'rgb(var(--vv-accent-hover-rgb) / <alpha-value>)'
        },
        text: {
          primary: 'rgb(var(--vv-text-primary-rgb) / <alpha-value>)',
          secondary: 'rgb(var(--vv-text-secondary-rgb) / <alpha-value>)'
        },
        muted: 'rgb(var(--vv-text-secondary-rgb) / <alpha-value>)',
        danger: 'rgb(var(--vv-error-rgb) / <alpha-value>)',
        success: 'rgb(var(--vv-success-rgb) / <alpha-value>)',
        warning: 'rgb(var(--vv-warning-rgb) / <alpha-value>)'
      },
      borderRadius: {
        xl: '16px',
        lg: '12px'
      },
      boxShadow: {
        'accent-glow': '0 0 0 1px rgb(var(--vv-accent-rgb) / 0.30), 0 8px 28px rgb(var(--vv-accent-rgb) / 0.22)'
      },
      backgroundImage: {
        metallic: 'linear-gradient(90deg, #D9E1F2 0%, #FFFFFF 50%, #C7CEDB 100%)'
      },
      minHeight: {
        navbar: '40px'
      }
    }
  },
  plugins: []
};

export default config;
