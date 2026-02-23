/*
VectorVue CLI Theme
*/

export const cliTheme = {
  colors: {
    bgPrimary: '#0A0F2D',
    bgSecondary: '#121735',
    accent: '#8A2BE2',
    accentHover: '#9D4DFF',
    metallicStart: '#D9E1F2',
    metallicMid: '#FFFFFF',
    metallicEnd: '#C7CEDB',
    success: '#00C896',
    warning: '#FFB020',
    error: '#FF4D4F',
    textPrimary: '#E6E9F2',
    textSecondary: '#AAB2D5'
  },
  attribution: {
    line1: 'VectorVue by Nyxera Labs',
    line2: '© 2026 Nyxera Labs. All rights reserved.'
  }
} as const;

export type CliTheme = typeof cliTheme;
