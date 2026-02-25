/*
Copyright (c) 2026 NyxeraLabs
Author: José María Micoli
Licensed under BSL 1.1
Change Date: 2033-02-17 -> Apache-2.0
*/

export const brandTheme = {
  colors: {
    bgPrimary: '#0A0F2D',
    bgSecondary: '#121735',
    accentPurple: '#8A2BE2',
    accentPurpleHover: '#9D4DFF',
    success: '#00C896',
    warning: '#FFB020',
    error: '#FF4D4F',
    textPrimary: '#E6E9F2',
    textSecondary: '#AAB2D5',
    borderSubtle: 'rgba(255, 255, 255, 0.05)'
  },
  gradients: {
    metallicLight: 'linear-gradient(90deg, #D9E1F2 0%, #FFFFFF 50%, #C7CEDB 100%)'
  },
  typography: {
    heading: "'Sora', 'Inter', sans-serif",
    body: "'Inter', sans-serif"
  },
  spacing: {
    radiusButton: '12px',
    radiusCard: '16px',
    navbarHeight: '40px'
  },
  attribution: {
    line1: 'VectorVue by Nyxera Labs',
    line2: '© 2026 Nyxera Labs. All rights reserved.'
  }
} as const;

export type BrandTheme = typeof brandTheme;
