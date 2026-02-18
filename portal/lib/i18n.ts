export type PortalLang = 'en' | 'es';

export const I18N: Record<PortalLang, Record<string, string>> = {
  en: {
    tenant: 'Tenant',
    logout: 'Logout',
    notifications: 'Notifications',
    preferences: 'Preferences',
    polling: 'Polling updates',
    findings_alerts: 'Finding alerts',
    remediation_alerts: 'Remediation alerts',
    findings: 'Findings',
    reports: 'Reports',
    risk: 'Risk',
    remediation: 'Remediation'
  },
  es: {
    tenant: 'Cliente',
    logout: 'Cerrar sesión',
    notifications: 'Notificaciones',
    preferences: 'Preferencias',
    polling: 'Actualizaciones automáticas',
    findings_alerts: 'Alertas de hallazgos',
    remediation_alerts: 'Alertas de remediación',
    findings: 'Hallazgos',
    reports: 'Reportes',
    risk: 'Riesgo',
    remediation: 'Remediación'
  }
};

export function t(lang: PortalLang, key: string): string {
  return I18N[lang]?.[key] ?? I18N.en[key] ?? key;
}
