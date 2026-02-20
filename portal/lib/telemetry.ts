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

type PortalEventType =
  | 'FINDING_VIEWED'
  | 'FINDING_ACKNOWLEDGED'
  | 'REMEDIATION_OPENED'
  | 'REMEDIATION_COMPLETED'
  | 'REPORT_DOWNLOADED'
  | 'DASHBOARD_VIEWED';

type PortalObjectType = 'finding' | 'report' | 'dashboard' | 'remediation';
type Severity = 'critical' | 'high' | 'medium' | 'low' | null;

type TelemetryPayload = {
  event_type: PortalEventType;
  object_type: PortalObjectType;
  object_id?: string;
  severity?: Severity;
  metadata_json?: Record<string, string | number | boolean | null>;
};

const ENDPOINT = '/api/proxy/events';
const DASHBOARD_THROTTLE_MS = 60_000;

function severityFromValue(raw: string | number | null | undefined): Severity {
  if (raw == null) return null;
  if (typeof raw === 'string') {
    const s = raw.trim().toLowerCase();
    if (s === 'critical' || s === 'high' || s === 'medium' || s === 'low') return s;
    const n = Number(s);
    if (Number.isNaN(n)) return null;
    if (n >= 9) return 'critical';
    if (n >= 7) return 'high';
    if (n >= 4) return 'medium';
    return 'low';
  }
  if (raw >= 9) return 'critical';
  if (raw >= 7) return 'high';
  if (raw >= 4) return 'medium';
  return 'low';
}

function sendEvent(payload: TelemetryPayload): void {
  const body = JSON.stringify({
    ...payload,
    object_id: payload.object_id ?? null,
    severity: payload.severity ?? null,
    timestamp: new Date().toISOString()
  });

  try {
    if (typeof navigator !== 'undefined' && typeof navigator.sendBeacon === 'function') {
      const blob = new Blob([body], { type: 'application/json' });
      navigator.sendBeacon(ENDPOINT, blob);
      return;
    }
  } catch {
    // Ignore and fallback to fetch.
  }

  fetch(ENDPOINT, {
    method: 'POST',
    credentials: 'include',
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json' },
    body,
    keepalive: true
  }).catch(() => undefined);
}

export function trackFindingView(id: number | string, severity?: string | number | null): void {
  sendEvent({
    event_type: 'FINDING_VIEWED',
    object_type: 'finding',
    object_id: String(id),
    severity: severityFromValue(severity)
  });
}

export function trackFindingAcknowledged(id: number | string, severity?: string | number | null): void {
  sendEvent({
    event_type: 'FINDING_ACKNOWLEDGED',
    object_type: 'finding',
    object_id: String(id),
    severity: severityFromValue(severity)
  });
}

export function trackDashboardView(dashboardName = 'overview'): void {
  const key = `vv_dash_view_${dashboardName}`;
  const now = Date.now();
  const last = Number(sessionStorage.getItem(key) ?? 0);
  if (Number.isFinite(last) && now - last < DASHBOARD_THROTTLE_MS) return;
  sessionStorage.setItem(key, String(now));

  sendEvent({
    event_type: 'DASHBOARD_VIEWED',
    object_type: 'dashboard',
    object_id: dashboardName
  });
}

export function trackReportDownload(id: number | string): void {
  sendEvent({
    event_type: 'REPORT_DOWNLOADED',
    object_type: 'report',
    object_id: String(id)
  });
}

export function trackRemediationAction(id: number | string, status?: string | null): void {
  const normalized = (status ?? '').toLowerCase();
  const done = normalized.includes('done') || normalized.includes('complete') || normalized.includes('closed');
  sendEvent({
    event_type: done ? 'REMEDIATION_COMPLETED' : 'REMEDIATION_OPENED',
    object_type: 'remediation',
    object_id: String(id),
    metadata_json: status ? { status } : undefined
  });
}

