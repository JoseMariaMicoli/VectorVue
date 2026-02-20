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

import { useEffect, useMemo, useState } from 'react';

import { type PortalLang, t } from '@/lib/i18n';

type NotificationCenterProps = {
  lang: PortalLang;
};

type Prefs = {
  polling: boolean;
  findingsAlerts: boolean;
  remediationAlerts: boolean;
};

const PREFS_KEY = 'vv_portal_alert_prefs';

export default function NotificationCenter({ lang }: NotificationCenterProps) {
  const [open, setOpen] = useState(false);
  const [prefs, setPrefs] = useState<Prefs>({ polling: true, findingsAlerts: true, remediationAlerts: true });
  const [messages, setMessages] = useState<string[]>([]);
  const [lastFindingTotal, setLastFindingTotal] = useState<number | null>(null);
  const [lastRemediationTotal, setLastRemediationTotal] = useState<number | null>(null);

  useEffect(() => {
    try {
      const raw = localStorage.getItem(PREFS_KEY);
      if (raw) setPrefs(JSON.parse(raw) as Prefs);
    } catch {
      // Keep defaults.
    }
  }, []);

  useEffect(() => {
    localStorage.setItem(PREFS_KEY, JSON.stringify(prefs));
  }, [prefs]);

  useEffect(() => {
    if (!prefs.polling) return;
    let active = true;

    async function poll() {
      try {
        const [findingsRes, remediationRes] = await Promise.all([
          fetch('/api/proxy/findings?page=1&page_size=1', { credentials: 'include', cache: 'no-store' }),
          fetch('/api/proxy/remediation', { credentials: 'include', cache: 'no-store' })
        ]);

        if (!active || !findingsRes.ok || !remediationRes.ok) return;

        const findingsData = (await findingsRes.json()) as { total?: number };
        const remediationData = (await remediationRes.json()) as { items?: unknown[] };

        const fTotal = findingsData.total ?? 0;
        const rTotal = remediationData.items?.length ?? 0;

        if (prefs.findingsAlerts && lastFindingTotal !== null && fTotal > lastFindingTotal) {
          setMessages((prev) => [`${fTotal - lastFindingTotal} new finding(s) available.`, ...prev].slice(0, 8));
        }

        if (prefs.remediationAlerts && lastRemediationTotal !== null && rTotal !== lastRemediationTotal) {
          setMessages((prev) => [`Remediation queue changed (${lastRemediationTotal} -> ${rTotal}).`, ...prev].slice(0, 8));
        }

        setLastFindingTotal(fTotal);
        setLastRemediationTotal(rTotal);
      } catch {
        // ignore transient errors
      }
    }

    poll();
    const timer = setInterval(poll, 30000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [prefs, lastFindingTotal, lastRemediationTotal]);

  const count = messages.length;
  const badge = useMemo(() => (count > 9 ? '9+' : String(count)), [count]);

  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="rounded border border-slate-700 px-3 py-2 text-xs hover:bg-slate-800"
      >
        {t(lang, 'notifications')} {count > 0 ? `(${badge})` : ''}
      </button>

      {open ? (
        <div className="absolute right-0 z-20 mt-2 w-96 rounded-lg border border-slate-700 bg-panel p-3 shadow-lg">
          <p className="mb-2 text-xs uppercase tracking-wide text-muted">{t(lang, 'preferences')}</p>
          <label className="mb-1 flex items-center gap-2 text-xs">
            <input type="checkbox" checked={prefs.polling} onChange={(e) => setPrefs((p) => ({ ...p, polling: e.target.checked }))} />
            {t(lang, 'polling')}
          </label>
          <label className="mb-1 flex items-center gap-2 text-xs">
            <input type="checkbox" checked={prefs.findingsAlerts} onChange={(e) => setPrefs((p) => ({ ...p, findingsAlerts: e.target.checked }))} />
            {t(lang, 'findings_alerts')}
          </label>
          <label className="mb-3 flex items-center gap-2 text-xs">
            <input type="checkbox" checked={prefs.remediationAlerts} onChange={(e) => setPrefs((p) => ({ ...p, remediationAlerts: e.target.checked }))} />
            {t(lang, 'remediation_alerts')}
          </label>

          <div className="max-h-56 overflow-y-auto rounded border border-slate-800 p-2 text-xs">
            {messages.length === 0 ? (
              <p className="text-muted">No alerts yet.</p>
            ) : (
              <ul className="space-y-1">
                {messages.map((msg, idx) => (
                  <li key={`${msg}-${idx}`} className="border-b border-slate-900 pb-1">
                    {msg}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      ) : null}
    </div>
  );
}
