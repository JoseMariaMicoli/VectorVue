'use client';

/*
Copyright (c) 2026 NyxeraLabs
Author: José María Micoli
Licensed under BSL 1.1
Change Date: 2033-02-17 → Apache-2.0
*/

import { useEffect, useMemo, useState, type UIEvent } from 'react';

import { Card } from '@/components/ui/card';

type LegalDocument = {
  name: string;
  path: string;
  content: string;
};

type LegalPayload = {
  documents: LegalDocument[];
  document_hash: string;
  version: string;
  deployment_mode: string;
};

function renderError(code?: string): string | null {
  if (!code) return null;
  if (code === 'username_password_required') return 'Username and password are required.';
  if (code === 'password_mismatch') return 'Passwords must match.';
  if (code === 'tenant_id_required') return 'Tenant ID is required for this host.';
  if (code === 'legal_acceptance_required') return 'Legal acceptance is required.';
  if (code === 'legal_record_failed') return 'Unable to persist legal acceptance.';
  if (code === 'registration_failed') return 'Registration failed.';
  return 'Registration failed.';
}

export default function RegisterPage() {
  const [legal, setLegal] = useState<LegalPayload | null>(null);
  const [scrolled, setScrolled] = useState<Record<number, boolean>>({});
  const [loaded, setLoaded] = useState(false);
  const params = useMemo(() => new URLSearchParams(typeof window !== 'undefined' ? window.location.search : ''), []);
  const error = renderError(params.get('error') ?? undefined);
  const tenantIdDefault = params.get('tenant_id') ?? '';

  useEffect(() => {
    let active = true;
    fetch('/api/legal/documents?mode=self-hosted', { cache: 'no-store' })
      .then((res) => res.json())
      .then((data: LegalPayload) => {
        if (!active) return;
        setLegal(data);
      })
      .finally(() => {
        if (active) setLoaded(true);
      });
    return () => {
      active = false;
    };
  }, []);

  const allScrolled = Boolean(
    legal &&
      legal.documents.length > 0 &&
      legal.documents.every((_, idx) => Boolean(scrolled[idx]))
  );

  const onScrollDoc = (index: number, event: UIEvent<HTMLDivElement>) => {
    const el = event.currentTarget;
    const max = el.scrollHeight - el.clientHeight;
    const ratio = max <= 0 ? 1 : el.scrollTop / max;
    if (ratio >= 0.95) {
      setScrolled((prev) => ({ ...prev, [index]: true }));
    }
  };

  return (
    <main className="min-h-screen bg-bg-primary p-6">
      <Card>
        <h1 className="mb-2 text-xl font-semibold text-metallic">Register</h1>
        <p className="mb-4 text-sm text-text-secondary">Complete legal review before account creation.</p>
        {error ? <p className="mb-4 text-sm text-danger">{error}</p> : null}

        {!loaded ? <p className="text-sm text-text-secondary">Loading legal documents...</p> : null}
        {legal ? (
          <section className="mb-6 space-y-4">
            {legal.documents.map((doc, idx) => (
              <div key={doc.name} className="rounded-xl border border-[color:var(--vv-border-subtle)] bg-bg-primary p-3">
                <div className="mb-2 flex items-center justify-between">
                  <h2 className="text-sm font-semibold">{doc.name}</h2>
                  <span className="text-xs text-text-secondary">{scrolled[idx] ? 'Scrolled' : 'Scroll to 95%'}</span>
                </div>
                <div
                  className="h-44 overflow-y-auto rounded-lg border border-[color:var(--vv-border-subtle)] bg-bg-secondary p-3 text-xs"
                  onScroll={(event) => onScrollDoc(idx, event)}
                >
                  <pre className="whitespace-pre-wrap">{doc.content}</pre>
                </div>
              </div>
            ))}
          </section>
        ) : null}

        <form action="/api/auth/register" method="post" className="space-y-3">
          <input type="hidden" name="document_hash" value={legal?.document_hash ?? ''} />
          <input type="hidden" name="version" value={legal?.version ?? ''} />
          <input type="hidden" name="deployment_mode" value={legal?.deployment_mode ?? 'self-hosted'} />
          <label className="block text-sm">
            <span className="mb-1 block text-text-secondary">Tenant ID</span>
            <input
              type="text"
              name="tenant_id"
              defaultValue={tenantIdDefault}
              className="w-full rounded-lg border border-[color:var(--vv-border-subtle)] bg-bg-primary px-3 py-2 text-text-primary"
            />
          </label>
          <label className="block text-sm">
            <span className="mb-1 block text-text-secondary">Username</span>
            <input
              type="text"
              name="username"
              required
              className="w-full rounded-lg border border-[color:var(--vv-border-subtle)] bg-bg-primary px-3 py-2 text-text-primary"
            />
          </label>
          <label className="block text-sm">
            <span className="mb-1 block text-text-secondary">Password</span>
            <input
              type="password"
              name="password"
              required
              className="w-full rounded-lg border border-[color:var(--vv-border-subtle)] bg-bg-primary px-3 py-2 text-text-primary"
            />
          </label>
          <label className="block text-sm">
            <span className="mb-1 block text-text-secondary">Confirm Password</span>
            <input
              type="password"
              name="confirm_password"
              required
              className="w-full rounded-lg border border-[color:var(--vv-border-subtle)] bg-bg-primary px-3 py-2 text-text-primary"
            />
          </label>
          <label className="flex items-start gap-2 text-sm text-text-secondary">
            <input type="checkbox" name="accepted" disabled={!allScrolled} className="mt-0.5" />
            <span>I have read and agree to all legal documents.</span>
          </label>
          <button
            type="submit"
            disabled={!allScrolled}
            className="w-full rounded-lg bg-accent px-4 py-2 font-medium text-white shadow-accent-glow transition-colors hover:bg-accent-hover disabled:cursor-not-allowed disabled:opacity-50"
          >
            Register
          </button>
        </form>
      </Card>
    </main>
  );
}
