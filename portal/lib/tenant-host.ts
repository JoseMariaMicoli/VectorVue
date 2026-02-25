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

type TenantHostConfig = {
  tenantId: string;
  tenantName?: string;
};

function normalizeHost(rawHost: string | null | undefined): string {
  const host = String(rawHost ?? '').trim().toLowerCase();
  return host.split(':')[0];
}

function parseCompactMap(raw: string): Record<string, TenantHostConfig> {
  const out: Record<string, TenantHostConfig> = {};
  for (const chunk of raw.split(',')) {
    const pair = chunk.trim();
    if (!pair) continue;
    const idx = pair.indexOf('=');
    if (idx <= 0) continue;
    const host = normalizeHost(pair.slice(0, idx));
    const value = pair.slice(idx + 1).trim();
    if (!host || !value) continue;
    const parts = value.split('|').map((s) => s.trim()).filter(Boolean);
    if (!parts[0]) continue;
    out[host] = { tenantId: parts[0], tenantName: parts[1] };
  }
  return out;
}

function parseJsonMap(raw: string): Record<string, TenantHostConfig> {
  try {
    const payload = JSON.parse(raw) as Record<string, { tenant_id?: string; tenant_name?: string }>;
    const out: Record<string, TenantHostConfig> = {};
    for (const [k, v] of Object.entries(payload ?? {})) {
      const host = normalizeHost(k);
      if (!host || !v?.tenant_id) continue;
      out[host] = { tenantId: String(v.tenant_id), tenantName: v.tenant_name ? String(v.tenant_name) : undefined };
    }
    return out;
  } catch {
    return {};
  }
}

export function tenantHostMap(): Record<string, TenantHostConfig> {
  const json = process.env.VV_TENANT_HOST_MAP_JSON?.trim();
  if (json) {
    const parsed = parseJsonMap(json);
    if (Object.keys(parsed).length > 0) return parsed;
  }
  const compact = process.env.VV_TENANT_HOST_MAP?.trim() ?? '';
  return parseCompactMap(compact);
}

export function resolveTenantFromHost(host: string | null | undefined): TenantHostConfig | null {
  const normalized = normalizeHost(host);
  if (!normalized) return null;
  const mapping = tenantHostMap()[normalized];
  return mapping ?? null;
}

