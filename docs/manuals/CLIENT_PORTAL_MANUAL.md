<sub>Copyright (c) 2026 José María Micoli | Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}</sub>

# VectorVue v4.1 Client Portal Manual (Phase 7)

## Scope

Phase 7 delivers a customer-facing read-only portal running in Docker behind nginx TLS termination.

## Access

1. Deploy stack: `make deploy`
2. Open: `https://127.0.0.1/login`
3. Seed demo identities: `make seed-clients`
4. Login with a seeded panel user (defaults):
   - Panel 1 tenant: `ACME Industries` (`10000000-0000-0000-0000-000000000001`)
     - `acme_viewer` / `AcmeView3r!`
     - `acme_operator` / `AcmeOperat0r!`
   - Panel 2 tenant: `Globex Corporation` (`20000000-0000-0000-0000-000000000002`)
     - `globex_viewer` / `GlobexView3r!`
     - `globex_operator` / `GlobexOperat0r!`
5. For custom credentials/tenants, use Makefile overrides documented in [Demo Access Matrix](./DEMO_ACCESS_MATRIX.md).

## Portal Pages

- `/portal/findings`: tenant-scoped findings table
- `/portal/findings/{id}`: finding detail + evidence gallery
- `/portal/reports`: report cards with PDF/HTML download actions
- `/portal/risk`: analytics dashboard (overall score, severity pie, 30-day trend)
- `/portal/remediation`: remediation tracking table with status badges

## Phase 7C Features

- Findings severity filter and deterministic sorting
- Findings export: JSON and CSV
- Finding timeline visualization (evidence-backed steps)
- Polling notification center with alert preferences
- Remediation timeline and completion verification display
- Multilingual topbar toggle (EN/ES)
- Brand configuration via environment:
  - `NEXT_PUBLIC_BRAND_NAME`
  - `NEXT_PUBLIC_BRAND_ACCENT`

## Security Model

- JWT is stored in an `httpOnly` cookie (`vv_access_token`).
- `/portal/*` is protected by middleware.
- API requests are tenant-scoped and read-only.

## Docker and Proxy Notes

- Public entrypoint is nginx on `443` and `80`.
- Use `https://<host>/...`, not container ports.
- Portal fetches use relative paths and proxy-aware routing.

## Troubleshooting

- If login fails after reset/seed, run:
  - `make phase65-migrate`
  - `make seed-clients`
- If pages are stale, hard refresh browser (`Ctrl+Shift+R`).
