<sub>Copyright (c) 2026 José María Micoli | Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}</sub>

# VectorVue v4.1 Client Portal Manual

## Scope

This manual explains exactly how a client user logs in and uses every portal page.
It is intentionally workflow-first and avoids internal engineering naming.

The portal is read-only and designed for:
- security transparency with customers
- evidence review
- remediation follow-up
- report consumption
- risk communication

## Access

### Prerequisites
1. Platform stack is up (`make deploy`).
2. Demo or production users exist (`make seed-clients` for demo).
3. Correct tenant host is configured.

### Login Procedure (Step-by-Step)
1. Open the tenant login URL:
   - `https://acme.vectorvue.local/login`
   - `https://globex.vectorvue.local/login`
   - fallback: `https://127.0.0.1/login`
2. Confirm tenant label shown on the login page.
3. Enter username and password.
4. Click `Login`.
5. Verify successful redirect to `/portal/overview`.

If login fails, follow the troubleshooting section at the end.

## Portal Pages

### 1) Overview (`/portal/overview`)

Use this page for executive and operational snapshot.

Steps:
1. Open `Overview` from the sidebar.
2. Read top KPI cards:
   - overall risk score
   - total findings
   - active remediation
   - published reports
3. Review bar chart `Findings by Campaign`.
4. Review bar chart `Remediation by Status`.
5. Review risk trend chart.
6. Review `Operational Timeline` list for latest activity.

Expected outcome:
- fast understanding of current client security state.

### 2) Findings (`/portal/findings`)

Use this page for triage and evidence navigation.

Steps:
1. Open `Findings` from the sidebar.
2. Use severity dropdown to filter (`All`, `Critical`, `High`, `Medium`, `Low`).
3. Click `Export JSON` or `Export CSV` when needed.
4. Click `View` on a finding row.
5. In detail page, review:
   - description
   - CVSS
   - evidence gallery
   - timeline visualization

Expected outcome:
- identify high-risk findings and inspect proof rapidly.

### 3) Reports (`/portal/reports`)

Use this page to consume formal deliverables.

Steps:
1. Open `Reports` from the sidebar.
2. Check each report card status.
3. Click `Download PDF` for presentation and sign-off workflows.
4. Click `Download HTML` for browser-native sharing and review.

Expected outcome:
- retrieve approved reporting artifacts with minimal friction.

### 4) Risk (`/portal/risk`)

Use this page for risk communication and trend analysis.

Steps:
1. Open `Risk` from the sidebar.
2. Review:
   - overall score
   - critical/high counts
   - severity distribution chart
   - 30-day trend
   - remediation summary cards

Expected outcome:
- communicate security posture over time to stakeholders.

### 5) Remediation (`/portal/remediation`)

Use this page for closure tracking.

Steps:
1. Open `Remediation` from the sidebar.
2. Review each task row:
   - task title
   - priority
   - owner
   - due date
   - verification state
   - status badge
3. Use row status to prioritize follow-up meetings.

Expected outcome:
- maintain visible remediation accountability.

## Day-to-Day Workflow (Recommended)

1. Start in `Overview` for status snapshot.
2. Move to `Findings` and filter `Critical` and `High`.
3. Open each critical finding and validate evidence.
4. Check `Remediation` to confirm ownership and status.
5. Download latest reports from `Reports`.
6. End in `Risk` to confirm trend direction before stakeholder updates.

## Client-Facing Features

- Findings severity filter and deterministic sorting
- Findings export (JSON/CSV)
- Finding detail with evidence gallery + timeline
- Report downloads (PDF/HTML)
- Risk charts (distribution + trend)
- Remediation status tracking
- Notification center
- Language toggle (EN/ES)
- Tenant branding support

## Security Model

- JWT stored in secure `httpOnly` cookie (`vv_access_token`)
- Tenant-scoped session and data access
- Read-only portal behavior for clients
- Middleware protection for `/portal/*` routes

## Docker and Proxy Notes

- Public entrypoint is nginx on `443` and `80`.
- Use `https://<host>/...`, not container ports.
- Portal fetches use relative paths and proxy-aware routing.

## Troubleshooting

- If login fails after reset/seed, run:
  - `make phase65-migrate`
  - `make phase7e-migrate`
  - `make seed-clients`
- If pages are stale, hard refresh browser (`Ctrl+Shift+R`).
- If host is not recognized, verify tenant host mapping in deployment env.
- If reports do not download, verify report visibility/status in API data.
