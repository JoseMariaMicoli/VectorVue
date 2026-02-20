<!--
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
-->

# VectorVue Client Portal Manual

This guide is written for client stakeholders using the portal for security transparency, remediation follow-up, and executive reporting.

## 1. Login and Access

1. Open your tenant URL:
   - `https://acme.vectorvue.local/login`
   - `https://globex.vectorvue.local/login`
2. Confirm tenant label on screen.
3. Enter credentials.
4. Verify redirect to `Overview`.

If login fails, see [Troubleshooting Guide](./TROUBLESHOOTING_GUIDE.md).

## 2. Portal Navigation

Recommended order for routine review:

1. Overview
2. Analytics
3. Findings
4. Remediation
5. Reports
6. Risk

## 3. Page-by-Page Workflows

### 3.1 Overview

Use for quick posture review.

Check:

- total findings
- high-risk findings
- active remediation count
- current risk trend

### 3.2 Analytics

Use for explainable security intelligence.

Check:

- security score
- residual risk
- detection coverage
- anomaly indicator
- model version and generation timestamp

### 3.3 Findings

Use for technical review and prioritization.

Actions:

- filter by severity
- open finding detail and evidence
- export JSON/CSV when required

### 3.4 Remediation

Use for closure tracking.

Check each task for:

- owner
- due date
- status
- verification state

### 3.5 Reports

Use for formal deliverables.

Actions:

- download PDF for executive circulation
- download HTML for technical review

### 3.6 Risk

Use for strategic communication.

Check:

- current posture score
- severity distribution
- trend direction

## 4. Compliance and Assurance View

Client portal workflows support compliance evidence generation by recording security workflow behavior such as:

- finding views and acknowledgements
- remediation open/completion actions
- report downloads
- dashboard consultations

This telemetry is security-focused and excludes marketing tracking behavior.

## 5. Export and Sharing Best Practices

- Use report exports for formal stakeholder updates.
- Use findings CSV for remediation planning sessions.
- Share risk trend and analytics scores with board-level summaries.

## 6. Privacy and Security Notes

- Session auth is tenant-scoped.
- Portal access is read-only for client users.
- No cross-tenant data exposure is allowed.

## 7. Quick Troubleshooting

- Stale UI data: hard refresh browser
- Login issues: revalidate credentials and tenant URL
- Missing reports: verify report publication status with delivery team
- API/portal outage: contact platform operator
