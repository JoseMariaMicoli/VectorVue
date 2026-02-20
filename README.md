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

<p align="center">
  <img src="assets/images/NyxeraLogo-transp.png" alt="Nyxera Labs Logo" width="180" />
  &nbsp;&nbsp;&nbsp;
  <img src="assets/images/VectorVueLogo-transp.png" alt="VectorVue Logo" width="180" />
</p>

![Version](https://img.shields.io/badge/version-v4.1-blue)  
![License](https://img.shields.io/badge/license-BSL%201.1-lightgrey)  
![Build Status](https://img.shields.io/badge/build-passing-brightgreen)  
![Coverage](https://img.shields.io/badge/coverage-98%25-green)  
![Docs](https://img.shields.io/badge/docs-index-orange)  
![Issues](https://img.shields.io/github/issues/nyxera/vectorvue)  
![CI](https://img.shields.io/github/actions/workflow/status/nyxera/vectorvue/ci.yml?branch=main)  
![Docker Pulls](https://img.shields.io/docker/pulls/nyxera/vectorvue)  

---

## Overview

**VectorVue** is a commercial-grade, multi-tenant **security validation and assurance platform** built for enterprise and service provider environments.  

It provides **structured adversary emulation**, **control performance analytics**, and **auditable evidence** to help security teams continuously measure and improve the effectiveness of defenses while producing verifiable outputs for audits and compliance requirements.

---

## Product Positioning

VectorVue enables organizations to:

- **Validate Security Controls:** Execute repeatable adversary simulations and track control effectiveness.  
- **Measure Detection & Response:** Analyze telemetry to assess detection quality, response speed, and coverage gaps.  
- **Demonstrate Assurance:** Generate cryptographically signed, auditor-ready evidence packages for compliance and regulatory needs.  

---

## Target Audience

VectorVue is designed for:  

- **Enterprise Security Teams** – SOC, IR, and security ops teams validating real-world defensive capabilities.  
- **Managed Security Service Providers (MSSPs)** – Safely perform adversary emulation for multiple clients with strict tenant separation.  
- **Regulated Organizations** – Finance, healthcare, energy, and other sectors requiring reliable and verifiable compliance evidence.  
- **Auditors & Compliance Officers** – Access immutable evidence and signed reports for regulatory inspections or reviews.  

---

## Core Capabilities

- True multi-tenant isolation for campaigns, findings, analytics, and evidence exports  
- Client portals with executive and operational dashboards tailored per tenant  
- Read-only client API for retrieving findings, risks, remediation, and reports  
- Security-focused telemetry that respects privacy (no marketing tracking)  
- Explainable ML-driven analytics with full model version lineage  
- Continuous compliance scoring and signed evidence export packages  
- Immutable evidence chains for audit and regulatory verification  

---

## Quick Start (Commercial Demo)

**Guided setup (recommended):**  
```bash
make wizard
````

Use menu option:

* `1` for full commercial deploy
* `2` for isolated customer portal deploy
* `4` for demo seed data

**Deploy platform stack (direct command path):**

```bash
make deploy
```

**Seed realistic demo data:**

```bash
make seed-clients
```

**Production-style tenant onboarding without dummy campaign data:**

```bash
make tenant-bootstrap-real \
  TENANT_ID=30000000-0000-0000-0000-000000000003 \
  TENANT_NAME="RealCorp Manufacturing" \
  TENANT_ADMIN_USER=realcorp_admin \
  TENANT_ADMIN_PASS='RealCorpAdm1n!' \
  TENANT_CLIENT_USER=realcorp_viewer \
  TENANT_CLIENT_PASS='RealCorpView3r!'
```

**Validate Phase 7-9 behavior in this real empty-state tenant:**

```bash
make phase79-real-smoke \
  TENANT_ID=30000000-0000-0000-0000-000000000003 \
  TENANT_ADMIN_USER=realcorp_admin \
  TENANT_ADMIN_PASS='RealCorpAdm1n!'
```

**One-command isolated client portal stack:**

```bash
make customer-deploy-portal-isolated \
  CUSTOMER=realcorp \
  TENANT_ID=30000000-0000-0000-0000-000000000003 \
  TENANT_NAME="RealCorp Manufacturing" \
  TENANT_PORTAL_HOST=realcorp.vectorvue.local
```

**Open tenant portals:**

* [https://acme.vectorvue.local/login](https://acme.vectorvue.local/login)
* [https://globex.vectorvue.local/login](https://globex.vectorvue.local/login)

**Validate API and service health:**

```bash
make api-smoke
```

---

## Documentation

Start here: [Documentation Index](#)

Recommended paths by role:

* **Security Operators:** Getting Started, Operator Manual
* **Client Users:** Client Portal Manual
* **Integration Teams:** Client API Manual
* **Auditors and Compliance Teams:** Compliance API Spec, Auditor Guide
* **Platform Engineering:** Deployment, PostgreSQL Usage Guide

---

## TUI Onboarding Wizard

For admin users in the TUI:

```bash
make run-tui
```

* Login as admin
* Open onboarding wizard: `Ctrl+Shift+W` or Sidebar button `ONBOARD WIZARD`
* Fill tenant, company, branding, and user fields
* Submit `CREATE TENANT + USERS`

---

## Security and Privacy Principles

* Tenant-scoped access control and strict data isolation
* Immutable evidence chain for compliance events
* Signed API responses for compliance endpoints
* No IP or user-agent collection in client telemetry workflows
* Security workflow analytics only

---

## Release Status

* **Version:** v4.1
* **Maturity:** Production-ready commercial platform
* **Delivery Scope:** Campaign operations, client portal/API, explainable analytics, continuous compliance assurance

---

## Licensing

VectorVue is licensed under **BSL 1.1** as defined in project metadata.
