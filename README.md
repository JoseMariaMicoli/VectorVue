<sub>Copyright (c) 2026 José María Micoli | Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}</sub>

## License Update Notice

Starting from version 3.8.0 this project will transition to BSL.

Reason:
To allow sustainable development, support, and long-term maintenance while keeping the project open and transparent.

Previous versions remain under the original license.

```
██▒   █▓▓█████  ▄████▄  ▄▄▄█████▓ ▒█████   ██▀███      ██▒   █▓ ██▓  ██▓ ▓█████
▓██░   █▒▓█   ▀ ▒██▀ ▀█  ▓  ██▒ ▓▒▒██▒  ██▒▓██ ▒ ██▒    ▓██░   █▒▓██▒  ██▒ ▓█   ▀
 ▓██  █▒░▒███   ▒▓█    ▄ ▒ ▓██░ ▒░▒██░  ██▒▓██ ░▄█ ▒     ▓██  █▒░▓██░  ██▒ ▒███
  ▒██ █░░▒▓█  ▄ ▒▓▓▄ ▄██▒░ ▓██▓ ░ ▒██   ██░▒██▀▀█▄       ▒██ █░░▒██   ██░ ▒▓█  ▄
   ▒▀█░  ░▒████▒▒ ▓███▀ ░  ▒██▒ ░ ░ ████▓▒░░██▓ ▒██▒      ▒▀█░  ░ ████▓▒░ ░▒████▒
   ░ ▐░  ░░ ▒░ ░░ ░▒ ▒  ░  ▒ ░░   ░ ▒░▒░▒░ ░ ▒▓ ░▒▓░      ░ ▐░  ░ ▒░▒░▒░  ░░ ▒░ ░
   ░ ░░   ░ ░  ░  ░  ▒       ░      ░ ░ ▒░   ░▒ ░ ▒░      ░ ░░  ░ ░ ░▒░▒░   ░ ░  ░
   ░      ░    ░    ░          ░      ░ ░ ░ ▒    ░░   ░ ░      ░        ░ ░ ▒░     ░
          ░  ░ ░                               ░               ░ ░ ░      ░  ░

                >> OPERATIONAL COGNITION PLATFORM FOR RED TEAMING <<
```

![Status](https://img.shields.io/badge/Status-Operational-39FF14)
![Version](https://img.shields.io/badge/Version-4.1-00FFFF)
![Maturity](https://img.shields.io/badge/Maturity-Phase_7.5.0_Complete-39FF14)
![Cognition](https://img.shields.io/badge/Cognition-Operational-39FF14)
![Security](https://img.shields.io/badge/Audit-Traceable-purple)
![Evidence](https://img.shields.io/badge/Evidence-Defensible-blue)
![License](https://img.shields.io/badge/License-Business_Source_1.1-red)

---

# VectorVue

VectorVue is a **terminal-native Red Team Operational Cognition Platform** designed to assist authorized adversary simulation teams in conducting structured, auditable, and controlled security assessments.

Unlike pentest note tools, VectorVue models the **state of an operation** and helps operators make safe, explainable decisions during engagements.

---

## UI Navigation: Three Ways to Navigate

**New in v4.1+:** Visual tab system for all 26 views. Operators can navigate using:

### 1. Keybindings (Fastest)
- **Space** → Files | **Ctrl+M** → MITRE | **Ctrl+K** → Campaign | **Ctrl+E** → Cmd Log
- **Ctrl+Shift+1** → Opportunities | **Ctrl+Shift+2** → Attack Paths | **Ctrl+Shift+4** → Pressure
- [Full keybinding reference](docs/TAB_QUICK_REFERENCE.txt)

### 2. Visual Tab Clicks
- Click tab names at top of screen to switch views instantly
- Color-coded: GREEN = active, PURPLE = hover, GRAY = inactive
- Keybinding shown on each tab

### 3. Arrow Keys + Enter
- **←** / **→** = Previous/next tab
- **↑** / **↓** = Previous/next tab group
- **Enter** = Select & activate tab

**All 26 views organized in 5 tab groups:**
- Core UI Navigation (8 views): Campaign, Cmd Log, Sessions, Detections, etc.
- Analytics Views (5 views): Dashboard, Analysis, Threat Intel, etc.
- Advanced Views (6 views): Collaboration, Tasks, Security, Compliance, etc.
- Phase 3-5 Views (3 views): Reporting, Teams, Threat Intelligence
- Phase 5.5 Cognition (10 modules): Opportunities, Paths, Pressure, Confidence, etc.

See [Tab Navigation Guide](docs/TAB_NAVIGATION_GUIDE.md) for complete documentation.

## Documentation

- Unified docs entrypoint: [Documentation Index](docs/manuals/INDEX.md)
- Client portal usage (step-by-step): [Client Portal Manual](docs/manuals/CLIENT_PORTAL_MANUAL.md)
- Demo users, URLs, and live walkthrough: [Demo Access Matrix](docs/manuals/DEMO_ACCESS_MATRIX.md)
- API integration runbook: [Client API Manual](docs/manuals/CLIENT_API_MANUAL.md)
- Telemetry operations and privacy model: [Portal Telemetry Manual](docs/manuals/PORTAL_TELEMETRY_MANUAL.md)
- Deployment and hardening: [Deployment Guide](docs/manuals/Deployment.md)
- PostgreSQL operations: [PostgreSQL Usage Guide](docs/manuals/POSTGRES_USAGE_GUIDE.md)
- Full product guide: [VectorVue User Guide](docs/manuals/VECTORVUE_USER_GUIDE.md)
- Telemetry analytics SQL examples: [Telemetry Queries](docs/manuals/PHASE7E_TELEMETRY_QUERIES.sql)

## Maturity Model

| Stage     | Purpose              | Status |
| --------- | -------------------- | ------ |
| Notebook  | Store evidence       | ✅ Complete (v1-2) |
| Manager   | Organize engagement  | ✅ Complete (v2.0+) |
| Platform  | Enforce workflow     | ✅ Complete (v3.0+) |
| Cognition | Guide decisions      | ✅ Complete (v4.1) |
| PostgreSQL Migration | Database + container baseline | ✅ Complete (v4.1, Phase 5.6) |
| Deployment & Hardening | Production-ready secure deployment | ✅ Complete (v4.1, Phase 6) |
| Autonomy  | Supervised execution | 🔮 Phase 8+ |
| **UI Navigation** | **Visual tabs for all views** | **✅ Complete (v4.1+)** |

Current state:

**Phase 5 — Campaign Platform (stable)** ✅
**Phase 5.5 — Operational Cognition (complete)** ✅
**Phase 5.6 — PostgreSQL + Docker baseline (complete)** ✅
**Phase 6 — Deployment & Hardening (complete)** ✅
**Phase 7 — Client Portal + Analytics (complete)** ✅
Client portal includes findings timeline, JSON/CSV export, remediation tracking with verification state,
polling notifications, multilingual toggle (EN/ES), and brandable UI variables.
**Phase 7.5.0 — Portal Usage Telemetry (complete)** ✅
Client telemetry now captures finding views/acknowledgements, remediation actions, report downloads,
and dashboard consultation frequency for Phase 8 defensive-effectiveness model datasets.

## Multi-Tenant Demo Seed (v4.1)

Run:

```bash
make seed-clients
```

This now provisions:

- 2 client panels (tenants), each with 2 client users
- 1 global red team admin + 2 operator accounts (lead + operator)
- 2 realistic campaigns per tenant (4 total), with findings, evidence, remediation, reports, and analytics data

At the end of `make seed-clients`, VectorVue prints the full access matrix.
See [Demo Access Matrix Manual](docs/manuals/DEMO_ACCESS_MATRIX.md) for credential defaults and overrides.

Access model:

- `redteam_admin` is mapped to both tenants
- `rt_lead` is mapped to Panel 1 tenant
- `rt_operator` is mapped to Panel 2 tenant
- each panel has 2 client users with different roles

Tenant-isolated container stacks:

```bash
make customer-deploy-isolated \
  CUSTOMER=acme \
  TENANT_NAME="ACME Industries" \
  HTTP_HOST_PORT=8081 \
  HTTPS_HOST_PORT=8444 \
  POSTGRES_HOST_PORT=5544
```

Run another tenant with a different `CUSTOMER` and different host ports.

## Quick Start (Operator + Client Demo)

1. Deploy:
```bash
make deploy
```
2. Seed demo data:
```bash
make seed-clients
```
3. Open portal:
   - `https://acme.vectorvue.local/login`
   - `https://globex.vectorvue.local/login`
4. Login with viewer account from `docs/manuals/DEMO_ACCESS_MATRIX.md`.
5. Walk pages in order:
   - `Overview`
   - `Findings`
   - `Reports`
   - `Remediation`
   - `Risk`

---

## Purpose

VectorVue exists because most red-team failures are decision failures, not technical failures.

Typical operator mistakes:

* Escalating too early
* Burning access
* Ignoring detection signals
* Losing evidence integrity
* Breaking Rules of Engagement

VectorVue helps determine **when NOT to act**.

---

## Core Principles

### Timeline First

Everything belongs to an evolving operation timeline:

Recon → Access → Expansion → Persistence → Impact → Reporting

---

### Deterministic Reasoning

No black-box AI decisions.

Example model:

```
opportunity_score =
    (value * 0.5) +
    (stealth * 0.3) -
    (risk * 0.2)
```

Every recommendation is explainable.

---

### Defensible Evidence

All evidence is:

* timestamped
* hashed
* attributed
* approval tracked
* auditable

---

### Safety Over Success

A stealth failure invalidates an engagement.

Priority order:

1. Safety
2. Realism
3. Validity
4. Success

---

## Capabilities

### Campaign Management

Multi-campaign isolation with RBAC, team coordination, client context.

### Operational Tracking

Sessions, detections, persistence, objectives, activity timelines.

### Operational Cognition (Phase 5.5)

**Decision-support system with 10 deterministic modules:**
- **Attack Graph** — Compromise relationship pathfinding
- **Objective Distance** — Steps to campaign goal calculation
- **Recommendation Scoring** — Risk-weighted action scoring
- **Detection Pressure** — Defensive state tracking (0-100)
- **OpSec Simulation** — Probability logging/detection prediction
- **Event Replay** — Immutable campaign narrative timeline
- **Operator Tempo** — Action rate analysis & spike detection
- **Infrastructure Burn** — C2 & tool exposure tracking
- **Confidence Analysis** — Data completeness & observation scoring
- **Memory Learning** — Pattern recognition & technique success rates

All logic deterministic, explainable, and confidence-scored.

### Intelligence Correlation

IOC ingestion, threat actor profiling, feed aggregation, risk aggregation.

### Reporting

Compliance-ready reports, evidence manifests, approval workflows, multi-format export.

### Security Controls

AES-256-GCM encryption, PBKDF2 key derivation, audit logs, retention enforcement, immutable evidence chains.

---

## Installation

Requirements:
Python 3.10+

```
git clone https://github.com/yourorg/vectorvue.git
cd vectorvue
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python vv.py
```

PostgreSQL one-command operations:

```bash
make pg-reset
make pg-migrate
make seed-clients
make pg-smoke
```

First launch:

1. Create admin
2. Create campaign
3. Select campaign
4. Begin operation

---

## Security Model

Confidentiality — encrypted storage
Integrity — hash & HMAC verification
Accountability — immutable audit logs

---

## Legal & Responsibility Disclaimer

### Authorized Use Only

VectorVue must only be used during explicitly authorized security assessments under signed Rules of Engagement.

Forbidden uses include:

* unauthorized intrusion
* surveillance
* out-of-scope exploitation
* illegal activity

### Operator Responsibility

Operators must ensure:

* written authorization exists
* actions remain in scope
* collected data handled securely

VectorVue does not validate legality — the operator must.

### No Warranty

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.

IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY ARISING FROM THE USE OF THE SOFTWARE.

---

## Ethical Doctrine

The purpose of a red team is not compromise.

The purpose is defense improvement.

---

## Roadmap

Phase 5.5 — Operational cognition ✅ **COMPLETE**
Phase 6 — Deployment & hardening ✅ **COMPLETE**
Phase 7 — Client portal (web UI) ✅ **COMPLETE**
Phase 7.5.0 — Portal usage telemetry ✅ **COMPLETE**
Phase 8 — Supervised autonomy & analytics

---

## What This Is NOT

VectorVue is NOT:

* an exploit kit
* a malware framework
* a scanner
* a C2 server

It is a decision support system for adversary simulation.

---

## Philosophy

Bad tools help attackers.
Good tools help testers.
Great tools help defenders.

VectorVue aims to improve security — not bypass it.

---
---
