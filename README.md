## License Update Notice

Starting from version 3.7.1 this project will transition to Apache-2.0.

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
![Version](https://img.shields.io/badge/Version-3.8-00FFFF)
![Maturity](https://img.shields.io/badge/Maturity-Phase_5.5_Complete-39FF14)
![Cognition](https://img.shields.io/badge/Cognition-Operational-39FF14)
![Security](https://img.shields.io/badge/Audit-Traceable-purple)
![Evidence](https://img.shields.io/badge/Evidence-Defensible-blue)
![License](https://img.shields.io/badge/License-Apache_2.0-green)

---

# VectorVue

VectorVue is a **terminal-native Red Team Operational Cognition Platform** designed to assist authorized adversary simulation teams in conducting structured, auditable, and controlled security assessments.

Unlike pentest note tools, VectorVue models the **state of an operation** and helps operators make safe, explainable decisions during engagements.

---

## UI Navigation: Three Ways to Navigate

**New in v3.8+:** Visual tab system for all 26 views. Operators can navigate using:

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
- Full commercial guide: [VectorVue User Guide](docs/manuals/VECTORVUE_USER_GUIDE.md)
- PostgreSQL migration: [PostgreSQL Migration Guide](docs/manuals/POSTGRES_MIGRATION_GUIDE.md)
- PostgreSQL operations: [PostgreSQL Usage Guide](docs/manuals/POSTGRES_USAGE_GUIDE.md)

## Maturity Model

| Stage     | Purpose              | Status |
| --------- | -------------------- | ------ |
| Notebook  | Store evidence       | ✅ Complete (v1-2) |
| Manager   | Organize engagement  | ✅ Complete (v2.0+) |
| Platform  | Enforce workflow     | ✅ Complete (v3.0+) |
| Cognition | Guide decisions      | ✅ Complete (v3.8) |
| PostgreSQL Migration | Database + container baseline | ✅ Complete (v3.8, Phase 5.6) |
| Autonomy  | Supervised execution | 🔮 Phase 6+ |
| **UI Navigation** | **Visual tabs for all views** | **✅ Complete (v3.8+)** |

Current state:

**Phase 5 — Campaign Platform (stable)** ✅
**Phase 5.5 — Operational Cognition (complete)** ✅
**Phase 5.6 — PostgreSQL + Docker baseline (complete)** ✅
**Phase 6 — Strategic Planning (upcoming)**

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
make pg-seed
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
Phase 6 — Strategic planning & hypothesis testing
Phase 7 — Adaptive operations & environment learning
Phase 8 — Supervised autonomy & execution engines

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
