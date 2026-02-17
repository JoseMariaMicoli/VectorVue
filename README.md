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
![Version](https://img.shields.io/badge/Version-3.7-00FFFF)
![Maturity](https://img.shields.io/badge/Maturity-Phase_5.5-orange)
![Security](https://img.shields.io/badge/Audit-Traceable-purple)
![Evidence](https://img.shields.io/badge/Evidence-Defensible-blue)
![License](https://img.shields.io/badge/License-Proprietary-red)

---

# VectorVue

VectorVue is a **terminal-native Red Team Operational Cognition Platform** designed to assist authorized adversary simulation teams in conducting structured, auditable, and controlled security assessments.

Unlike pentest note tools, VectorVue models the **state of an operation** and helps operators make safe, explainable decisions during engagements.

---

## Maturity Model

| Stage     | Purpose              |
| --------- | -------------------- |
| Notebook  | Store evidence       |
| Manager   | Organize engagement  |
| Platform  | Enforce workflow     |
| Cognition | Guide decisions      |
| Autonomy  | Supervised execution |

Current state:

**Phase 5 — Campaign Platform (stable)**
**Phase 5.5 — Operational Cognition (active development)**

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

Multi-campaign isolation with RBAC.

### Operational Tracking

Sessions, detections, persistence, objectives.

### Intelligence Correlation

IOC ingestion and risk aggregation.

### Reporting

Compliance-ready reports and evidence manifests.

### Security Controls

Encryption, audit logs, retention enforcement.

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

### Organizational Responsibility

Organizations deploying VectorVue must provide supervision, training, and lawful engagement approval.

### No Warranty

Provided **as-is** without liability for damages, misuse, or legal consequences.

---

## Ethical Doctrine

The purpose of a red team is not compromise.

The purpose is defense improvement.

---

## Roadmap

Phase 5.5 — Operational cognition
Phase 6 — Strategic planning
Phase 7 — Adaptive operations
Phase 8 — Supervised autonomy

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

```
```
