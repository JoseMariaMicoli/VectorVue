<!-- Copyright (c) 2026 José María Micoli | Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'} -->

# VectorVue User Guide

Version: v3.8 (Phase 5.5 complete)  
Audience: Red Team operators, security engineers, authorized penetration testers

## Table of Contents

1. [Introduction](#introduction)
2. [Installation and Setup](#installation-and-setup)
3. [Quick Start](#quick-start)
4. [Detailed Feature Guide](#detailed-feature-guide)
5. [Operation Modeling](#operation-modeling)
6. [Configuration and Customization](#configuration-and-customization)
7. [Advanced Features](#advanced-features)
8. [FAQ and Troubleshooting](#faq-and-troubleshooting)
9. [Appendices](#appendices)

## Introduction

VectorVue is a terminal-native Red Team Operational Cognition Platform for structured and auditable adversary simulation.

Unlike note-taking tools, VectorVue models campaign state and supports operator decisions using deterministic scoring, campaign telemetry, and explicit safety controls.

### Target Audience

- Red Team operators running authorized campaigns
- Security engineers validating defensive coverage
- Engagement leads managing multi-operator workflows
- Internal security programs requiring defensible evidence trails

### Primary Use Cases

- Multi-phase red team campaign execution with strong traceability
- Credential, session, persistence, and detection timeline tracking
- Reporting and evidence-chain workflows with compliance mapping
- Threat intelligence enrichment and risk scoring
- Operational cognition (Phase 5.5) for explainable next-action guidance

### Authorized Use and Safety

> WARNING: VectorVue must be used only in authorized environments and within explicit rules of engagement (ROE).

- Use only on systems where written authorization exists.
- Respect campaign scope, prohibited targets, and time windows.
- Validate OPSEC/detection risk before high-impact actions.
- Maintain evidence integrity for defensible reporting.

## Installation and Setup

### System Requirements

| Area | Requirement |
|---|---|
| OS | Linux, macOS, or Windows via WSL2 |
| Python | 3.10+ |
| Terminal | UTF-8, 256-color minimum |
| Storage | Local writable workspace for `vectorvue.db` |

### Dependencies

Install from source:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -U pip setuptools wheel
pip install -r requirements.txt
```

Key libraries in `requirements.txt` include:
- `textual` (TUI)
- `cryptography` (encryption primitives)
- `rich`, `Markdown` (rendering)
- `reportlab`, `weasyprint`, `fpdf2` (reporting)

### Run

```bash
python vv.py
```

### First Launch

1. Register first user (first user becomes `ADMIN`).
2. Authenticate.
3. Initialize a campaign.
4. Start documenting and executing workflows.

### Installation Verification

```bash
python -m py_compile vv.py vv_core.py vv_theme.py vv_tab_navigation.py
python check_system.py
```

### Distribution Status

| Method | Status |
|---|---|
| Source install | Supported now |
| PyPI package | Not published (requires roadmap phase decision) |
| Docker image | Planned in Roadmap Phase 6 |

## Quick Start

### 10-Minute Guided Workflow

1. Launch:

```bash
python vv.py
```

2. Authenticate and create/select campaign.
3. Open editor (`Esc`) and create a finding draft.
4. Open campaign views with keybindings:
   - `Ctrl+K` Campaign
   - `Ctrl+E` Command log
   - `Ctrl+J` Sessions
   - `Ctrl+D` Detections
   - `Ctrl+Y` Timeline
5. Save finding (`Ctrl+S`).
6. Generate outputs from reporting views.

### Example Operator Sequence

```text
[LOGIN] -> [CAMPAIGN] -> [EDITOR] -> [COMMAND LOG] -> [DETECTIONS] -> [TIMELINE] -> [REPORTING]
```

### Expected Outputs

- Finding persisted to encrypted DB fields where applicable.
- Audit entries created for key mutations.
- Campaign telemetry visible in timeline/graph/analysis views.

## Detailed Feature Guide

### Architecture Overview

| Layer | Main Files | Responsibility |
|---|---|---|
| TUI App | `vv.py`, `vv_theme.py`, `vv_tab_navigation.py` | Views, keybindings, navigation, auth flow |
| Data + Security | `vv_core.py`, `vv_fs.py` | DB schema/migrations, RBAC, crypto, persistence |
| Cognition | `cognition_service.py`, `engines/*.py`, `vv_cognition*.py` | Deterministic decision support and analytics |
| Domain Engines | `vv_graph.py`, `vv_objective.py`, `vv_recommend.py`, `vv_detection_pressure.py`, `vv_opsec.py`, `vv_replay.py`, `vv_tempo.py`, `vv_infra_burn.py`, `vv_confidence.py`, `vv_memory.py` | Campaign-state computation modules |
| Support Scripts | `scripts/seed_db.py`, `scripts/reset_db.py`, `check_system.py` | Environment checks, test data, DB reset |

### Core Application Views

| View | Keybinding | Purpose | Typical Input | Typical Output |
|---|---|---|---|---|
| Editor | `Esc` | Author findings in Markdown | Finding text, CVSS, MITRE | Draft and saved finding |
| File Manager | `Space` | Navigate/open files | Local file selection | Open markdown into editor |
| MITRE DB | `Ctrl+M` | Technique lookup | ID/name search | Technique details |
| Campaign | `Ctrl+K` | Campaign/assets/credentials | Campaign metadata | Campaign state updates |
| Command Log | `Ctrl+E` | Command execution ledger | Filters and refresh | Command timeline |
| Sessions | `Ctrl+J` | Session lifecycle | Open/close/revive actions | Session table |
| Detections | `Ctrl+D` | Detection event timeline | Refresh/filter | Detection and severity view |
| Objectives | `Ctrl+O` | Goal progress tracking | Objective updates | Progress and coverage |
| Persistence | `Ctrl+P` | Persistence inventory | Register/verify events | Persistence status |
| Graph | `Ctrl+G` | Attack path relationships | Campaign telemetry | Attack graph summary |
| Timeline | `Ctrl+Y` | Engagement chronology | Campaign telemetry | Ordered replay timeline |
| Reporting | `Ctrl+R` | Report/export operations | Format selections | Markdown/JSON/PDF/HTML artifacts |

### Advanced and Administration Views

| View | Keybinding | Minimum Role |
|---|---|---|
| Teams | `Ctrl+T` | LEAD |
| Integration | `Alt+4` | LEAD |
| Users | UI/Admin tools | ADMIN |
| Compliance/Security/Analytics | `Alt+3/5/6` | OPERATOR+ |

### Cognition Views (Phase 5.5)

| View | Keybinding | Function |
|---|---|---|
| Opportunities | `Ctrl+Shift+1` | Candidate next actions |
| Paths | `Ctrl+Shift+2` | Attack path options |
| State | `Ctrl+Shift+3` | Campaign state snapshot |
| Pressure | `Ctrl+Shift+4` | Detection pressure and trend |
| Confidence | `Ctrl+Shift+5` | Data quality/confidence gaps |
| Knowledge | `Ctrl+Shift+6` | Evidence completeness |
| Techniques | `Ctrl+Shift+7` | Technique effectiveness |
| Validation | `Ctrl+Shift+8` | Approval/validation queue |
| Explain | `Ctrl+Shift+9` | Rationale and scoring explanation |
| Dashboard | `Ctrl+Shift+0` | Unified cognition view |

### CLI and Script Interfaces

| Command | Options | Purpose |
|---|---|---|
| `python vv.py` | none | Run TUI |
| `python scripts/seed_db.py` | `--admin-user`, `--admin-pass`, `--passphrase` | Seed realistic demo campaigns |
| `python scripts/reset_db.py` | `--yes` | Remove local DB/session state |
| `python check_system.py` | none | Validate dependencies, FS IO, crypto chain |

### Module-Level Notes

- `vv_core.Database` is the primary service boundary for persistence, RBAC checks, audit chain, reporting, team and threat-intel features.
- `cognition_service.CognitionService` orchestrates `engines/*` deterministic modules.
- `vv_cognition_integration.CognitionOrchestrator` integrates campaign telemetry into cognition outputs.
- `vv_tab_navigation.TabNavigationPanel` provides grouped navigation UX.

_Note: some legacy function naming overlaps exist in `vv_core.py` (for example similarly named report/compliance helpers in different phase blocks); behavior should be validated against the active migration path in your deployed build._

## Operation Modeling

VectorVue models operations as a stateful loop:

1. Observe: collect campaign telemetry.
2. Simulate: evaluate OPSEC and detection likelihood.
3. Execute: perform authorized action.
4. Evaluate: assess effects/detections/objective delta.
5. Adapt: choose lower-risk/high-value next action.

### State Components

| Component | Data Source |
|---|---|
| Asset/control graph | Assets, relationships, sessions |
| Objective distance | Objectives + linked actions |
| Detection pressure | Detection events + pressure history |
| Confidence score | Completeness of telemetry evidence |
| Recommendation score | Value/stealth/risk deterministic model |

### Safety Controls

- RBAC gating per view and action
- Campaign scope enforcement
- Audit logging on critical mutations
- Session timeout and re-auth workflows
- Evidence integrity verification and manifests

## Configuration and Customization

### Runtime Storage and Project Files

| File | Purpose |
|---|---|
| `vectorvue.db` | Main SQLite database |
| `vectorvue.salt` | Crypto salt for key derivation |
| `.vectorvue_session` | Session artifact |
| `Reports/` | Exported artifacts |

### Configuration Surface

Most configuration is database-backed rather than env-var driven.

Examples referenced in shipped guides:
- `session_timeout_minutes`
- `mfa_required`

### Operational Customization

- Update theme and spacing in `vv_theme.py`.
- Tune nav groupings and tab labels in `vv_tab_navigation.py`.
- Extend cognition behavior in `engines/*` and `cognition_service.py`.
- Use `scripts/seed_db.py` to bootstrap realistic scenarios.

### Example Setup Profile

```text
Environment: Internal red-team lab
Auth: Mandatory per launch
Timeout: 120 min
Campaign naming: OP_<NAME>_<YEAR>
Exports: Reports/<campaign>_navigator.json + markdown package
```

## Advanced Features

### Logging, Audit, and Integrity

- Database mutation events are written to audit structures.
- Evidence and critical records include hash/integrity workflows.
- Chain verification helpers exist for immutable logs and manifests.

### Reporting and Export

Available capabilities in code include:
- Markdown export
- MITRE Navigator JSON export
- PDF/HTML report generation (phase feature paths in `vv_core.py`)
- Compliance report generation methods

### Integrations

Implemented integration surfaces include:
- Webhook registration and delivery tracking
- API integration registry entries
- Threat feed and IoC enrichment pipelines

### Debugging Tips

1. Run compile checks before launch:

```bash
python -m py_compile vv.py vv_core.py cognition_service.py
```

2. Validate DB key/passphrase consistency.
3. Use `scripts/reset_db.py --yes` only in non-production test environments.
4. Seed deterministic test data with `scripts/seed_db.py`.

## FAQ and Troubleshooting

### Q1: Why do I need to login every launch?
Security policy: fresh authentication prevents stale token reuse.

### Q2: Why is a campaign required for some views?
Many operational views are campaign-scoped and rely on campaign telemetry.

### Q3: Where are exports written?
`Reports/` in the project root.

### Q4: How do I reset a local test instance?

```bash
python scripts/reset_db.py --yes
```

### Q5: Threat-intel/cognition looks sparse in a new campaign.
Seed data first or generate realistic command/session/detection history.

For issue-specific workflows, see `docs/manuals/TROUBLESHOOTING_GUIDE.md`.

## Appendices

### Glossary

| Term | Meaning |
|---|---|
| ROE | Rules of Engagement |
| OPSEC | Operational Security |
| IoC | Indicator of Compromise |
| TTP | Tactics, Techniques, and Procedures |
| RBAC | Role-Based Access Control |
| Cognition | Deterministic decision-support layer |

### References

- `README.md`
- `docs/ROADMAP.md`
- `docs/TAB_NAVIGATION_GUIDE.md`
- `docs/manuals/GETTING_STARTED.md`
- `docs/manuals/OPERATOR_MANUAL.md`
- `docs/manuals/ARCHITECTURE_SPEC.md`
- `docs/manuals/TROUBLESHOOTING_GUIDE.md`

### Version and Roadmap Summary

Current implemented scope aligns with Roadmap through Phase 5.5.  
Planned scopes (not started):
- Phase 6: Deployment hardening (Docker/systemd/TLS/air-gap)
- Phase 7: Client portal (web UI)
- Phase 8: Advanced ML analytics

Changelog source of truth: roadmap and repository history.
