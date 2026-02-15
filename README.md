```markdown
██▒   █▓▓█████  ▄████▄  ▄▄▄█████▓ ▒█████   ██▀███      ██▒   █▓ ██▓  ██▓ ▓█████ 
▓██░   █▒▓█   ▀ ▒██▀ ▀█  ▓  ██▒ ▓▒▒██▒  ██▒▓██ ▒ ██▒    ▓██░   █▒▓██▒  ██▒ ▓█   ▀ 
 ▓██  █▒░▒███   ▒▓█    ▄ ▒ ▓██░ ▒░▒██░  ██▒▓██ ░▄█ ▒     ▓██  █▒░▓██░  ██▒ ▒███   
  ▒██ █░░▒▓█  ▄ ▒▓▓▄ ▄██▒░ ▓██▓ ░ ▒██   ██░▒██▀▀█▄       ▒██ █░░▒██   ██░ ▒▓█  ▄ 
   ▒▀█░  ░▒████▒▒ ▓███▀ ░  ▒██▒ ░ ░ ████▓▒░░██▓ ▒██▒      ▒▀█░  ░ ████▓▒░ ░▒████▒
   ░ ▐░  ░░ ▒░ ░░ ░▒ ▒  ░  ▒ ░░   ░ ▒░▒░▒░ ░ ▒▓ ░▒▓░      ░ ▐░  ░ ▒░▒░▒░  ░░ ▒░ ░
   ░ ░░   ░ ░  ░  ░  ▒       ░      ░ ░ ▒░   ░▒ ░ ▒░      ░ ░░  ░ ░ ▒░▒░   ░ ░  ░
   ░      ░    ░          ░      ░ ░ ░ ▒    ░░   ░ ░      ░        ░ ░ ▒░     ░    
          ░  ░ ░                               ░               ░ ░ ░      ░  ░  
               >> ADVERSARY REPORTING FRAMEWORK <<

# VectorVue Tactical v2.1

![Status](https://img.shields.io/badge/Status-Operational-39FF14) ![Version](https://img.shields.io/badge/Version-2.1-00FFFF) ![Build](https://img.shields.io/badge/Build-Enterprise_Grade-grey) ![License](https://img.shields.io/badge/License-Proprietary-FF0000)

**VectorVue** is a high-performance, terminal-based Adversary Reporting and Intelligence suite engineered specifically for Red Team Operations and Offensive Security R&D. It streamlines the lifecycle of a penetration test—from initial finding documentation to final executive report generation—within a unified, low-latency Text User Interface (TUI).

Designed for operators who demand speed and stability, VectorVue integrates real-time adversary intelligence (MITRE ATT&CK®) and a robust dual-database core, ensuring mission-critical data remains structured, searchable, and secure.

---

## ⚡ Key Technical Features

### 1. Phosphor Cyberpunk UI/UX
Optimized for high-stress, low-light operational environments (SOC/NOC), the interface utilizes a high-contrast phosphorescent palette for maximum legibility:
* **Phosphor Green (#39FF14):** Active status, success indicators, and primary action buttons.
* **Amber Phosphor (#FFBF00):** Warning labels, secondary headers, and metadata fields.
* **Electric Cyan (#00FFFF):** Navigation focus, active file paths, and breadcrumbs.
* **Red Alert (#FF0000):** Critical errors, delete confirmations, and high-risk findings.
* **Neutrals (#121212 / #444444):** Deep black canvas with industrial grey borders for clean separation.

### 2. Enterprise Markdown Engine
* **Real-time Syntax Highlighting:** Professional-grade rendering of GitHub Flavored Markdown (GFM) with zero input lag.
* **Tactical Layout:** Split-pane architecture allowing for simultaneous metadata entry (CVSS, MITRE IDs) and content editing.
* **Atomic I/O Operations:** Fault-tolerant saving mechanisms utilize atomic writes to prevent data loss during sudden terminal crashes or SSH disconnects.

### 3. Intelligence & Data Core
* **Dual-Database Orchestration:**
    * `vectorvue.db`: Primary operational store for engagement findings, remediation steps, and asset metadata.
    * `adversary.db`: An intelligence-heavy secondary store containing adversary profiles and historical threat data.
* **MITRE Tactical Mapping:** Automated lookup engine utilizing the `mitre_reference.txt` flat-file. Entering a Technique ID (e.g., `T1548`) instantly resolves official descriptions and sub-technique data directly into the finding view.

### 4. Full-Screen Atomic File Manager
A "Direct Switch" viewport manager that replaces the editor for filesystem operations. 
* **Zero Transitions:** Hard state-switching architecture to prevent screen tearing and rendering artifacts.
* **Vim-Style Navigation:** Native support for `j`, `k`, `g`, `G` and standard arrow keys for rapid file traversal.
* **Professional CRUD:** Secure Create, Read, Update, and Delete operations with non-modal footer confirmations to ensure an uninterrupted workflow.

---

## 📂 Project Structure & Tree

The VectorVue project follows a modular R&D architecture, separating UI logic from core filesystem and database handlers.

```text
VectorVue_Root/
├── assets/                    # Graphical assets and logos
├── docs/
│   └── manuals/               # EXTENDED ENTERPRISE DOCUMENTATION
│       ├── INDEX.md           # CENTRAL DOCUMENTATION INDEX
│       ├── ARCHITECTURE_SPEC.md# Technical data-flow & state specs
│       ├── GETTING_STARTED.md # Deployment & initial config
│       ├── OPERATOR_MANUAL.md # Field usage & keybindings guide
│       └── TROUBLESHOOTING.md # Rendering & DB recovery guide
├── fonts/                     # Custom TUI-optimized fonts
├── vv.py                      # Main entry point (View Controller)
├── vv_core.py                 # Core application logic & Markdown processor
├── vv_file_manager.py         # Full-screen atomic CRUD manager
├── vv_fs.py                   # Low-level filesystem operations
├── vv_theme.py                # Phosphor Cyberpunk theme definitions
├── database_handler.py        # SQL Orchestrator (vectorvue.db / adversary.db)
├── mitre_reference.txt        # MITRE ATT&CK lookup table
├── requirements.txt           # Project dependencies
├── vectorvue.db               # Operational Database (Auto-generated)
├── adversary.db              # Intelligence Database
├── .gitignore                 # Environment exclusion rules
├── LICENSE                    # Proprietary License
└── README.md                  # Main Technical Overview

```

---

## 🚀 Deployment & Installation

### System Prerequisites

* **Python:** 3.10 or higher (Fully optimized for Python 3.14).
* **Terminal:** A terminal emulator with **TrueColor (24-bit)** support is mandatory (Kitty, Alacritty, iTerm2, or Windows Terminal).
* **Environment:** Designed for Linux (Debian/Arch/Kali) and macOS.

### Installation

```bash
# 1. Clone the tactical repository
git clone [https://internal.repo/vectorvue.git](https://internal.repo/vectorvue.git)
cd vectorvue

# 2. Initialize virtual environment
python -m venv venv
source venv/bin/activate

# 3. Install enterprise dependencies
pip install -r requirements.txt

# 4. Launch VectorVue Tactical
python vv.py

```

---

## 📖 Extended Documentation

VectorVue includes a complete suite of professional documentation for architects and operators. For detailed instructions on MITRE mapping, database schema, or custom CSS styling, please refer to our internal index:

> **[CENTRAL DOCUMENTATION INDEX](https://www.google.com/search?q=./docs/manuals/INDEX.md)**

* **[Getting Started](https://www.google.com/search?q=./docs/manuals/GETTING_STARTED.md):** Quickest path to operational readiness.
* **[Operator's Manual](https://www.google.com/search?q=./docs/manuals/OPERATOR_MANUAL.md):** Mastering shortcuts and report workflows.
* **[Architecture Spec](https://www.google.com/search?q=./docs/manuals/ARCHITECTURE_SPEC.md):** Detailed breakdown of the TUI state machine.

---

## ⚖️ License & Disclaimer

**VectorVue v2.1** is proprietary software developed for Offensive Security R&D. Unauthorized distribution or reverse engineering is strictly prohibited. The developers assume no liability for misuse or damage caused by this software in non-authorized environments.

---

**VectorVue v2.1** | *Precision Intelligence. Tactical Reporting.*

---
