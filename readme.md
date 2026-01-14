```text
__      __         _              __   __            
 \ \    / /        | |             \ \ / /            
  \ \  / /__   ___ | |_  ___   _ __ \ V / _   _   ___ 
   \ \/ / _ \ / __|| __|/ _ \ | '__| \ / | | | | / _ \
    \  /  __/| (__ | |_| (_) || |    | | | |_| ||  __/
     \/ \___| \___| \__|\___/ |_|    \_/  \__,_| \___|

                                                      
             >> ADVERSARY REPORTING FRAMEWORK <<

```

**VectorVue is a high-fidelity reporting automation engine designed to transform technical vulnerabilities into professional, boardroom-ready intelligence.** It provides a centralized SQLite backend to manage findings across Web, API, Mobile, and Infrastructure assessments.

---

### ⚠️ DISCLAIMER

**For Authorized Security Testing Purposes Only.**

The use of this framework for reporting or documenting systems without prior mutual consent is illegal. The authors assume no liability for misuse, data loss, or legal consequences resulting from the use of this software. By using VectorVue, you agree to operate within the legal boundaries of your jurisdiction.

---

## 🚀 Project Status: Stable

* [x] **SQLite Backend:** Centralized finding management and persistence.
* [x] **Golden Remediation Library:** Pre-mapped OWASP & AD remediations.
* [x] **Dynamic PDF Engine:** Automated "CLASSIFIED" watermarking and branding.
* [x] **Executive Summary Module:** High-level stakeholder summaries.
* [x] **Technical Detailer:** Deep-dive reproduction steps and evidence tracking.
* [x] **Risk Heatmap:** Automated Likelihood vs. Impact matrix.
* [x] **Engagement Wizard:** Interactive CLI for rapid finding entry.
* [x] **Multi-Target Support:** Segmented reporting by Company/Target.

---

## 🛠 Project Structure

### 🛰 The VectorVue Core (`vv.py`)

The command-line interface and logic engine for all reporting operations.

### 📊 The Data Layer (`vectorvue.db`)

A structured SQLite database that serves as the single source of truth for all engagements.

---

## ⚙️ Setup & Execution

### 1. Environment Setup

Clone the repository and install the necessary dependencies via the requirements file.

```bash
# Install Dependencies
pip install -r requirements.txt

# Launch the Reporting Engine
python3 vv.py

```

---

## 🕹 Command Reference (CLI Usage)

| Command | Action | Usage Example |
| --- | --- | --- |
| **`init`** | Initializes the local database and creates the 5-stage folder structure. | `init` |
| **`new`** | Launches the interactive wizard to manually add a new finding to the DB. | `new` |
| **`seed`** | Injects 10 industry-standard findings (SQLi, BOLA, etc.) for testing. | `seed` |
| **`report_executive`** | Generates a high-level PDF summary in Folder 02. | `report_executive "TargetCorp"` |
| **`report_technical`** | Generates a technical deep-dive report in Folder 04. | `report_technical "TargetCorp"` |
| **`report_full`** | Generates all report modules and aggregates them in Folder 05. | `report_full "TargetCorp"` |
| **`usage`** | Displays the help menu with all available commands. | `usage` |
| **`exit`** | Safely closes the database connection and exits the shell. | `exit` |

---

## 🛡️ Remediation Library Coverage

VectorVue includes a standardized "Golden Library" to ensure remediation advice is industry-standard:

| Category | Coverage Areas |
| --- | --- |
| **Web & API** | OWASP Top 10 (BOLA, SQLi, Mass Assignment, IDOR) |
| **Active Directory** | Kerberoasting, LLMNR/NBNS Poisoning, AS-REP Roasting |
| **Infrastructure** | Unquoted Service Paths, SNMP Public Strings, Weak Protocols |
| **Mobile** | PII in Logcat, Hardcoded API Keys, Insecure Data Storage |

---

## 🔒 Rules of Engagement & Safety

1. **Isolation:** Keep the `vectorvue.db` localized to your encrypted assessment machine.
2. **Cleanup:** Use the `exit` command to safely close database handles.
3. **Data Integrity:** Do not manually edit the SQLite database unless using the `vv.py` interface to prevent index corruption.

---

**Would you like me to generate the `requirements.txt` file content now so you can add it to your repo?**