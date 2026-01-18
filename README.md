```markdown
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

## 🚀 Project Status: Stable (v1.6)

* [x] **SQLite Backend:** Centralized finding management with automatic schema repair.
* [x] **Status Tracking:** Integrated finding lifecycle (Open, Fixed, Risk Accepted).
* [x] **40-Point Golden Library:** 100% coverage for OWASP Web, API, Mobile, and AD.
* [x] **Raw SQL Interface:** Direct database querying from the CLI.
* [x] **Dynamic PDF Engine:** Automated "CLASSIFIED" watermarking and branding.
* [x] **Multi-Target Support:** Segmented reporting by Company/Target.

---

## 🕹 Command Reference (CLI Usage)

| Command | Action | Usage Example |
| --- | --- | --- |
| **`init`** | Initializes database and creates the 5-stage folder structure. | `init` |
| **`new`** | Launches the interactive wizard for manual finding entry. | `new` |
| **`seed`** | Injects 10 industry-standard findings for testing. | `seed` |
| **`list`** | Displays table of IDs, Severity, and Status for a target. | `list "TargetCorp"` |
| **`library`** | View the 40-point Golden Remediation Library. | `library "Mobile"` |
| **`status`** | Updates the lifecycle state of a finding by ID. | `status 1 "Fixed"` |
| **`delete`** | Permanent removal of a specific finding from the DB. | `delete 5` |
| **`query`** | Executes raw SQL against the findings table. | `query SELECT * FROM findings` |
| **`report_full`** | Generates all report modules for a target in Folder 05. | `report_full "TargetCorp"` |
| **`usage`** | Displays the help menu with aligned visual boxes. | `usage` |
| **`exit`** | Safely closes the database connection and exits the shell. | `exit` |

---

## 🛠 Workflow Example: TargetCorp

Follow this sequence for a standard engagement lifecycle:

1. **Setup:** `init` (Prepare folders for TargetCorp)
2. **Data:** `seed` or `new` (Populate findings for TargetCorp)
3. **Verify:** `list "TargetCorp"` (Identify finding IDs)
4. **Manage:** `status 1 "Fixed"` (Update remediation progress)
5. **Research:** `library "API"` (Pull standard API remediations)
6. **Finalize:** `report_full "TargetCorp"` (Generate PDF delivery)

---

## 🛡️ Remediation Library Coverage

VectorVue includes a standardized "Golden Library" to ensure remediation advice is industry-standard:

| Category | Coverage Areas |
| --- | --- |
| **Web App** | OWASP Top 10 (A01-A10) Full Coverage |
| **API Security** | OWASP API Top 10 (BOLA, BOPLA, Mass Assignment) |
| **Mobile** | OWASP Mobile Top 10 (M1-M10, Keystore, Pinning) |
| **AD & Infra** | Kerberoasting, BloodHound Paths, LLMNR, Weak TLS |

---

**Would you like me to help you format the Git commit message to perfectly summarize these new features?**

---

## 🔒 Rules of Engagement & Safety

1. **Isolation:** Keep the `vectorvue.db` localized to your encrypted assessment machine.
2. **Cleanup:** Use the `exit` command to safely close database handles.
3. **Data Integrity:** Do not manually edit the SQLite database unless using the `vv.py` interface to prevent index corruption.

---