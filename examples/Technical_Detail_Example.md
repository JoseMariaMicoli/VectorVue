## Technical Detail

**Target:** Global Logistics Corp (GLC)

**ID:** ENG-2025-042

**Status:** Open

### I. Attack Path Narrative

1. **Initial Access:** A spear-phishing email was sent to the HR department containing a macro-enabled Excel document (`Q4_Bonus_Structure.xlsm`).
2. **Foothold:** One user executed the file, establishing a Cobalt Strike Beacon on `WKST-HR-04`.
3. **Persistence:** A scheduled task was created to re-establish the connection every 60 minutes.
4. **Privilege Escalation:** The team performed **LSASS Memory Dumping**, retrieving the NTLM hash of a Domain Admin who had logged into the machine earlier for troubleshooting.
5. **Objective:** Using the "Pass-the-Hash" technique, the team accessed the `DB-PROD-01` server and exported a sample of the `Customer_PII` table.

---

### II. Findings Deep-Dive

#### FIND-001: Unauthorized Access to Production SQL Database

* **Severity:** **CRITICAL** (CVSS: 9.8)
* **Asset:** `10.0.4.55` (DB-PROD-01)
* **Description:** The production database was accessible via the network using credentials recovered from a misconfigured network share.

**Reproduction Steps:**

1. Scan the internal network for open port `1433`.
2. Access the public file share `\\GLC-FILE01\Public\Scripts\`.
3. Locate `backup_db.ps1`. Open the file to find the hardcoded service account password:
```powershell
$DB_Pass = "FallSeason2025!" 

```


4. Use `impacket-mssqlclient` to connect:
```bash
mssqlclient.py svc_db_backup:FallSeason2025!@10.0.4.55

```



**Impact:** Total compromise of customer data integrity and confidentiality. An attacker can delete, modify, or steal the entire database.

**Remediation:**

* Immediately rotate the password for the `svc_db_backup` account.
* Implement a "Least Privilege" model; the backup account should not have `sysadmin` rights.
* Remove all hardcoded credentials from scripts.

---

#### FIND-002: Insecure Direct Object Reference (IDOR)

* **Severity:** **MEDIUM** (CVSS: 5.3)
* **Asset:** `https://portal.glc.com/api/v1/orders/`
* **Description:** The API allows a user to view any order by simply changing the `order_id` in the URL.

**Reproduction Steps:**

1. Log in as a standard user.
2. Navigate to `https://portal.glc.com/api/v1/orders/1001`.
3. Change the URL to `https://portal.glc.com/api/v1/orders/1002`.
4. The system returns the order details for a different customer without checking ownership.

**Remediation:**

* Implement server-side authorization checks to ensure the `current_user` owns the requested `order_id`.

---

### III. Engagement Cleanup

* **Accounts Deleted:** `svc_pentest_dummy`
* **Files Removed:** `C:\Temp\mimikatz.exe`, `\\GLC-FILE01\Public\test_exploit.txt`
* **Persistence Removed:** Scheduled task `WindowsUpdate_Maintenance` on `WKST-HR-04` has been deleted.

---