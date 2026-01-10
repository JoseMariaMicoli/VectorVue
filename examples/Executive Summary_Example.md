## Executive Summary

**Target:** Global Logistics Corp (GLC)

**Engagement Date:** October 12 – October 26, 2025

**Consultant:** Gemini Security Labs

### I. Executive Narrative

The security assessment of Global Logistics Corp revealed a **High-Risk** security posture. While the external perimeter (Public Website and VPN) showed strong resilience against common automated attacks, the internal network contained systemic vulnerabilities.

The most significant finding involved an **Identity-based Attack Path**. By gaining access to a low-privileged employee workstation via a simulated phishing lure, the Red Team was able to harvest credentials from memory. These credentials belonged to a DevOps engineer, which ultimately allowed the team to access the **Production SQL Database** containing over 1.2 million customer shipping records.

### II. Risk Rating & Distribution

| Risk Level | Count | Primary Areas of Concern |
| --- | --- | --- |
| **Critical** | 1 | Production Database Access / PII Leakage |
| **High** | 2 | Lack of MFA on Internal Admin Portals |
| **Medium** | 4 | Outdated Web Components / Cleartext Logs |
| **Low** | 6 | Information Disclosure / TLS Weaknesses |

### III. Key Findings

* **Database Compromise:** Unauthorized access to the central SQL cluster was achieved by exploiting a stored credential in an unencrypted PowerShell script on a file share.
* **MFA Bypass:** Several internal administrative portals (e.g., Jenkins, GitLab) were discovered to have MFA disabled for "legacy compatibility," allowing for easy lateral movement.
* **Lateral Movement:** The absence of network segmentation between the "Guest Wi-Fi" and the "Corporate Server VLAN" allowed the team to scan sensitive assets from the lobby.

### IV. Strategic Recommendations

1. **Enforce MFA Universally:** Remove all "legacy" exceptions for MFA. Every internal login must require a second factor.
2. **Network Segmentation:** Implement a Zero-Trust architecture to ensure the Guest Wi-Fi has zero visibility into the server environment.
3. **Secrets Management:** Deploy a solution like HashiCorp Vault to prevent developers from storing passwords in scripts or local files.

---