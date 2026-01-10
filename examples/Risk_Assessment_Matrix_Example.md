## Risk Assessment Matrix

**Engagement ID:** ENG-2025-042

**Target:** Global Logistics Corp (GLC)

### I. Visual Risk Heatmap

This matrix categorizes the findings based on the difficulty of the attack (**Likelihood**) versus the damage to the business (**Impact**).

|  | **Impact: Low** | **Impact: Medium** | **Impact: High** |
| --- | --- | --- | --- |
| **Likelihood: High** | FIND-006 (Info Leak) | FIND-003 (IDOR) | **FIND-001 (DB Access)** |
| **Likelihood: Medium** | FIND-005 (TLS) | FIND-004 (Egress) | **FIND-002 (Domain Admin)** |
| **Likelihood: Low** |  |  |  |

---

### II. Ranked Findings Summary

The following table provides the prioritized remediation list based on the matrix above.

| Finding ID | Finding Title | Likelihood | Impact | Risk Rating | Status |
| --- | --- | --- | --- | --- | --- |
| **FIND-001** | **Hardcoded DB Credentials** | High | High | **CRITICAL** | Open |
| **FIND-002** | **Kerberoasting (Admin)** | Medium | High | **HIGH** | Open |
| **FIND-003** | **Order IDOR (Customer PII)** | High | Medium | **HIGH** | In Progress |
| **FIND-004** | **Insecure Egress Rules** | Medium | Medium | **MEDIUM** | Open |
| **FIND-005** | **Deprecated TLS 1.0/1.1** | Medium | Low | **LOW** | Accepted |
| **FIND-006** | **Server Version Headers** | High | Low | **LOW** | Fixed |

---

### III. Business Impact Analysis

To help management understand the "why" behind these ratings, we have mapped the top risks to specific business consequences:

* **FIND-001 (Critical):** Direct violation of **PCI-DSS** compliance. A leak of this database would trigger mandatory reporting and potential fines exceeding **$500,000**, plus reputational damage.
* **FIND-002 (High):** An attacker gaining Domain Admin rights can deploy **Ransomware** across the entire corporate network, leading to a total operational shutdown of logistics tracking for 24-72 hours.
* **FIND-003 (High):** Competitors could programmatically "scrape" GLC's order history, revealing client lists and pricing strategies, leading to a **loss of competitive advantage**.

---

### IV. Remediation Timeline (Recommended)

| Risk Level | Remediation Deadline | Responsibility |
| --- | --- | --- |
| **CRITICAL** | **< 24 Hours** | Database Admin / Security Ops |
| **HIGH** | **< 7 Days** | DevOps / Infrastructure Team |
| **MEDIUM** | **< 30 Days** | Software Development Team |
| **LOW** | **Next Sprint** | IT Support / Web Team |

