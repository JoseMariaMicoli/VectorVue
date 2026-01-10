## Risk Assessment Matrix

### I. Risk Rating Methodology

We determine risk by calculating the intersection of **Impact** (consequence to the business) and **Likelihood** (ease of exploitation/probability).

| Likelihood / Impact | Low | Medium | High |
| --- | --- | --- | --- |
| **High** | Medium | High | **CRITICAL** |
| **Medium** | Low | Medium | High |
| **Low** | Low | Low | Medium |

---

### II. Findings Heatmap

This table provides a snapshot of where the engagement findings sit on the risk spectrum.

| ID | Finding Title | Likelihood | Impact | Risk Level |
| --- | --- | --- | --- | --- |
| **FIND-001** | Production Database Compromise | High | High | **CRITICAL** |
| **FIND-002** | Domain Admin via Kerberoasting | Medium | High | **HIGH** |
| **FIND-003** | Insecure Direct Object Reference (IDOR) | High | Medium | **HIGH** |
| **FIND-004** | Lack of Egress Filtering | High | Low | **MEDIUM** |
| **FIND-005** | Internal Information Disclosure | Medium | Low | **LOW** |

---

### III. Impact Definitions

* **High:** Potential for full system compromise, significant financial loss, or major regulatory fines (GDPR/HIPAA).
* **Medium:** Partial loss of data or functionality; affects a specific department or subset of users.
* **Low:** Minimal business impact; requires complex "chaining" of vulnerabilities to be useful to an attacker.

### IV. Likelihood Definitions

* **High:** Exploitable by an unskilled attacker using public tools; no significant barriers exist.
* **Medium:** Requires specialized knowledge, specific timing, or social engineering success.
* **Low:** Extremely difficult to exploit; requires "perfect storm" conditions or physical access.

---