<!--
Copyright (c) 2026 NyxeraLabs
Author: José María Micoli
Licensed under BSL 1.1
Change Date: 2033-02-17 → Apache-2.0

You may:
✔ Study
✔ Modify
✔ Use for internal security testing

You may NOT:
✘ Offer as a commercial service
✘ Sell derived competing products
-->

# VectorVue Security Policy

## 🛡️ Overview

VectorVue is a multi-tenant security validation and assurance platform for enterprise security teams, service providers, and regulated organizations.  
Security is at the core of the platform, including adversary emulation, compliance evidence, and telemetry analytics.

This document provides **responsible disclosure guidelines**, security expectations, and operational guidance for researchers, clients, auditors, and platform contributors.

---

## 🐞 Reporting a Security Vulnerability

If you discover a security issue, report it **responsibly and privately**:

- **Email (preferred):** `founder@nyxera.cloud`  
- **GitHub (private issue template):** [VectorVue Security Issues](https://github.com/NyxeraLabs/VectorVue-Website/issues/new?assignees=&labels=security&template=security_issue.md)

**Include:**

- Description of the issue  
- Steps to reproduce  
- Potential impact (data exposure, privilege escalation)  
- Environment details (VectorVue version, OS, browser)  
- Proof-of-concept (PoC) if available  

> ⚠️ Do **not** disclose publicly before coordination with the VectorVue security team.

---

## ⏱️ Response & Triage Process

VectorVue follows a structured triage process:

| Step | Action | Responsible | Timeline |
|------|--------|------------|---------|
| 1 | Acknowledge report | Security team | < 24h |
| 2 | Initial triage & severity classification | Security lead | 3 business days |
| 3 | Mitigation planning | Dev + Security | 7 business days |
| 4 | Patch & release | Dev | ASAP |
| 5 | Public acknowledgement (optional) | Security team | After fix |

### Severity Classification

| Severity | Description | Example |
|----------|------------|--------|
| Critical | Immediate threat to multiple tenants / sensitive data | Remote code execution, full privilege escalation |
| High | Severe, but conditions required | Authentication bypass, sensitive data exposure |
| Medium | Exploitable but limited | Info leakage, minor misconfigurations |
| Low | Minor impact or hard-to-exploit | UI bugs, verbose error messages |

---

## 💡 Security Best Practices for Contributors

- Validate inputs, sanitize outputs, secure all APIs  
- Maintain multi-tenant isolation for campaigns, findings, and analytics  
- Conduct security-focused code reviews  
- Enable automated security scans (SAST, dependency checks)  
- Keep dependencies updated  
- Document security-relevant changes in commits

---

## 🧩 Integration with VectorVue

For security researchers or enterprise clients:

- **Client Portal:** `https://<tenant>.vectorvue.nyxera.cloud/login`  
- **API:** Read-only access for findings, risk, remediation, reports, analytics  
- **TUI Onboarding Wizard:** `make run-tui` → `Ctrl+Shift+W`  
- **Telemetry:** Tenant-scoped, privacy-compliant  
- **Compliance:** Immutable signed evidence chain; cryptographically verifiable audit logs

---

## 📝 Disclosure Policy

- VectorVue follows **Coordinated Vulnerability Disclosure**  
- Researchers may be publicly acknowledged **with consent**  
- No bug bounty currently, but responsible disclosure is recognized  

---

## 🏢 Contact

- **Security email:** founder@nyxera.cloud  
- **Slack (internal / enterprise):** [nyxeralabs.slack.com](https://nyxeralabs.slack.com)  
- **GitHub repo:** [NyxeraLabs/VectorVue-Website](https://github.com/NyxeraLabs/VectorVue-Website)  
- **Website:** [https://vectorvue.nyxera.cloud](https://vectorvue.nyxera.cloud)  

---

## 📄 Licensing Context

- Licensed under **BSL 1.1**, copyright **NyxeraLabs**  
- Author: **José María Micoli**  
- **Change Date:** 2033-02-17 → Apache-2.0