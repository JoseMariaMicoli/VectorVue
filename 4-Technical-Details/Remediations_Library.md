The "Golden Library" of remediations.
---

## 🛡️ The Master Remediation Library

### 1. Web Application (OWASP Top 10:2025/21)

| Category | Finding | Remediation Strategy |
| --- | --- | --- |
| **A01** | **Broken Access Control** | Implement centralized access control; use "Deny by Default." |
| **A02** | **Security Misconfiguration** | Automate hardening; remove default accounts and verbose error pages. |
| **A03** | **Software/Data Integrity** | Use digital signatures for updates; verify CI/CD pipeline security. |
| **A04** | **Cryptographic Failures** | Encrypt data at rest/transit (AES-256/TLS 1.3); disable old protocols. |
| **A05** | **Injection (SQLi, XSS)** | Use parameterized queries and context-aware output encoding. |
| **A06** | **Insecure Design** | Shift-left security; perform Threat Modeling during the design phase. |
| **A07** | **Authentication Failures** | Implement Phishing-resistant MFA (FIDO2); enforce account lockouts. |
| **A08** | **Integrity Failures** | Verify plugins/libraries; use Subresource Integrity (SRI) for CDN assets. |
| **A09** | **Logging & Alerting** | Log all auth failures/high-value transactions; use a SIEM for alerts. |
| **A10** | **SSRF / Exception Handling** | Sanitize inputs for URLs; implement strict allowlists for outbound calls. |

---

### ⚙️ API Security (OWASP API Top 10:2023)

| Category | Finding | Remediation Strategy |
| --- | --- | --- |
| **API1** | **BOLA (Object Level Auth)** | Validate that the logged-in user owns the resource requested in the URL. |
| **API2** | **Broken Authentication** | Use standard OAuth2/OpenID Connect; secure tokens with short TTLs. |
| **API3** | **BOPLA (Property Level)** | Use Data Transfer Objects (DTOs) to prevent "Mass Assignment" of fields. |
| **API4** | **Unrestricted Consumption** | Set Rate Limits (TPS) and quotas for CPU/Memory/Payload size. |
| **API5** | **Broken Function Level Auth** | Enforce RBAC (Role-Based Access Control) on all admin endpoints. |
| **API6** | **Unrestricted Access to Flows** | Implement business logic checks to prevent "gaming" of the API flow. |
| **API7** | **Server Side Request Forgery** | Block API access to internal metadata services (e.g., AWS IMDS). |
| **API8** | **Security Misconfiguration** | Disable unneeded HTTP methods (e.g., PUT, DELETE) if not used. |
| **API9** | **Improper Inventory** | Maintain OpenAPI/Swagger docs; sunset "Zombie" (old) API versions. |
| **API10** | **Unsafe API Consumption** | Treat data from 3rd-party APIs as untrusted; validate and sanitize it. |

---

### 📱 Mobile Security (OWASP Mobile Top 10:2024)

| Category | Finding | Remediation Strategy |
| --- | --- | --- |
| **M1** | **Improper Credential Usage** | Use Android Keystore/iOS Keychain; never hardcode API keys. |
| **M2** | **Supply Chain Security** | Audit 3rd-party SDKs; use dependency scanning (SCA) in builds. |
| **M3** | **Insecure Auth/AuthZ** | Move authorization logic to the server; don't rely on local app checks. |
| **M4** | **Insufficient Input/Output** | Sanitize inputs for Deeplinks and IPC (Inter-Process Communication). |
| **M5** | **Insecure Communication** | Enforce TLS; implement **Certificate Pinning** to stop MitM attacks. |
| **M6** | **Inadequate Privacy Controls** | Avoid logging PII; use "Masking" for sensitive data in the UI. |
| **M7** | **Insufficient Binary Protect.** | Use Obfuscation (DexGuard/ProGuard) and Anti-Tampering checks. |
| **M8** | **Security Misconfiguration** | Disable debugging in production; restrict file permissions (`0600`). |
| **M9** | **Insecure Data Storage** | Encrypt local SQLite/Realm databases using SQLCipher. |
| **M10** | **Insufficient Cryptography** | Use modern libraries (BouncyCastle/NaCl); avoid custom crypto. |

---

### 🔑 Active Directory & Infrastructure (Red Team Essentials)

| Area | Common Vulnerability | Remediation Strategy |
| --- | --- | --- |
| **AD** | **Kerberoasting** | Use gMSAs or passwords with >25 characters for Service Accounts. |
| **AD** | **AS-REP Roasting** | Ensure "Do not require Kerberos preauthentication" is **unchecked**. |
| **AD** | **Tiered Access** | Implement "Privileged Access Workstations" (PAW) for Domain Admins. |
| **Network** | **LLMNR/NBNS** | Disable via GPO; enable **SMB Signing** to prevent relaying. |
| **Network** | **Default SNMP Strings** | Disable SNMP v1/v2; use SNMP v3 with Auth/Priv or disable entirely. |
| **Infra** | **Unquoted Service Paths** | Wrap service executables in quotes: `"C:\Program Files\App\srv.exe"`. |
| **Infra** | **Cleartext in Shares** | Automate scanning of `SYSVOL` and File Shares for `.xml`, `.ps1` secrets. |

---