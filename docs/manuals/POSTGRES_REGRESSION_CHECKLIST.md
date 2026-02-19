<sub>Copyright (c) 2026 Jose Maria Micoli | Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}</sub>

# PostgreSQL Regression Checklist

Use this checklist before release cutover and after major migrations.

## 1. Platform Boot

- [ ] `make deploy` completes without errors
- [ ] `vectorvue_app` health endpoint reports healthy
- [ ] login and token issuance operate normally

## 2. Core Workflows

- [ ] campaign data loads and tenant scoping is correct
- [ ] findings and evidence APIs return expected payloads
- [ ] remediation and risk endpoints return expected payloads
- [ ] report listing and download paths are functional

## 3. Analytics and Workers

- [ ] ML worker is running and queue listener is active
- [ ] analytics endpoints return score/confidence/explanation contract
- [ ] no cross-tenant analytics leakage observed

## 4. Compliance Assurance

- [ ] compliance workers are running
- [ ] `/compliance/frameworks` returns signed response envelope
- [ ] framework score/report endpoints return valid dataset hash
- [ ] audit window endpoint returns expected counts

## 5. Data Integrity

- [ ] immutable compliance event behavior enforced
- [ ] hash-chain validation succeeds for sampled tenant
- [ ] evidence export package checksums verify

## 6. Security Controls

- [ ] RBAC enforcement works by role
- [ ] tenant claim enforcement blocks unauthorized scope access
- [ ] telemetry ingestion respects privacy constraints

