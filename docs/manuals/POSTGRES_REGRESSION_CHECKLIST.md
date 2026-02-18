# Copyright (c) 2026 José María Micoli
# Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}
#
# You may:
# ✔ Study
# ✔ Modify
# ✔ Use for internal security testing
#
# You may NOT:
# ✘ Offer as a commercial service
# ✘ Sell derived competing products

# PostgreSQL Regression Checklist

## Platform Boot

- [ ] `docker compose up -d postgres` reports healthy
- [ ] `VV_DB_BACKEND=postgres` app launch succeeds
- [ ] Login/register/auth canary behavior unchanged

## Campaign and Operations

- [ ] Campaign create/select/list works
- [ ] Asset and credential CRUD works
- [ ] Session lifecycle events populate correctly
- [ ] Detection timeline queries render without SQL errors
- [ ] Objective and persistence views update correctly

## Cognition Layer (Phase 5.5)

- [ ] Opportunities, paths, state, pressure, confidence tabs load
- [ ] Recommendation scoring and explainability remain deterministic
- [ ] Replay and tempo metrics populate with campaign telemetry

## Reporting and Exports

- [ ] Markdown export works
- [ ] MITRE Navigator JSON export works
- [ ] PDF/HTML generation completes without DB syntax issues

## Security and Audit

- [ ] Audit log inserts continue for mutations
- [ ] Immutable evidence update/delete protections enforced
- [ ] HMAC/SHA256 integrity checks return expected results
- [ ] RBAC checks still block unauthorized actions

## Integrations and Runtime

- [ ] Background scheduled tasks execute
- [ ] Webhook queue processing works
- [ ] Retention policy execution works

## Concurrency

- [ ] Multi-operator lock workflows behave correctly
- [ ] No deadlocks under parallel session activity
