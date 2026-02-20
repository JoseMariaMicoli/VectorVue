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

# PostgreSQL Migration Audit Report

This document records static analysis and migration-audit context for PostgreSQL transition quality checks.

## Scope

- verify method-level SQL touchpoints
- identify multi-table mutation candidates
- support regression and release sign-off workflows

## Status

The detailed method classification table is generated from codebase analysis and should be treated as audit evidence for migration review cycles.

For active release validation, use:

- `docs/manuals/POSTGRES_REGRESSION_CHECKLIST.md`
- `docs/manuals/POSTGRES_MIGRATION_GUIDE.md`
- `make api-smoke`

## Method Classification Reference

Generated from static analysis of `vv_core.py` database methods.

| Method | Categories | Multi-table Mutation Candidate | SQL Fragments |
|---|---|---|---|
| `__init__` | none | No | 0 |
| `_run_postgres_migrations` | none | No | 0 |
| `_run_migrations` | create, delete, join, update, upsert | Yes | 82 |
| `transaction` | none | No | 0 |
| `verify_or_set_canary` | create, read | No | 2 |
| `has_users` | read | No | 1 |
| `register_user` | create, read, update | Yes | 5 |
| `authenticate_user` | create, read, update | Yes | 3 |
| `_persist_session` | none | No | 0 |
| `resume_session` | read | No | 2 |
| `logout` | delete | No | 1 |
| `list_users` | read | No | 1 |
| `set_user_role` | create, read, update, upsert | Yes | 4 |
| `list_user_access` | join, read | No | 1 |
| `set_user_capability_profile` | create, read, update, upsert | Yes | 3 |
| `list_groups` | read | No | 1 |
| `create_group` | create | No | 1 |
| `list_projects` | read | No | 2 |
| `create_project` | create | No | 1 |
| `archive_project` | update | No | 1 |
| `create_campaign` | create | No | 1 |
| `list_campaigns` | read | No | 1 |
| `get_campaign_by_name` | read | No | 1 |
| `get_campaign_by_id` | read | No | 1 |
| `add_asset` | create | No | 1 |
| `list_assets` | read | No | 1 |
| `add_credential` | create, delete | Yes | 2 |
| `list_credentials` | read | No | 1 |
| `log_action` | create | No | 1 |
| `list_actions` | read | No | 1 |
| `add_relation` | create | No | 1 |
| `verify_campaign_integrity` | read | No | 4 |
| `calculate_detection_coverage` | none | No | 0 |
| `build_attack_path` | none | No | 0 |
| `generate_campaign_report` | read | No | 1 |
| `_visible_filter` | none | No | 0 |
| `get_findings` | read | No | 1 |
| `_rows_to_findings` | none | No | 0 |
| `add_finding` | create | No | 1 |
| `update_finding` | read, update | Yes | 3 |
| `delete_finding` | delete | Yes | 3 |
| `approve_finding` | read, update | No | 2 |
| `reject_finding` | delete, read, update | Yes | 4 |
| `log_audit_event` | create, delete, upsert | Yes | 4 |
| `_audit` | create, upsert | No | 1 |
| `get_audit_log` | read | No | 1 |
| `_require_role` | none | No | 0 |
| `_check_write_permission` | read | No | 1 |
| `enter_phase` | create, update | Yes | 3 |
| `get_current_phase` | read | No | 1 |
| `get_phase_history` | read | No | 1 |
| `add_relationship` | create | No | 1 |
| `get_attack_path` | read | No | 2 |
| `build_compromise_chain` | read | No | 1 |
| `mark_credential_valid` | create, read, update | Yes | 3 |
| `mark_credential_invalid` | create, read, update | Yes | 3 |
| `mark_credential_burned` | create, read, update | Yes | 3 |
| `get_credential_state` | read | No | 1 |
| `add_opsec_rule` | create | No | 1 |
| `calculate_action_risk` | create, read | No | 3 |
| `acquire_target_lock` | create, read | No | 2 |
| `release_target_lock` | delete, read | No | 2 |
| `review_lock_diff` | create | No | 1 |
| `log_command_execution` | create | No | 1 |
| `get_command_history` | read | No | 1 |
| `analyze_command_detection_risk` | read | No | 2 |
| `open_session` | create | No | 1 |
| `close_session` | update | No | 1 |
| `mark_session_detected` | update | No | 1 |
| `revive_session` | update | No | 1 |

