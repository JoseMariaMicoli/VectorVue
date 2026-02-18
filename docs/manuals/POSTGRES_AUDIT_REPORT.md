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

# PostgreSQL Migration Audit Report

Generated from static analysis of `vv_core.py` database methods.

## Method Classification

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
| `get_active_sessions` | read | No | 1 |
| `log_detection_event` | create | No | 1 |
| `assess_evasion_success` | create | No | 1 |
| `get_detection_timeline` | join, read | No | 1 |
| `calculate_detection_risk` | read | No | 2 |
| `create_campaign_objective` | create | No | 1 |
| `link_action_to_objective` | create | No | 1 |
| `update_objective_progress` | update | Yes | 2 |
| `get_objective_coverage` | join, read | No | 2 |
| `register_persistence` | create | No | 1 |
| `verify_persistence` | create, update | Yes | 2 |
| `mark_persistence_compromised` | update | No | 1 |
| `get_persistence_inventory` | read | No | 1 |
| `get_persistence_redundancy` | read | No | 1 |
| `record_campaign_metrics` | create | No | 1 |
| `raise_alert` | create | No | 1 |
| `acknowledge_alert` | update | No | 1 |
| `get_campaign_dashboard` | read | No | 2 |
| `create_engagement_report` | create | No | 1 |
| `record_ttp_execution` | create, read, update | Yes | 3 |
| `get_ttp_effectiveness_report` | read | No | 1 |
| `add_threat_intel_feed` | create, update | No | 1 |
| `correlate_intel_indicator` | create | No | 1 |
| `get_correlated_intelligence` | join, read | No | 1 |
| `log_remediation_action` | create | No | 1 |
| `assess_remediation_impact` | create | No | 1 |
| `get_remediation_timeline` | join, read | No | 1 |
| `register_capability` | create | No | 1 |
| `record_capability_execution` | create | No | 1 |
| `get_capability_assessment_report` | read | No | 2 |
| `create_collaboration_session` | create | No | 1 |
| `join_collaboration_session` | create, join | No | 1 |
| `sync_collaborative_changes` | create | No | 1 |
| `detect_collaboration_conflicts` | read | No | 1 |
| `create_task_template` | create | No | 1 |
| `schedule_task` | create | No | 1 |
| `log_task_execution` | create | No | 1 |
| `get_task_execution_history` | join, read | No | 1 |
| `create_behavioral_profile` | create | No | 1 |
| `detect_anomalies` | create, read | No | 2 |
| `predict_defense` | create | No | 1 |
| `register_webhook` | create | No | 1 |
| `log_webhook_delivery` | create | No | 1 |
| `register_api_integration` | create | No | 1 |
| `register_compliance_framework` | create | No | 1 |
| `map_compliance_requirement` | create | No | 1 |
| `generate_compliance_report` | create, read | No | 3 |
| `classify_data_tlp` | create | No | 1 |
| `log_sensitive_field_access` | create | No | 1 |
| `log_immutable_audit` | create | No | 1 |
| `verify_audit_chain` | create, read | No | 2 |
| `create_managed_session` | create | No | 1 |
| `check_session_expired` | read | No | 1 |
| `log_re_authentication` | create | No | 1 |
| `create_retention_policy` | create | No | 1 |
| `execute_purge_operation` | create, delete | Yes | 2 |
| `log_secure_deletion` | create | No | 1 |
| `get_pending_scheduled_tasks` | read | No | 1 |
| `execute_scheduled_task` | read, update | No | 2 |
| `get_pending_webhooks` | read | No | 1 |
| `deliver_webhook` | read | No | 1 |
| `enforce_session_timeouts` | read, update | No | 2 |
| `execute_retention_policies` | delete, read, update | Yes | 17 |
| `trigger_anomaly_detection` | create, read | No | 3 |
| `_run_phase3_migrations` | update | Yes | 11 |
| `create_campaign_report` | create | No | 1 |
| `generate_pdf_report` | read, update | No | 2 |
| `generate_html_report` | read, update | No | 2 |
| `create_evidence_manifest` | create, read | Yes | 4 |
| `verify_evidence_manifest` | read, update | No | 4 |
| `get_evidence_manifest` | read | No | 2 |
| `create_finding_summary` | create, update, upsert | No | 1 |
| `map_finding_to_compliance` | create | No | 1 |
| `generate_compliance_report` | create, read | No | 3 |
| `schedule_recurring_report` | create | No | 1 |
| `execute_pending_report_schedules` | create, read, update | Yes | 3 |
| `get_user_by_id` | read | No | 1 |
| `_run_phase4_migrations` | join | No | 10 |
| `create_team` | create | No | 1 |
| `add_team_member` | create | No | 1 |
| `list_teams` | join, read | No | 2 |
| `get_team_members` | join, read | No | 1 |
| `assign_campaign_to_team` | create | No | 1 |
| `get_team_campaigns` | join, read | No | 1 |
| `create_data_sharing_policy` | create | No | 1 |
| `get_sharing_policies` | read | No | 1 |
| `calculate_team_metrics` | create, join, read | No | 6 |
| `calculate_operator_performance` | create, read | No | 6 |
| `get_team_leaderboard` | read | No | 1 |
| `create_intelligence_pool` | create | No | 1 |
| `add_to_intelligence_pool` | read, update | No | 2 |
| `log_coordination` | create | No | 1 |
| `get_coordination_logs` | read | No | 2 |
| `_run_phase5_migrations` | update | Yes | 15 |
| `add_threat_feed` | create | No | 1 |
| `create_threat_actor` | create | No | 1 |
| `link_actor_ttp` | create | No | 1 |
| `ingest_ioc` | create | No | 1 |
| `enrich_ioc` | create | No | 1 |
| `correlate_threat` | create | No | 1 |
| `calculate_risk_score` | create | No | 1 |
| `archive_intelligence` | create | No | 1 |
| `get_actor_profile` | read | No | 3 |
| `get_ioc_intelligence` | read | No | 4 |
| `generate_threat_report` | join, read | No | 6 |
| `get_campaign` | read | No | 4 |
| `save_opportunity` | create | No | 1 |
| `save_attack_path` | create | No | 1 |
| `get_opportunity` | read | No | 1 |
| `save_learning` | create, update, upsert | No | 1 |
| `save_detection` | create | Yes | 2 |
| `get_user_by_id` | read | No | 1 |
| `close` | none | No | 0 |

## Notes

- Methods marked `Multi-table Mutation Candidate = Yes` should be validated with explicit transaction tests.
- Upsert and conflict-handling SQL was normalized for PostgreSQL in compatibility wrappers.
- Immutable and audit-sensitive tables require trigger-based protections in PostgreSQL schema.
