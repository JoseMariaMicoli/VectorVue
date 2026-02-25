<sub>Copyright (c) 2026 Jose Maria Micoli | Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}</sub>

# VectorVue Architecture Specification

This document defines the production architecture of VectorVue as a multi-tenant security validation and assurance platform.

## 1. System Overview

Primary components:

- API service: FastAPI (`vv_client_api.py`)
- Runtime service: campaign and workflow execution support
- ML worker: async model training and inference queues
- Compliance workers: observation derivation and daily compliance evaluation
- Portal: Next.js tenant-facing interface
- Data stores: PostgreSQL and Redis
- Edge: nginx TLS termination and reverse proxy

## 2. Core Architecture Principles

- Tenant isolation is mandatory across all data and APIs.
- Evidence integrity is enforced through append-only and hash-chain models where required.
- Background processing is queue-driven; long-running jobs do not block API request paths.
- Client-facing analytics and compliance outputs are explainable and version-aware.

## 3. Data Domains

Operational domain:

- campaigns, findings, remediation, reports, activity traces

Analytics domain:

- events, feature sets, model registry, predictions, health metrics

Compliance domain:

- frameworks, controls, mappings, observations, control state history, compliance events, scores, snapshots

## 4. Service Interaction Model

1. Operational workflows create tenant-scoped events.
2. Observation worker derives control observations from telemetry.
3. Control evaluator computes effectiveness states.
4. Evidence engine records immutable compliance events with hash links.
5. Compliance scoring computes framework-level posture snapshots.
6. Client and auditor APIs expose signed, tenant-scoped outputs.

## 5. Security Controls

- JWT tenant claim enforcement
- role-based access controls
- signed compliance response envelopes
- immutable compliance event chain
- restricted telemetry scope (security workflow behavior only)

## 6. Deployment Topology (Default)

- `vectorvue_app`
- `vectorvue_runtime`
- `vectorvue_ml_worker`
- `vectorvue_compliance_observation_worker`
- `vectorvue_compliance_daily_worker`
- `vectorvue_portal`
- `vectorvue_nginx`
- `vectorvue_postgres`
- `vectorvue_redis`

## 7. Auditor Verifiability Contract

Auditors can:

1. select a time window
2. retrieve signed dataset package
3. verify checksums and hash-chain integrity
4. recompute control effectiveness
5. validate framework-level compliance state

