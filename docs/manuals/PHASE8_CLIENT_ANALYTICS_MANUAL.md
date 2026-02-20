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

# Client Analytics Manual

This manual explains how to use VectorVue analytics in commercial delivery and stakeholder communication.

## Scope

Analytics capabilities include:

- security effectiveness scoring
- residual risk estimation
- detection coverage insight
- anomaly visibility
- explainable model output and confidence indicators

## Portal Workflow

1. Open `Overview` and verify KPI and analytics cards load.
2. Open `Analytics` and review score, confidence, explanations, model version, and generation time.
3. Run simulation to evaluate proposed defensive improvements.
4. Open `Risk` to communicate trend and severity posture.

## API Workflow

Use tenant-authenticated token and call:

- `GET /ml/client/security-score`
- `GET /ml/client/risk`
- `GET /ml/client/detection-gaps`
- `GET /ml/client/anomalies`
- `POST /ml/client/simulate`

Expected response contract:

- `score`
- `confidence`
- `explanation`
- `model_version`
- `generated_at`

## Quality and Governance Rules

- Tenant isolation is mandatory for all analytics data paths.
- Predictions must reference model version and dataset lineage.
- Explanations must be available for client-facing decisions.
- Model promotion is explicit and controlled.

## Troubleshooting

1. Verify migrations and seed data:

```bash
make deploy
make seed-clients
```

2. Verify workers are healthy:

```bash
docker compose ps
```

3. Validate endpoint behavior with API smoke and direct calls.

