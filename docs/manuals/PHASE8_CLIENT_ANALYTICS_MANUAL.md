<sub>Copyright (c) 2026 José María Micoli | Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}</sub>

# VectorVue Client Analytics Manual (Phase 8)

## Purpose

This guide explains how client users and delivery teams use commercial analytics features in the portal and API.
It is step-by-step, tenant-safe, and focused on operational outcomes.

## What Is Included

- explainable tenant-scoped ML scores
- confidence values and model versions on every response
- anomaly baseline monitoring
- detection gap and residual risk estimates
- defensive simulation ("what-if" projection)
- operator suggestion analytics for campaign context

## Access Requirements

1. Deploy stack: `make deploy`
2. Seed demo data: `make seed-clients`
3. Login to portal:
   - `https://acme.vectorvue.local/login`
   - `https://globex.vectorvue.local/login`

## Portal Workflow

### 1) Open `Overview`

1. Confirm classic risk cards render.
2. Confirm ML cards render:
   - `ML Security Score`
   - `ML Residual Risk`
   - `ML Detection Coverage`
   - `ML Baseline Anomaly`

### 2) Open `Analytics`

1. Open `/portal/analytics`.
2. Review top cards:
   - security score
   - residual risk
   - detection coverage
   - anomaly baseline
   - operator suggestion score
3. Review `Phase 8 Score Comparison` bar chart.
4. Review `Latest Explanations` block for human-readable drivers.
5. Review `Model Timeline`:
   - `model_version`
   - `generated_at`
6. Click `Run Hardening Simulation` and verify projection score appears.

### 3) Open `Risk`

1. Confirm classic severity and trend visuals.
2. Confirm additional ML risk cards render for customer-facing narrative.

## API Workflow

Use the same JWT token from `POST /api/v1/client/auth/login`.

### Client analytics endpoints

- `GET /ml/client/security-score`
- `GET /ml/client/risk`
- `GET /ml/client/detection-gaps`
- `GET /ml/client/anomalies`
- `POST /ml/client/simulate`
- `GET /ml/operator/suggestions/{campaign_id}`

### Response contract

All client ML endpoints return:

- `score`
- `confidence`
- `explanation`
- `model_version`
- `generated_at`

No raw ML internals are exposed to client users.

## Example Calls

```bash
TOKEN="<access_token>"

curl -k https://127.0.0.1/ml/client/security-score \
  -H "Authorization: Bearer $TOKEN"

curl -k https://127.0.0.1/ml/client/risk \
  -H "Authorization: Bearer $TOKEN"

curl -k https://127.0.0.1/ml/client/detection-gaps \
  -H "Authorization: Bearer $TOKEN"

curl -k https://127.0.0.1/ml/client/anomalies \
  -H "Authorization: Bearer $TOKEN"

curl -k -X POST https://127.0.0.1/ml/client/simulate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"scenario":"hardening-sprint","controls_improvement":0.18,"detection_improvement":0.14}'
```

## Commercial Readiness Checklist

- tenant isolation enforced in all analytics queries
- model outputs include explainability text
- model version attached to every prediction
- predictions mapped to dataset/model lineage in analytics schema
- no client access to cross-tenant records
- no auto-promotion without explicit action

## Troubleshooting

If analytics cards show defaults or pending values:

1. verify migrations:
   - `make phase8-migrate`
2. re-seed:
   - `make seed-clients`
3. verify worker and API:
   - `docker compose ps`
   - `make api-smoke`
