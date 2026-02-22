# SpectraStrike Payload Examples

## Valid Single Event
```json
{
  "source_system": "spectrastrike-sensor",
  "event_type": "PROCESS_ANOMALY",
  "occurred_at": "2026-02-22T10:00:00Z",
  "severity": "high",
  "asset_ref": "host-nyc-01",
  "message": "Unexpected parent-child process chain",
  "metadata": {
    "pid": 2244,
    "parent_pid": 2210,
    "technique": "T1059"
  }
}
```

## Valid Batch Event
```json
[
  {
    "source_system": "spectrastrike-sensor",
    "event_type": "PROCESS_ANOMALY",
    "occurred_at": "2026-02-22T10:00:00Z",
    "severity": "high",
    "asset_ref": "host-nyc-01",
    "message": "Unexpected parent-child process chain"
  },
  {
    "event_id": "evt_external_22",
    "source_system": "spectrastrike-sensor",
    "event_type": "AUTH_SPIKE",
    "occurred_at": "2026-02-22T10:02:00Z",
    "severity": "medium",
    "asset_ref": "host-nyc-02",
    "message": "Burst of failed logins"
  }
]
```

## Valid Single Finding
```json
{
  "title": "Suspicious PowerShell Script",
  "description": "Encoded command observed in endpoint telemetry",
  "severity": "critical",
  "status": "open",
  "first_seen": "2026-02-22T09:45:00Z",
  "asset_ref": "host-nyc-01",
  "recommendation": "Block script hash and isolate endpoint",
  "metadata": {
    "technique": "T1059.001"
  }
}
```

## Partial Failure Batch Response Example
```json
{
  "request_id": "67e0f522-b1b7-4fc2-9fdd-bfc8d5d527f2",
  "status": "partial",
  "data": {
    "summary": {
      "total": 2,
      "accepted": 1,
      "failed": 1
    },
    "results": [
      {
        "index": 0,
        "item_id": "evt_4512abc9e8bc9f34de22f011",
        "status": "accepted",
        "error_code": null,
        "error_message": null
      },
      {
        "index": 1,
        "item_id": null,
        "status": "failed",
        "error_code": "validation_failed",
        "error_message": "Field required"
      }
    ]
  },
  "errors": [],
  "signature": null
}
```

## Status Polling Response Example
```json
{
  "request_id": "f2ec435f-2994-45a3-aaf0-b2ff3863f5f4",
  "status": "accepted",
  "data": {
    "request_id": "67e0f522-b1b7-4fc2-9fdd-bfc8d5d527f2",
    "status": "partial",
    "endpoint": "/api/v1/integrations/spectrastrike/events/batch",
    "counts": {
      "total": 2,
      "accepted": 1,
      "failed": 1
    },
    "failed_items": [
      {
        "index": 1,
        "item_id": null,
        "status": "failed",
        "error_code": "validation_failed",
        "error_message": "Field required"
      }
    ],
    "created_at": "2026-02-22T10:03:23.111111Z",
    "updated_at": "2026-02-22T10:03:23.111111Z"
  },
  "errors": [],
  "signature": null
}
```
