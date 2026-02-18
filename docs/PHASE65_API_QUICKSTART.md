<sub>Copyright (c) 2026 José María Micoli | Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}</sub>

# Phase 6.5 API Quickstart (v4.1)

## Start

```bash
make deploy
```

This builds the image, starts PostgreSQL/Redis/API/runtime/nginx, applies tenant migration, and runs API smoke checks.

## Validate

```bash
make api-smoke
```

## Stop

```bash
make api-down
```

## Tenant Claim Requirement

All client API routes require JWT with `tenant_id` claim in `Authorization: Bearer <token>`.
