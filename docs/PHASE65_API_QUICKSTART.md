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
