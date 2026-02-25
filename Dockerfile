# Copyright (c) 2026 NyxeraLabs
# Author: José María Micoli
# Licensed under BSL 1.1
# Change Date: 2033-02-17 → Apache-2.0
#
# You may:
# ✔ Study
# ✔ Modify
# ✔ Use for internal security testing
#
# You may NOT:
# ✘ Offer as a commercial service
# ✘ Sell derived competing products
#
# You may:
# ✔ Study
# ✔ Modify
# ✔ Use for internal security testing
#
# You may NOT:
# ✘ Offer as a commercial service
# ✘ Sell derived competing products

FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    libffi-dev \
    libcairo2 \
    libgdk-pixbuf-2.0-0 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    shared-mime-info \
    fonts-dejavu-core \
    fonts-jetbrains-mono \
    fonts-noto-color-emoji \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --upgrade pip setuptools wheel \
    && pip install -r requirements.txt

COPY . .

RUN python -m py_compile vv.py vv_core.py vv_core_postgres.py vv_client_api.py scripts/*.py tests/test_postgres_smoke.py \
    && VV_DB_BACKEND=sqlite python -m unittest -q tests/test_postgres_smoke.py \
    && python -m compileall -q vv.py vv_core.py vv_core_postgres.py vv_client_api.py vv_*.py cognition_service.py engines scripts tests

FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH="/opt/venv/bin:$PATH" \
    VV_DB_BACKEND=postgres \
    VV_DB_HOST=postgres \
    VV_DB_PORT=5432 \
    VV_DB_NAME=vectorvue_db \
    VV_DB_USER=vectorvue \
    VV_DB_PASSWORD=strongpassword \
    VV_HEALTH_PORT=8080 \
    VV_RUN_MODE=service

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    tini \
    postgresql-client \
    libcairo2 \
    libgdk-pixbuf-2.0-0 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libffi8 \
    shared-mime-info \
    fonts-dejavu-core \
    fonts-jetbrains-mono \
    fonts-noto-color-emoji \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 10001 vectorvue \
    && useradd --system --uid 10001 --gid vectorvue --create-home --home-dir /home/vectorvue --shell /usr/sbin/nologin vectorvue \
    && mkdir -p /opt/vectorvue /var/lib/vectorvue/reports /var/lib/vectorvue/logs /var/lib/vectorvue/run /var/lib/vectorvue/tmp \
    && chown -R vectorvue:vectorvue /opt/vectorvue /var/lib/vectorvue /home/vectorvue

WORKDIR /opt/vectorvue

COPY --from=builder /opt/venv /opt/venv
COPY --from=builder --chown=vectorvue:vectorvue /build /opt/vectorvue

RUN rm -rf /opt/vectorvue/.git /opt/vectorvue/venv /opt/vectorvue/__pycache__ \
    && ln -sfn /var/lib/vectorvue/reports /opt/vectorvue/Reports \
    && ln -sfn /var/lib/vectorvue/logs /opt/vectorvue/logs \
    && python -m compileall -q /opt/vectorvue/vv.py /opt/vectorvue/vv_core.py /opt/vectorvue/vv_core_postgres.py /opt/vectorvue/vv_client_api.py /opt/vectorvue/engines /opt/vectorvue/scripts /opt/vectorvue/tests

USER vectorvue:vectorvue

EXPOSE 8080

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "-m", "uvicorn", "vv_client_api:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers"]
