# Copyright (c) 2026 José María Micoli
# Licensed under Apache-2.0

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libcairo2 \
    libgdk-pixbuf-2.0-0 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libffi8 \
    shared-mime-info \
    fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY . .

ENV VV_DB_BACKEND=postgres \
    VV_DB_HOST=postgres \
    VV_DB_PORT=5432 \
    VV_DB_NAME=vectorvue \
    VV_DB_USER=vectorvue \
    VV_DB_PASSWORD=vectorvue

CMD ["python", "vv.py"]
