FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1
WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install .

FROM python:3.12-slim

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
RUN groupadd --system auditor \
    && useradd --system --gid auditor --create-home --home-dir /home/auditor auditor \
    && mkdir -p /app/output /app/cache /app/config \
    && chown -R auditor:auditor /app /home/auditor
COPY --from=builder /opt/venv /opt/venv
WORKDIR /app
USER auditor
VOLUME ["/app/output", "/app/cache", "/app/config"]
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD ["origin-audit", "version"]
ENTRYPOINT ["origin-audit"]
CMD ["--help"]
