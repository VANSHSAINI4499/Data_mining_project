# Backend image: used by both the `backend` (API) and `worker` services.
FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.13.1 /uv /uvx /bin/

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH=/opt/venv/bin:$PATH

# "--no-dev" for runtime images; the development compose file passes "" so tests can run.
ARG UV_SYNC_ARGS="--no-dev"

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project ${UV_SYNC_ARGS}
COPY . .
RUN uv sync --frozen ${UV_SYNC_ARGS}

# Non-root runtime user owning only the writable data directories (SECURITY_REQUIREMENTS §13).
RUN useradd --create-home --uid 10001 cti \
    && mkdir -p /var/lib/cti/uploads /var/lib/cti/artifacts \
    && chown -R cti:cti /var/lib/cti
USER cti

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
