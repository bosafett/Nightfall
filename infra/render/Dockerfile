# Single-container image for Render's free tier (render.yaml): the Next.js server is the
# only public listener; the API (with the worker loop embedded) listens on 127.0.0.1:8000
# inside the container. Evidence content lives in Postgres (no persistent disk on free).
# Build from the repository root: docker build -f infra/render/Dockerfile .
# Base images are pinned by digest.

FROM node:22-trixie-slim@sha256:2117f713a417f3aff682ac8f5bc2ebbdf1beed51f36e67ab1e0fd3866b6d2d8f AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web ./
ENV API_INTERNAL_URL=http://127.0.0.1:8000 NEXT_TELEMETRY_DISABLED=1
RUN npm run build

FROM python:3.13-slim@sha256:ae14d4ce8771606477a81446e7ef429edd6762305fc50c84507c1041fa8285d1
COPY --from=web /usr/local/bin/node /usr/local/bin/node
RUN useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin nightfall
COPY api/requirements.lock /app/requirements.lock
RUN pip install --no-cache-dir -r /app/requirements.lock
COPY api/pyproject.toml api/alembic.ini /app/api/
COPY api/nightfall /app/api/nightfall
COPY api/migrations /app/api/migrations
RUN pip install --no-cache-dir --no-deps /app/api
COPY --from=web /web/.next/standalone /app/web
COPY --from=web /web/.next/static /app/web/.next/static
COPY --from=web /web/public /app/web/public
COPY infra/render/start.sh /app/start.sh

ENV NIGHTFALL_EVIDENCE_BACKEND=postgres \
    NIGHTFALL_EMBEDDED_WORKER=true \
    NIGHTFALL_TOOL_SANDBOX=none \
    NIGHTFALL_FORWARDED_HOPS=0 \
    NEXT_TELEMETRY_DISABLED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER nightfall
CMD ["/app/start.sh"]
