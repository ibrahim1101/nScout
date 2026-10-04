# syntax=docker/dockerfile:1

# Build the React frontend first.
FROM node:24-bookworm-slim AS frontend-builder
WORKDIR /src/frontend
# Node 24 images already include Yarn/Corepack tooling; avoid reinstalling Yarn
# over the existing /usr/local/bin/yarnpkg binary.
COPY frontend/package.json ./
COPY frontend/yarn.lock* ./
RUN if [ -f yarn.lock ]; then yarn install --frozen-lockfile; else yarn install; fi
COPY frontend/ ./
ENV REACT_APP_BACKEND_URL=""
RUN yarn build

# Runtime image for FastAPI + the compiled React UI.
FROM python:3.11-slim-bookworm AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MONGO_URL=mongodb://mongo:27017 \
    DB_NAME=nscout \
    CORS_ORIGINS=*

WORKDIR /app

# libpcap enables Scapy packet capture inside Linux containers.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt ./requirements.txt
RUN python -m pip install --no-cache-dir --upgrade pip setuptools wheel \
    && python -m pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/
COPY --from=frontend-builder /src/frontend/build ./backend/frontend_build/

EXPOSE 8001

# server.py imports etherlens as a top-level package, so run with backend on PYTHONPATH.
WORKDIR /app/backend
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8001"]
