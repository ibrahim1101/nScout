# ---------- Stage 1: build React UI ----------
FROM node:20-alpine AS ui
WORKDIR /ui
COPY frontend/package.json frontend/yarn.lock ./
RUN yarn install --frozen-lockfile
COPY frontend/ ./
# Same-origin build so the single container serves both UI and API
ENV REACT_APP_BACKEND_URL=""
RUN yarn build


# ---------- Stage 2: Python runtime ----------
FROM python:3.11-slim AS runtime

# libpcap for live capture, tini for proper signal handling
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 tini \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python deps first for caching
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

# App source
COPY backend/ /app/backend/

# Compiled React UI → served by FastAPI at `/`
COPY --from=ui /ui/build /app/backend/frontend_build

ENV PYTHONUNBUFFERED=1 \
    MONGO_URL=mongodb://mongo:27017 \
    DB_NAME=nscout \
    CORS_ORIGINS=* \
    EMERGENT_LLM_KEY=""

EXPOSE 8001
WORKDIR /app/backend
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "-m", "uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8001"]

# For live capture, run with:
#   docker run --rm -p 8001:8001 --cap-add=NET_RAW --cap-add=NET_ADMIN --network host nscout
# Without those caps the app still works in Simulated / PCAP-upload mode.
