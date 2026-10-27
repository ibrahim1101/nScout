"""Browser origin checks for the unauthenticated local nScout service."""
import os

DEFAULT_ORIGINS = (
    "http://localhost:8001", "http://127.0.0.1:8001",
    "http://localhost:3000", "http://127.0.0.1:3000",
)

def allowed_origins():
    configured = os.environ.get("CORS_ORIGINS")
    origins = DEFAULT_ORIGINS if configured is None else tuple(x.strip() for x in configured.split(",") if x.strip())
    if "*" in origins or "null" in origins:
        raise RuntimeError("CORS_ORIGINS must list trusted origins explicitly; wildcard and null are unsafe")
    return list(origins)

def browser_origin_allowed(origin, origins):
    # Non-browser clients may omit Origin. This is not an authentication check.
    return origin is None or origin in origins
