"""Browser origin checks for the unauthenticated local nScout service."""
import os
import re

DEFAULT_ORIGINS = (
    "http://localhost:8001", "http://127.0.0.1:8001",
    "http://localhost:3000", "http://127.0.0.1:3000",
)

def allowed_origins():
    configured = os.environ.get("CORS_ORIGINS")
    origins = DEFAULT_ORIGINS if configured is None else tuple(x.strip() for x in configured.split(",") if x.strip())
    if "*" in origins or "null" in origins:
        raise RuntimeError("CORS_ORIGINS must list trusted origins explicitly; wildcard and null are unsafe")
    origins = list(origins)
    local_origin = os.environ.get("NSCOUT_LOCAL_ORIGIN")
    if local_origin:
        if not re.fullmatch(r"http://127\.0\.0\.1:[0-9]{1,5}", local_origin) or not 1 <= int(local_origin.rsplit(":", 1)[1]) <= 65535:
            raise RuntimeError("Invalid local launcher origin")
        if local_origin not in origins:
            origins.append(local_origin)
    return origins

def browser_origin_allowed(origin, origins):
    # Non-browser clients may omit Origin. This is not an authentication check.
    return origin is None or origin in origins
