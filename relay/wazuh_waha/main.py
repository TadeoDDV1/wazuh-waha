"""
wazuh-waha: servicio HTTP que recibe alertas de Wazuh y las manda a WhatsApp via WAHA.
"""
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from . import __version__
from .api.alerts import router as alerts_router
from .api.dashboard import router as dashboard_router
from .api.debug import router as debug_router
from .api.telemetry import router as telemetry_router
from .common.context import WORKER_ID
from .common.logging import log
from .common.traffic_stream import traffic_watcher
from .config import settings


# ── Rate limiting simple (por IP + bucket de path) ──────────────────────────
_RATE_LIMITS: dict[str, deque] = defaultdict(deque)
_RATE_WINDOW_SEC = 60.0
_RATE_MAX_DEFAULT = 300
_RATE_MAX_ALERTS = 120
_RATE_MAX_TELEMETRY = 600


def _rate_allow(key: str, limit: int) -> bool:
    now = time.monotonic()
    window = _RATE_LIMITS[key]
    while window and now - window[0] > _RATE_WINDOW_SEC:
        window.popleft()
    if len(window) >= limit:
        return False
    window.append(now)
    return True


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info(
        "relay_started worker_id=%s port=%s chat=%s ollama=%s waha=%s session=%s log_dir=%s",
        WORKER_ID,
        settings.relay_port,
        settings.admin_chat_id,
        settings.ollama_host,
        settings.waha_host,
        settings.waha_session,
        settings.relay_log_dir,
    )
    traffic_watcher.start()
    yield
    await traffic_watcher.stop()
    log.info("relay_stopping worker_id=%s", WORKER_ID)


app = FastAPI(
    title="wazuh-waha Relay",
    description="Bridge service forwarding Wazuh alerts to WAHA (WhatsApp HTTP API)",
    version=__version__,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-Api-Key"],
)


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    client = request.client.host if request.client else "unknown"
    path = request.url.path
    method = request.method

    if path.startswith("/alerts") and method == "POST":
        limit = _RATE_MAX_ALERTS
        bucket = f"alerts:{client}"
    elif path.startswith("/api/v1/telemetry"):
        limit = _RATE_MAX_TELEMETRY
        bucket = f"tel:{client}"
    elif path in ("/health", "/docs", "/openapi.json"):
        limit = _RATE_MAX_DEFAULT
        bucket = f"misc:{client}"
    else:
        limit = _RATE_MAX_DEFAULT
        bucket = f"default:{client}"

    if not _rate_allow(bucket, limit):
        log.warning("rate_limited path=%s ip=%s limit=%d/60s", path, client, limit)
        return JSONResponse(
            status_code=429,
            content={"error": "rate limit exceeded", "limit_per_min": limit},
        )
    return await call_next(request)


app.include_router(alerts_router)
app.include_router(debug_router)
app.include_router(telemetry_router)
app.include_router(dashboard_router)
