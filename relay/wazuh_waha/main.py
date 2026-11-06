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
from .api.auth import router as auth_router
from .api.console import router as console_router
from .api.dashboard import router as dashboard_router
from .api.debug import router as debug_router
from .api.reports import router as reports_router
from .api.telemetry import router as telemetry_router
from .api.wazuh_control import router as wazuh_control_router
from .api.waha_webhook import router as waha_webhook_router
from .common.audit import get_audit_log
from .common.body_limit import BodySizeLimitMiddleware
from .common.context import WORKER_ID
from .common.logging import log
from .common.network_bus import network_bus
from .common.request import client_ip as _client_ip
from .common.session import COOKIE_NAME, verify_session
from .common.traffic_stream import traffic_watcher
from .config import settings
from .infrastructure.agent_analyzer import agent_watcher
from .infrastructure.telegram_bot import telegram_bot


# ── Rate limiting simple (por IP real + bucket de path) ─────────────────────
_RATE_LIMITS: dict[str, deque] = defaultdict(deque)
_RATE_WINDOW_SEC = 60.0
_RATE_MAX_DEFAULT = 300
_RATE_MAX_ALERTS = 120
_RATE_MAX_TELEMETRY = 600
_RATE_MAX_AUTH = 5          # login: fuerza bruta de la API key
_RATE_SWEEP_SEC = 60.0
_last_sweep = 0.0


def _rate_allow(key: str, limit: int) -> bool:
    global _last_sweep
    now = time.monotonic()
    # Depura buckets con ventanas vacías: sin esto, IPs rotando crecen
    # _RATE_LIMITS sin límite (memory leak).
    if now - _last_sweep > _RATE_SWEEP_SEC:
        _last_sweep = now
        for k in list(_RATE_LIMITS):
            w = _RATE_LIMITS[k]
            while w and now - w[0] > _RATE_WINDOW_SEC:
                w.popleft()
            if not w:
                del _RATE_LIMITS[k]
    window = _RATE_LIMITS[key]
    while window and now - window[0] > _RATE_WINDOW_SEC:
        window.popleft()
    if len(window) >= limit:
        return False
    window.append(now)
    return True


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Fail-fast: nunca exponer el relay fuera de loopback con la clave de
    # fábrica. Sin esto un despliegue sin .env arranca con "changeme".
    _insecure_keys = {"", "changeme", "cambiar_relay_api_key", "cambiar"}
    _loopback = {"127.0.0.1", "::1", "localhost"}
    if settings.relay_api_key.strip().lower() in _insecure_keys and settings.relay_bind not in _loopback:
        raise RuntimeError(
            "RELAY_API_KEY insegura (valor de fábrica) con RELAY_BIND="
            f"{settings.relay_bind}. Genera una clave con 'openssl rand -hex 24' "
            "o enlaza el relay solo a 127.0.0.1."
        )
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
    network_bus.start()
    telegram_bot.start()
    agent_watcher.start()
    yield
    await agent_watcher.stop()
    await telegram_bot.stop()
    await network_bus.stop()
    await traffic_watcher.stop()
    log.info("relay_stopping worker_id=%s", WORKER_ID)


app = FastAPI(
    title="wazuh-waha Relay",
    description="Bridge service forwarding Wazuh alerts to WAHA (WhatsApp HTTP API)",
    version=__version__,
    lifespan=lifespan,
    # /docs y /openapi.json exponen el mapa completo de la API: apagados
    # en prod (ENABLE_DOCS=true para re-activarlos en dev).
    docs_url="/docs" if settings.enable_docs else None,
    redoc_url="/redoc" if settings.enable_docs else None,
    openapi_url="/openapi.json" if settings.enable_docs else None,
)

# add_middleware inserta en la cabeza: el ÚLTIMO agregado queda más externo.
# Registro en este orden -> stack externo→interno: CORS → rate-limit → body
# ⇒ las respuestas 429 y 413 pasan por CORS y llevan cabeceras.
app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_body_bytes)


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    client = _client_ip(request)
    # Sesiones reales tienen bucket propio (sid): detrás del proxy de nginx
    # todos los usuarios comparten IP, y con XFF ausente compartirían bucket.
    # El sid se verifica (no solo se lee) para que cookies falsas no puedan
    # evadir el rate limit generando buckets nuevos a voluntad.
    identity = client
    token = request.cookies.get(COOKIE_NAME)
    if token:
        payload = verify_session(token)
        if payload is not None:
            identity = f"sid:{payload['sid']}"

    path = request.url.path
    method = request.method

    if path.startswith("/alerts") and method == "POST":
        limit = _RATE_MAX_ALERTS
        bucket = f"alerts:{identity}"
    elif path == "/api/v1/auth/login" and method == "POST":
        limit = _RATE_MAX_AUTH
        bucket = f"auth:{client}"  # login siempre por IP (fuerza bruta)
    elif path.startswith("/api/v1/telemetry"):
        limit = _RATE_MAX_TELEMETRY
        bucket = f"tel:{identity}"
    elif path in ("/health", "/docs", "/openapi.json"):
        limit = _RATE_MAX_DEFAULT
        bucket = f"misc:{client}"
    else:
        limit = _RATE_MAX_DEFAULT
        bucket = f"default:{identity}"

    if not _rate_allow(bucket, limit):
        log.warning("rate_limited path=%s ip=%s limit=%d/60s", path, client, limit)
        return JSONResponse(
            status_code=429,
            content={"error": "rate limit exceeded", "limit_per_min": limit},
        )
    return await call_next(request)


# CORS se registra al final para quedar por fuera del rate limit.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-Api-Key"],
)


# ── Auditoría de mutaciones ────────────────────────────────────────────────
# Todas las escrituras autenticadas quedan en <relay_lib_dir>/audit.jsonl
# (quién, cuándo, desde dónde, qué endpoint, resultado). /alerts se excluye:
# es ingesta de Wazuh, no una decisión administrativa.
_AUDIT_PREFIXES = ("/api/v1/dashboard/", "/api/v1/telemetry/traffic/", "/api/v1/wazuh/", "/api/v1/console/")
_AUDIT_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@app.middleware("http")
async def audit_middleware(request: Request, call_next):
    path = request.url.path
    if request.method not in _AUDIT_METHODS or not path.startswith(_AUDIT_PREFIXES):
        return await call_next(request)

    response = await call_next(request)
    # scope["state"] es compartido entre middleware y handlers: el auth que
    # fijó verify_api_key/verify_write durante el manejo es visible aquí.
    auth = getattr(request.state, "auth", None) or {}
    get_audit_log().record(
        method=request.method,
        path=path,
        status=response.status_code,
        ip=_client_ip(request),
        sid=auth.get("sid", "-"),
        scope=auth.get("scope", "-"),
    )
    return response


app.include_router(auth_router)
app.include_router(alerts_router)
app.include_router(debug_router)
app.include_router(telemetry_router)
app.include_router(wazuh_control_router)
app.include_router(console_router)
app.include_router(dashboard_router)
app.include_router(reports_router)
app.include_router(waha_webhook_router)
