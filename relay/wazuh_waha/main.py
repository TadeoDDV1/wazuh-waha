"""
wazuh-waha: servicio HTTP que recibe alertas de Wazuh y las manda a WhatsApp via WAHA.
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import __version__
from .api.alerts import router as alerts_router
from .api.dashboard import router as dashboard_router
from .api.debug import router as debug_router
from .api.telemetry import router as telemetry_router
from .common.context import WORKER_ID
from .common.logging import log
from .config import settings


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
    yield
    log.info("relay_stopping worker_id=%s", WORKER_ID)


app = FastAPI(
    title="wazuh-waha Relay",
    description="Bridge service forwarding Wazuh alerts to WAHA (WhatsApp HTTP API)",
    version=__version__,
    lifespan=lifespan,
)

# CORS middleware for dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-Api-Key"],
)

app.include_router(alerts_router)
app.include_router(debug_router)
app.include_router(telemetry_router)
app.include_router(dashboard_router)
