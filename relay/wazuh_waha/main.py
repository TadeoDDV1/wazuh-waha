"""
wazuh-waha: servicio HTTP que recibe alertas de Wazuh y las manda a WhatsApp via WAHA.
Con logging detallado de cada alerta en cada paso del pipeline.
"""
import json
import logging
import os
import time
from collections import deque
from contextlib import asynccontextmanager
from logging.handlers import RotatingFileHandler
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse

from . import waha_client
from .config import settings
from .formatter import format_alert

# Worker ID para distinguir logs entre workers uvicorn.
WORKER_ID = os.getpid()

# --- Logging estructurado a journal (JSON) + archivo human-readable ---
log = logging.getLogger("wazuh-waha")
log.setLevel(logging.INFO)

JSON_FMT = (
    '{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s",'
    '"worker":' + str(WORKER_ID) + ',"msg":"%(message)s"}'
)
HUMAN_FMT = f"%(asctime)s [%(levelname)-7s] wazuh-waha[%(process)d] :: %(message)s"
DATE_FMT = "%Y-%m-%d %H:%M:%S"

# Handler JSON al journal (lo recoje systemd)
_jh = logging.StreamHandler()
_jh.setFormatter(logging.Formatter(JSON_FMT))
log.addHandler(_jh)

# Handler human-readable a archivo por-worker (un log por proceso uvicorn).
try:
    log_dir = Path(settings.relay_log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    _fh = RotatingFileHandler(
        log_dir / f"wazuh-waha-{WORKER_ID}.log",
        maxBytes=2_000_000,
        backupCount=3,
        encoding="utf-8",
    )
    _fh.setFormatter(logging.Formatter(HUMAN_FMT, DATE_FMT))
    log.addHandler(_fh)
    log.info("file_logger_init path=%s", log_dir / f"wazuh-waha-{WORKER_ID}.log")
except Exception as e:
    log.warning("file_logger_init_failed err=%s continuando_solo_journal", e)


# --- Buffer en memoria de las ultimas alertas (para /debug/recent) ---
# NOTA multi-worker: cada worker tiene su propio buffer. /debug/recent
# devuelve solo el del worker que recibio la request. Para tener una
# vista global, journalctl es la fuente.
_RECENT_CAP = 50
_recent: deque[dict] = deque(maxlen=_RECENT_CAP)

# Metadata del worker (para /debug/workers)
_worker_started_at = time.time()


def _record_recent(entry: dict) -> None:
    """Guarda la entrada en el buffer circular para /debug/recent."""
    _recent.append(entry)


# --- Auth ---
async def verify_api_key(request: Request) -> None:
    key = request.headers.get("X-Api-Key") or request.headers.get("x-api-key")
    if not key or key != settings.relay_api_key:
        log.warning(
            "auth_fail path=%s ip=%s",
            request.url.path,
            request.client.host if request.client else "?",
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="unauthorized")


# --- Lifespan (reemplaza on_event deprecation) ---
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


# --- App ---
app = FastAPI(
    title="wazuh-waha",
    description="Bridge Wazuh manager -> WAHA (WhatsApp)",
    version="0.3.0",
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "wazuh-waha",
        "version": app.version,
        "worker_id": WORKER_ID,
    }


@app.get("/debug/recent")
async def debug_recent():
    """Devuelve las ultimas N alertas recibidas y su resultado. Sin auth (solo para debug)."""
    return {
        "count": len(_recent),
        "max": _RECENT_CAP,
        "worker_id": WORKER_ID,
        "alerts": list(_recent),
    }


@app.get("/debug/workers")
async def debug_workers():
    """Devuelve info del worker que respondio. Para tener la lista de TODOS
    los workers, hay que hacer N requests (uno por worker) o leer journalctl."""
    return {
        "worker_id": WORKER_ID,
        "pid": WORKER_ID,
        "started_at": _worker_started_at,
        "uptime_sec": time.time() - _worker_started_at,
    }


@app.post("/alerts")
async def receive_alert(request: Request, _: None = Depends(verify_api_key)):
    """Recibe alerta del manager Wazuh. Body esperado: dict con la alerta parseada."""
    t_start = time.time()

    # 1) Body
    try:
        body_bytes = await request.body()
        alert = json.loads(body_bytes.decode("utf-8"))
    except Exception as e:
        log.warning(
            "invalid_json err=%s remote=%s worker=%s",
            e, request.client.host if request.client else "?", WORKER_ID,
        )
        raise HTTPException(status_code=400, detail="invalid json")

    if not isinstance(alert, dict):
        log.warning("invalid_payload type=%s", type(alert).__name__)
        raise HTTPException(status_code=400, detail="expected object")

    # 2) Extraer campos clave para logging
    rule = alert.get("rule", {}) or {}
    agent = alert.get("agent", {}) or {}
    rule_id = str(rule.get("id", "0"))
    agent_id = str(agent.get("id", "0"))
    agent_name = agent.get("name", "?")
    level = int(rule.get("level", 0))
    description = rule.get("description", "?")
    ts_alert = alert.get("timestamp", "?")

    log.info(
        "alert_received rule_id=%s level=%d agent_id=%s agent=%s desc=%r body_bytes=%d worker=%s",
        rule_id, level, agent_id, agent_name, description, len(body_bytes), WORKER_ID,
    )

    record = {
        "ts": time.time(),
        "rule_id": rule_id,
        "level": level,
        "agent_id": agent_id,
        "agent_name": agent_name,
        "description": description,
        "alert_timestamp": ts_alert,
        "worker_id": WORKER_ID,
    }

    # 3) Formatear (dedup + template + default)
    try:
        message, meta = await format_alert(alert)
    except Exception as e:
        log.exception("format_error rule=%s agent=%s err=%s", rule_id, agent_id, e)
        record["decision"] = "format_error"
        record["error"] = str(e)
        _record_recent(record)
        raise HTTPException(status_code=500, detail="format error")

    record["decision"] = meta.get("decision", "?")

    # 4) Dedupe -> no se manda nada
    if not message:
        log.info(
            "alert_deduped rule=%s agent=%s decision=%s dentro_de_TTL=%ss",
            rule_id, agent_id, meta.get("decision"), settings.relay_dedup_ttl,
        )
        record["result"] = "deduped"
        _record_recent(record)
        return JSONResponse(status_code=200, content={"status": "deduped", "meta": meta})

    # 5) Template matched? Logueamos que plantilla uso
    log.info(
        "alert_formatted rule=%s agent=%s decision=%s msg_len=%d",
        rule_id, agent_id, meta.get("decision"), len(message),
    )
    record["msg_len"] = len(message)
    record["msg_preview"] = message[:160]

    # 6) Enviar a WAHA
    try:
        wa_resp = await waha_client.send_text(message)
    except waha_client.WAHAError as e:
        log.exception("waha_send_failed rule=%s agent=%s err=%s", rule_id, agent_id, e)
        record["result"] = "waha_error"
        record["error"] = str(e)
        _record_recent(record)
        raise HTTPException(status_code=502, detail=f"waha error: {e}")

    elapsed_ms = int((time.time() - t_start) * 1000)
    msg_id = wa_resp.get("id", {}).get("id") if isinstance(wa_resp, dict) else None
    log.info(
        "alert_sent rule=%s agent=%s decision=%s waha_id=%s total_ms=%d worker=%s",
        rule_id, agent_id, meta.get("decision"), msg_id, elapsed_ms, WORKER_ID,
    )
    record["result"] = "sent"
    record["waha_id"] = msg_id
    record["total_ms"] = elapsed_ms
    _record_recent(record)

    return {
        "status": "sent",
        "message_id": msg_id,
        "worker_id": WORKER_ID,
        "meta": {**meta, "total_ms": elapsed_ms},
    }
