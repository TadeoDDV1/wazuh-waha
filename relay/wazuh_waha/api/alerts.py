import json
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from ..common.backup import save_alert_backup
from ..common.context import WORKER_ID, record_recent
from ..common.logging import log
from ..common.telemetry import telemetry_store
from ..common.traffic_stream import traffic_watcher
from ..config import settings
from ..domain.pipeline import format_alert
from ..infrastructure import waha_client
from ..infrastructure.notifier import notify_alert_email
from ..infrastructure.telegram_bot import telegram_bot
from .deps import verify_api_key


def _finish_record(record: dict, raw_alert: dict | None = None) -> None:
    record_recent(record)
    save_alert_backup(record, raw_alert=raw_alert)



router = APIRouter(tags=["alerts"])


@router.post("/alerts")
async def receive_alert(request: Request, _: None = Depends(verify_api_key)):
    t_start = time.time()

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

    # Difundir evento al stream de tráfico en vivo (journal + SSE)
    try:
        traffic_watcher.record_manual_event(alert, source="relay")
    except Exception as _tw_err:
        log.debug("Error registrando alerta en traffic_watcher: %s", _tw_err)

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

    try:
        message, meta = await format_alert(alert)
    except Exception as e:
        log.exception("format_error rule=%s agent=%s err=%s", rule_id, agent_id, e)
        record["decision"] = "format_error"
        record["error"] = str(e)
        _finish_record(record, alert)
        # ── telemetría ──
        import asyncio
        asyncio.create_task(telemetry_store.record(
            rule_id=rule_id, level=level,
            agent_id=agent_id, agent_name=agent_name,
            description=description, decision="format_error",
            alert_timestamp=ts_alert,
        ))
        raise HTTPException(status_code=500, detail="format error")

    record["decision"] = meta.get("decision", "?")

    if not message:
        log.info(
            "alert_deduped rule=%s agent=%s decision=%s dentro_de_TTL=%ss",
            rule_id, agent_id, meta.get("decision"), settings.relay_dedup_ttl,
        )
        record["result"] = "deduped"
        _finish_record(record, alert)
        # ── telemetría ──
        import asyncio
        asyncio.create_task(telemetry_store.record(
            rule_id=rule_id, level=level,
            agent_id=agent_id, agent_name=agent_name,
            description=description, decision="deduped",
            alert_timestamp=ts_alert,
        ))
        return JSONResponse(status_code=200, content={"status": "deduped", "meta": meta})

    log.info(
        "alert_formatted rule=%s agent=%s decision=%s msg_len=%d",
        rule_id, agent_id, meta.get("decision"), len(message),
    )
    record["msg_len"] = len(message)
    record["msg_preview"] = message[:160]

    import asyncio

    channels_sent: list[str] = []
    channels_errors: list[str] = []
    msg_id: str | None = None

    # 1. Despacho por Telegram (si está habilitado)
    if getattr(settings, "telegram_enabled", False):
        try:
            asyncio.create_task(telegram_bot.send_alert(
                message_text=message,
                level=level,
                rule_id=rule_id,
                agent_name=agent_name,
            ))
            channels_sent.append("telegram")
        except Exception as _tg_err:
            log.warning("telegram_dispatch_err err=%s", _tg_err)
            channels_errors.append(f"telegram: {_tg_err}")

    # 2. Despacho por Correo Electrónico (si está habilitado)
    if getattr(settings, "email_alerts_enabled", False) and settings.admin_email:
        try:
            subject = f"🚨 [Wazuh Alerta Nivel {level}] {agent_name} - Regla #{rule_id}"
            asyncio.create_task(notify_alert_email(
                subject=subject,
                message=message,
                rule_id=rule_id,
                level=level,
                agent_name=agent_name,
            ))
            channels_sent.append("email")
        except Exception as _em_err:
            log.warning("email_dispatch_err err=%s", _em_err)
            channels_errors.append(f"email: {_em_err}")

    # 3. Despacho por WhatsApp (si está habilitado)
    if getattr(settings, "whatsapp_enabled", True):
        try:
            wa_resp = await waha_client.send_text(message)
            msg_id = wa_resp.get("id", {}).get("id") if isinstance(wa_resp, dict) else None
            channels_sent.append("whatsapp")
        except waha_client.WAHAError as e:
            log.exception("waha_send_failed rule=%s agent=%s err=%s", rule_id, agent_id, e)
            channels_errors.append(f"whatsapp: {e}")
            # Si solo estaba activo WhatsApp (o ninguno otro pudo procesar), reportar error 502
            if not channels_sent:
                record["result"] = "waha_error"
                record["error"] = str(e)
                _finish_record(record, alert)
                asyncio.create_task(telemetry_store.record(
                    rule_id=rule_id, level=level,
                    agent_id=agent_id, agent_name=agent_name,
                    description=description, decision="waha_error",
                    alert_timestamp=ts_alert,
                ))
                return {
                    "status": "error",
                    "reason": "waha_unavailable",
                    "detail": f"WhatsApp gateway no disponible o sesión no iniciada: {e}",
                    "rule_id": rule_id,
                }

    # Si ningún canal está habilitado en configuración
    if not channels_sent and not getattr(settings, "whatsapp_enabled", True):
        log.info("alert_ignored_all_channels_disabled rule=%s agent=%s", rule_id, agent_id)
        record["result"] = "no_channels_enabled"
        _finish_record(record, alert)
        return {
            "status": "ignored",
            "reason": "no_channels_enabled",
            "message": "Ningún canal de notificación activo (WhatsApp/Telegram/Email desactivados)",
            "meta": meta,
        }

    elapsed_ms = int((time.time() - t_start) * 1000)
    log.info(
        "alert_sent rule=%s agent=%s decision=%s channels=%s total_ms=%d worker=%s",
        rule_id, agent_id, meta.get("decision"), ",".join(channels_sent), elapsed_ms, WORKER_ID,
    )
    record["result"] = "sent"
    record["channels"] = channels_sent
    record["waha_id"] = msg_id
    record["total_ms"] = elapsed_ms
    _finish_record(record, alert)

    # ── telemetría ──
    asyncio.create_task(telemetry_store.record(
        rule_id=rule_id, level=level,
        agent_id=agent_id, agent_name=agent_name,
        description=description, decision="sent",
        latency_ms=float(elapsed_ms),
        alert_timestamp=ts_alert,
    ))

    return {
        "status": "sent",
        "channels": channels_sent,
        "message_id": msg_id,
        "worker_id": WORKER_ID,
        "meta": {**meta, "total_ms": elapsed_ms, "channels": channels_sent},
    }

