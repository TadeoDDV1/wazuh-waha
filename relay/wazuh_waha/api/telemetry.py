"""
Router de telemetría en vivo.

Endpoints:
  GET /api/v1/telemetry/stream   — Server-Sent Events, push cada ~1s
  GET /api/v1/telemetry/snapshot — JSON snapshot instantáneo
  GET /api/v1/telemetry/live     — Alias de snapshot para polling
"""

import asyncio
import json
import time

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, StreamingResponse

from .deps import verify_api_key
from ..common.telemetry import telemetry_store
from ..common.traffic_stream import traffic_watcher

router = APIRouter(tags=["telemetry"])

_SSE_MAX_CLIENTS = 20          # límite de clientes SSE simultáneos
_sse_client_count = 0


@router.get("/api/v1/telemetry/snapshot")
async def telemetry_snapshot(_: None = Depends(verify_api_key)) -> JSONResponse:
    """Snapshot instantáneo de todas las métricas de tráfico del relay."""
    data = await telemetry_store.snapshot()
    return JSONResponse(content=data)


@router.get("/api/v1/telemetry/live")
async def telemetry_live(_: None = Depends(verify_api_key)) -> JSONResponse:
    """Alias de /snapshot — útil para polling fallback desde el frontend."""
    data = await telemetry_store.snapshot()
    return JSONResponse(content=data)


@router.get("/api/v1/telemetry/stream")
async def telemetry_stream(
    request: Request,
    _: None = Depends(verify_api_key),
):
    """
    Server-Sent Events: emite el snapshot completo cada vez que llega una alerta
    nueva, o como mínimo una vez por segundo (heartbeat).

    Cabeceras del evento:
      X-Worker-Id — PID del worker que atiende la conexión (informativo)
    """
    global _sse_client_count

    import os
    worker_id = os.getpid()

    if _sse_client_count >= _SSE_MAX_CLIENTS:
        return JSONResponse(
            status_code=503,
            content={"error": f"Demasiados clientes SSE simultáneos (max {_SSE_MAX_CLIENTS})"},
        )

    async def event_generator():
        global _sse_client_count
        _sse_client_count += 1
        try:
            # Evento inicial inmediato
            data = await telemetry_store.snapshot()
            yield f"data: {json.dumps(data)}\n\n"

            while True:
                # Verificar si el cliente desconectó
                if await request.is_disconnected():
                    break

                # Esperar nueva alerta o timeout de heartbeat
                await telemetry_store.wait_for_update(timeout=1.5)

                if await request.is_disconnected():
                    break

                data = await telemetry_store.snapshot()
                payload = json.dumps(data)
                yield f"data: {payload}\n\n"

        except asyncio.CancelledError:
            pass
        finally:
            _sse_client_count -= 1

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",       # desactiva buffer de Nginx
            "X-Worker-Id": str(worker_id),
        },
    )


@router.get("/api/v1/telemetry/traffic/tail")
async def traffic_tail(
    limit: int = 100,
    _: None = Depends(verify_api_key),
) -> JSONResponse:
    """Devuelve los últimos eventos capturados de Wazuh para poblar la terminal al abrirla."""
    items = traffic_watcher.get_recent(limit=limit)
    return JSONResponse(content={"items": items, "count": len(items)})


@router.get("/api/v1/telemetry/traffic/source")
async def traffic_source(_: None = Depends(verify_api_key)) -> JSONResponse:
    """Información de la fuente de tráfico activa (local/ssh/api/off)."""
    return JSONResponse(content=traffic_watcher.get_source_info())


@router.get("/api/v1/telemetry/traffic/stream")
async def traffic_stream(
    request: Request,
    _: None = Depends(verify_api_key),
):
    """
    Server-Sent Events: emite cada nuevo evento de tráfico o alerta capturado por Wazuh
    en tiempo real para la terminal interactiva del dashboard.
    """
    queue = traffic_watcher.subscribe()

    async def event_generator():
        try:
            # Enviar primer mensaje de conexión confirmada
            yield f"data: {json.dumps({'type': 'connected', 'msg': 'Wazuh live traffic stream conectado'})}\n\n"

            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=2.0)
                    yield f"data: {json.dumps({'type': 'event', 'data': event})}\n\n"
                except asyncio.TimeoutError:
                    # Heartbeat para mantener viva la conexión SSE a través de Nginx/proxies
                    yield f"data: {json.dumps({'type': 'heartbeat', 'ts': time.time()})}\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            traffic_watcher.unsubscribe(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/api/v1/telemetry/traffic/simulate")
async def traffic_simulate(
    request: Request,
    _: None = Depends(verify_api_key),
) -> JSONResponse:
    """Inyecta un evento simulado de prueba en el flujo de tráfico."""
    try:
        body = await request.json()
    except Exception:
        body = {}
    rule_id = str(body.get("rule_id", "57100"))
    level = int(body.get("level", 10))
    desc = body.get("description", "Tráfico de prueba generado desde la terminal")

    mock_alert = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000+0000", time.gmtime()),
        "rule": {
            "id": rule_id,
            "level": level,
            "description": desc,
            "mitre": {"id": ["T1078"], "technique": ["Valid Accounts"]},
        },
        "agent": {"id": "001", "name": "greenalgorithm"},
        "data": {
            "srcip": body.get("src_ip", "192.168.122.1"),
            "srcport": "44321",
            "srcuser": body.get("src_user", "tadeou7"),
            "dstuser": "tadeou7",
        },
        "full_log": f"Manual test event: {desc}",
        "location": "manual_simulation",
    }
    traffic_watcher.record_manual_event(mock_alert, source="simulate")
    return JSONResponse(content={"ok": True, "event": mock_alert})

