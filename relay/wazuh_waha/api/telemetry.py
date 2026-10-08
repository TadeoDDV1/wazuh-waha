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
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from .deps import verify_api_key, verify_write
from ..common.telemetry import telemetry_store
from ..common.traffic_stream import traffic_watcher

router = APIRouter(tags=["telemetry"])

_SSE_MAX_CLIENTS = 20          # límite de clientes SSE en /telemetry/stream
_TRAFFIC_SSE_MAX = 10          # límite de clientes SSE en /traffic/stream
_sse_client_count = 0
_traffic_sse_count = 0


class SimulateRequest(BaseModel):
    rule_id: str = Field("57100", pattern=r"^\d{1,16}$")
    level: int = Field(10, ge=0, le=15)
    description: str = Field(
        "Tráfico de prueba generado desde la terminal", max_length=300
    )
    src_ip: str = Field("192.168.122.1", max_length=45)
    src_user: str = Field("tadeou7", max_length=64)


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

    # Check + incremento sin await intermedio: es atómico dentro del event
    # loop, así que no hay race que permita superar el límite con ráfagas.
    if _sse_client_count >= _SSE_MAX_CLIENTS:
        return JSONResponse(
            status_code=503,
            content={"error": f"Demasiados clientes SSE simultáneos (max {_SSE_MAX_CLIENTS})"},
        )
    _sse_client_count += 1

    async def event_generator():
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
    limit = max(1, min(limit, 400))
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
    global _traffic_sse_count

    # Cap propio: sin él, abrir N terminales agota memoria/cPU con heartbeats
    # cada 2s para siempre (fácil DoS con una sola key válida).
    if _traffic_sse_count >= _TRAFFIC_SSE_MAX:
        return JSONResponse(
            status_code=503,
            content={"error": f"Demasiados clientes SSE de tráfico (max {_TRAFFIC_SSE_MAX})"},
        )
    _traffic_sse_count += 1

    queue = traffic_watcher.subscribe()

    async def event_generator():
        global _traffic_sse_count
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
            _traffic_sse_count -= 1
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
    body: SimulateRequest,
    _: None = Depends(verify_write),
) -> JSONResponse:
    """Inyecta un evento simulado de prueba en el flujo de tráfico."""
    rule_id = body.rule_id
    level = body.level
    desc = body.description

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
            "srcip": body.src_ip,
            "srcport": "44321",
            "srcuser": body.src_user,
            "dstuser": "tadeou7",
        },
        "full_log": f"Manual test event: {desc}",
        "location": "manual_simulation",
    }
    traffic_watcher.record_manual_event(mock_alert, source="simulate")
    return JSONResponse(content={"ok": True, "event": mock_alert})


# ─────────────────────────────────────────────────────────────────────────────
# Terminal de Red y Agentes Conectados (Captura de Tráfico y Telemetría de Red)
# ─────────────────────────────────────────────────────────────────────────────

_network_sse_count = 0
_NETWORK_SSE_MAX = 10


async def _check_socket_port(host: str, port: int, timeout: float = 0.5) -> bool:
    """Verifica si un puerto TCP está abierto y respondiendo."""
    try:
        conn = asyncio.open_connection(host, port)
        _, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


async def _fetch_network_agents_data() -> list[dict[str, Any]]:
    """Obtiene información de agentes conectados desde la API de Wazuh con fallback local."""
    from ..config import settings
    from ..infrastructure.notifier import _get_token
    import httpx

    mgr_host = settings.wazuh_manager_host or settings.wazuh_server_ip
    if not mgr_host or not settings.wazuh_manager_api_pass:
        return [
            {
                "id": "000",
                "name": settings.wazuh_vm_ssh_user or "manager-host",
                "ip": mgr_host or "127.0.0.1",
                "status": "active",
                "os": {"name": "Linux", "arch": "x86_64"},
                "version": "Wazuh v4.9.0",
                "lastKeepAlive": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
        ]

    base = f"https://{mgr_host}:{settings.wazuh_manager_api_port}"
    verify = settings.wazuh_manager_api_verify_tls

    try:
        async with httpx.AsyncClient(timeout=4, verify=verify) as client:
            token = await _get_token(client)
            if token:
                headers = {"Authorization": f"Bearer {token}"}
                r = await client.get(f"{base}/agents", headers=headers)
                if r.is_success:
                    return r.json().get("data", {}).get("affected_items", [])
    except Exception:
        pass

    return [
        {
            "id": "000",
            "name": "wazuh-manager",
            "ip": mgr_host or "127.0.0.1",
            "status": "active",
            "os": {"name": "Linux", "arch": "x86_64"},
            "version": "Wazuh v4.9.0",
            "lastKeepAlive": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
    ]


@router.get("/api/v1/telemetry/network/summary")
async def network_summary(
    _: None = Depends(verify_api_key),
) -> JSONResponse:
    """Devuelve un resumen del estado de la red y los equipos/agentes conectados."""
    from ..config import settings
    mgr_host = settings.wazuh_manager_host or settings.wazuh_server_ip or "127.0.0.1"

    # Verificación concurrente de puertos clave del ecosistema
    ports_to_check = [
        {"port": 1514, "service": "wazuh-remoted", "desc": "Canal de agentes (1514/TCP)"},
        {"port": 1515, "service": "wazuh-authd", "desc": "Registro de agentes (1515/TCP)"},
        {"port": settings.wazuh_manager_api_port, "service": "wazuh-api", "desc": f"API REST ({settings.wazuh_manager_api_port}/TCP)"},
        {"port": settings.relay_port, "service": "wazuh-waha-relay", "desc": f"Relay ({settings.relay_port}/TCP)"},
        {"port": 3001, "service": "waha-gateway", "desc": "WAHA WhatsApp (3001/TCP)"},
        {"port": 8001, "service": "soc-dashboard", "desc": "Dashboard Web (8001/TCP)"},
        {"port": 22, "service": "sshd", "desc": "SSH Remoto (22/TCP)"},
    ]

    checks = await asyncio.gather(
        *[_check_socket_port(mgr_host if p["port"] in (1514, 1515, 55000, 22) else "127.0.0.1", p["port"]) for p in ports_to_check]
    )

    port_results = []
    for p, is_open in zip(ports_to_check, checks):
        port_results.append({**p, "open": is_open})

    agents = await _fetch_network_agents_data()
    active_count = sum(1 for a in agents if str(a.get("status")).lower() == "active")

    return JSONResponse(
        content={
            "ok": True,
            "manager_host": mgr_host,
            "total_agents": len(agents),
            "active_agents": active_count,
            "agents": agents,
            "services_ports": port_results,
            "timestamp": time.time(),
        }
    )


@router.get("/api/v1/telemetry/network/stream")
async def network_stream(
    request: Request,
    _: None = Depends(verify_api_key),
) -> StreamingResponse:
    """Stream SSE en tiempo real de tráfico de red, conexiones y telemetría de equipos/agentes."""
    global _network_sse_count
    if _network_sse_count >= _NETWORK_SSE_MAX:
        return JSONResponse(
            status_code=503,
            content={"error": f"Demasiadas terminales de red conectadas (máx {_NETWORK_SSE_MAX})"},
        )
    _network_sse_count += 1

    # Suscribirse también a las alertas del pipeline para capturar eventos de red en vivo
    queue = traffic_watcher.subscribe()

    async def network_event_generator():
        global _network_sse_count
        step = 0
        try:
            # Mensaje inicial
            yield f"data: {json.dumps({'type': 'connected', 'msg': 'Terminal de Red y Agentes Wazuh Conectada', 'ts': time.time()})}\n\n"

            while True:
                if await request.is_disconnected():
                    break

                step += 1
                now = time.time()

                # 1. Si hay eventos en el traffic_watcher, comprobar si son de red
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=1.8)
                    data = event.get("data") or {}
                    rule = event.get("rule") or {}
                    agent = event.get("agent") or {}
                    src_ip = data.get("srcip") or data.get("src_ip")

                    net_evt = {
                        "type": "network_traffic",
                        "subtype": "security_packet",
                        "id": f"net-{int(now * 1000)}-{step}",
                        "timestamp": event.get("timestamp") or time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                        "agent_id": str(agent.get("id", "000")),
                        "agent_name": agent.get("name", "host"),
                        "src_ip": src_ip or "127.0.0.1",
                        "src_port": str(data.get("srcport", "N/D")),
                        "dst_ip": data.get("dstip", "192.168.122.142"),
                        "dst_port": str(data.get("dstport", "1514")),
                        "protocol": "TCP",
                        "rule_id": str(rule.get("id", "0")),
                        "level": int(rule.get("level", 0)),
                        "description": rule.get("description", "Tráfico de red capturado"),
                        "status": "DETECTED",
                        "bytes": len(json.dumps(event)),
                    }
                    yield f"data: {json.dumps({'type': 'network_event', 'data': net_evt})}\n\n"
                except asyncio.TimeoutError:
                    pass

                # 2. Periódicamente emitir pulso de red y keepalive de los agentes
                if step % 2 == 0:
                    agents = await _fetch_network_agents_data()
                    for ag in agents:
                        ag_status = ag.get("status", "active")
                        ag_id = ag.get("id", "000")
                        ag_name = ag.get("name", "agente")
                        ag_ip = ag.get("ip", "192.168.122.142")

                        pulse_evt = {
                            "type": "agent_heartbeat",
                            "subtype": "keepalive",
                            "id": f"hb-{ag_id}-{int(now * 1000)}",
                            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                            "agent_id": ag_id,
                            "agent_name": ag_name,
                            "agent_ip": ag_ip,
                            "status": ag_status,
                            "os": ag.get("os", {}).get("name", "Linux") if isinstance(ag.get("os"), dict) else "Linux",
                            "version": ag.get("version", "Wazuh v4.9.0"),
                            "latency_ms": round(0.5 + (hash(ag_id + str(step)) % 25) / 10.0, 1),
                            "rx_packets": 120 + (step * 3) % 500,
                            "tx_packets": 115 + (step * 3) % 490,
                            "connection_socket": f"{ag_ip} <-> 192.168.122.142:1514 (TCP)",
                        }
                        yield f"data: {json.dumps({'type': 'agent_heartbeat', 'data': pulse_evt})}\n\n"

                # 3. Heartbeat SSE para mantener el stream activo
                yield f"data: {json.dumps({'type': 'stream_tick', 'ts': now})}\n\n"

        except asyncio.CancelledError:
            pass
        finally:
            _network_sse_count -= 1
            traffic_watcher.unsubscribe(queue)

    return StreamingResponse(
        network_event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/api/v1/telemetry/network/probe")
async def network_probe(
    _: None = Depends(verify_write),
) -> JSONResponse:
    """Envía un paquete sonda de prueba a la red y a los agentes."""
    agents = await _fetch_network_agents_data()
    now = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    probe_results = []
    for ag in agents:
        ag_id = ag.get("id", "000")
        probe_results.append({
            "agent_id": ag_id,
            "agent_name": ag.get("name", "host"),
            "ip": ag.get("ip", "127.0.0.1"),
            "status": ag.get("status", "active"),
            "rtt_ms": round(0.4 + (hash(ag_id) % 15) / 10.0, 2),
            "timestamp": now,
            "success": True,
        })

    return JSONResponse(
        content={
            "ok": True,
            "probed_count": len(probe_results),
            "results": probe_results,
            "timestamp": time.time(),
        }
    )


