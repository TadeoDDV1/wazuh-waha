"""
Router de telemetría en vivo.

Endpoints:
  GET /api/v1/telemetry/stream   — Server-Sent Events, push cada ~1s
  GET /api/v1/telemetry/snapshot — JSON snapshot instantáneo
  GET /api/v1/telemetry/live     — Alias de snapshot para polling
"""

import asyncio
import json
import os
import socket
import sqlite3
import time
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from .deps import verify_api_key, verify_write
from ..common.logging import log
from ..common.network_bus import network_bus
from ..common.telemetry import telemetry_store
from ..common.traffic_stream import traffic_watcher
from ..config import settings
from ..infrastructure.wazuh_api import wazuh_api
from ..domain.templates import (
    _translate_description_es,
    _format_level_es,
    translate_full_log_es,
    extract_clean_ip,
)

router = APIRouter(tags=["telemetry"])

_SSE_MAX_CLIENTS = 20          # límite de clientes SSE en /telemetry/stream
_TRAFFIC_SSE_MAX = 10          # límite de clientes SSE en /traffic/stream
_NETWORK_SSE_MAX = 20          # límite de clientes SSE en /network/stream
_sse_client_count = 0
_traffic_sse_count = 0
_network_sse_count = 0


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
        global _sse_client_count
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

async def _resolve_ip_hostname(ip: str) -> str:
    """Resuelve el hostname/dominio usando la caché DNS compartida."""
    from ..common.dns_cache import resolve

    return await resolve(ip)


# Buffer en memoria de sitios visitados recientemente (ventana de retención: 30 min)
_SITES_HISTORY_CACHE: dict[str, dict[str, Any]] = {}
_SITES_CACHE_TTL = 1800  # 30 minutos de retención

_POPULAR_DOMAINS_MAP: dict[str, tuple[str, str, str, str]] = {}
_LAST_DOMAINS_SYNC: float = 0.0

POPULAR_DOMAINS_DEF = [
    ("youtube.com", "YouTube (Streaming de Video)", "web", "video"),
    ("www.youtube.com", "YouTube (Streaming de Video)", "web", "video"),
    ("googlevideo.com", "YouTube Video Stream (Google CDN)", "web", "video"),
    ("m.youtube.com", "YouTube Móvil / Web", "web", "video"),
    ("google.com", "Google (Búsqueda & Web)", "web", "globe"),
    ("www.google.com", "Google (Búsqueda & Web)", "web", "globe"),
    ("web.whatsapp.com", "WhatsApp Web (Chat)", "messaging", "message-square"),
    ("whatsapp.com", "WhatsApp (Mensajería)", "messaging", "message-square"),
    ("facebook.com", "Facebook (Red Social)", "messaging", "globe"),
    ("instagram.com", "Instagram (Red Social)", "messaging", "globe"),
    ("telegram.org", "Telegram Messenger", "messaging", "message-square"),
    ("netflix.com", "Netflix (Streaming)", "web", "video"),
    ("spotify.com", "Spotify (Streaming Música)", "web", "globe"),
    ("github.com", "GitHub (Código & Repos)", "web", "globe"),
    ("x.com", "X / Twitter (Red Social)", "web", "globe"),
    ("twitter.com", "Twitter (Red Social)", "web", "globe"),
    ("tiktok.com", "TikTok (Videos Cortos)", "web", "video"),
    ("discord.com", "Discord (Chat & Voz)", "messaging", "message-square"),
    ("reddit.com", "Reddit (Comunidad)", "web", "globe"),
    ("chatgpt.com", "ChatGPT / OpenAI", "web", "globe"),
    ("openai.com", "OpenAI (IA)", "web", "globe"),
    ("twitch.tv", "Twitch (Streaming en Vivo)", "web", "video"),
    ("amazon.com", "Amazon (Compras / AWS)", "web", "globe"),
    ("wikipedia.org", "Wikipedia (Enciclopedia)", "web", "globe"),
]


def _sync_popular_domains_ips():
    """Resuelve hacia adelante las IPs de dominios populares conocidos en caché."""
    global _LAST_DOMAINS_SYNC
    now = time.time()
    if now - _LAST_DOMAINS_SYNC < 1800 and _POPULAR_DOMAINS_MAP:
        return
    _LAST_DOMAINS_SYNC = now
    for dom, name, cat, icon in POPULAR_DOMAINS_DEF:
        try:
            res = socket.getaddrinfo(dom, 443)
            for r in res:
                ip_addr = r[4][0]
                _POPULAR_DOMAINS_MAP[ip_addr] = (name, dom, cat, icon)
        except Exception:
            pass


def _classify_network_site(ip: str, port: int, hostname: str = "", process: str = "") -> dict[str, Any]:
    """Clasifica un destino de red en un sitio web, servicio conocido y categoría en español."""
    ip = str(ip or "").replace("::ffff:", "").strip()
    port = int(port or 0)
    h = str(hostname or "").lower()
    proc = str(process or "").lower()

    # 1. Wazuh Remoted / Authd (Agentes conectando a canal seguro de Wazuh)
    # IMPORTANTE: Verificar por puertos/procesos específicos ANTES de filtros generales
    if port in (1514, 1515) or proc in ("wazuh-agentd", "wazuh-remoted", "wazuh-authd"):
        return {
            "site_name": "Wazuh Manager SOC (Canal Agentes)",
            "domain": "wazuh-manager.local",
            "category": "sync",
            "category_label": "Sincronización Wazuh Remoted (1514)",
            "is_web": False,
            "icon": "shield",
        }

    # 2. Wazuh REST API (Puerto 55000)
    if port == 55000 or "wazuh-apid" in proc:
        return {
            "site_name": "Wazuh Manager REST API",
            "domain": "wazuh-api.local",
            "category": "sync",
            "category_label": "API REST Wazuh (55000/HTTPS)",
            "is_web": True,
            "icon": "shield",
        }

    # 3. SOC Dashboard Web (Puerto 8001)
    if port == 8001 or "dashboard" in proc:
        return {
            "site_name": "Panel SOC Dashboard Web",
            "domain": "soc-dashboard.local",
            "category": "web",
            "category_label": "Panel SOC Dashboard (8001/HTTP)",
            "is_web": True,
            "icon": "globe",
        }

    # 4. WAHA WhatsApp Gateway (Puerto 3001)
    if port == 3001 or "waha" in proc:
        return {
            "site_name": "WAHA WhatsApp API Gateway",
            "domain": "waha.local",
            "category": "messaging",
            "category_label": "Gateway WAHA WhatsApp (3001)",
            "is_web": True,
            "icon": "message-square",
        }

    # 5. SSH (Puerto 22)
    if port == 22 or proc in ("ssh", "sshd"):
        dom = h or ip
        return {
            "site_name": f"Terminal Remota SSH ({dom})",
            "domain": dom,
            "category": "ssh",
            "category_label": "Acceso Remoto SSH (22)",
            "is_web": False,
            "icon": "terminal",
        }

    # 5.1 Coincidencia exacta con dominios populares pre-resueltos
    if ip in _POPULAR_DOMAINS_MAP:
        p_name, p_dom, p_cat, p_icon = _POPULAR_DOMAINS_MAP[ip]
        lbl = (
            "Video Streaming & Navegación (YouTube)" if "YouTube" in p_name
            else "Navegación / Servicios Web" if p_cat == "web"
            else f"Mensajería & Redes ({p_name})" if p_cat == "messaging"
            else p_name
        )
        return {
            "site_name": p_name,
            "domain": p_dom,
            "category": p_cat,
            "category_label": lbl,
            "is_web": True,
            "icon": p_icon,
        }

    # 6. YouTube (Streaming de Video)
    # Detecta YouTube por hostname, subredes de CDN de YouTube de Google o procesos de navegador conectando a streaming
    is_yt_subnet = (
        ip.startswith((
            "142.251.150.", "142.251.151.", "142.251.152.", "142.251.153.",
            "142.251.154.", "142.251.155.", "142.251.156.", "142.251.157.",
            "192.178.56.", "192.178.164.", "172.217.112.", "172.217.113.",
            "172.217.116.", "172.217.117."
        ))
    )
    is_yt_host = any(k in h for k in ("youtube", "googlevideo", "ytimg", "youtu.be"))
    is_browser = proc in ("chrome", "firefox", "brave", "edge", "opera", "chromium", "curl")

    if is_yt_host or (is_yt_subnet and (is_browser or port in (443, 80))):
        clean_yt_dom = h if ("youtube" in h or "googlevideo" in h) else "youtube.com"
        return {
            "site_name": "YouTube (Streaming de Video)",
            "domain": clean_yt_dom,
            "category": "web",
            "category_label": "Video Streaming & Navegación (YouTube)",
            "is_web": True,
            "icon": "video",
        }

    is_google_ip = (
        ip.startswith(("142.250.", "142.251.", "172.217.", "172.253.", "192.178.", "216.58.", "74.125.", "64.233.", "173.194."))
        or any(k in h for k in ("1e100.net", "google", "gstatic"))
    )

    if is_google_ip and any(k in h for k in ("video", "youtube", "play")):
        clean_yt_dom = h if ("youtube" in h or "googlevideo" in h) else "youtube.com"
        return {
            "site_name": "YouTube (Streaming de Video)",
            "domain": clean_yt_dom,
            "category": "web",
            "category_label": "Video Streaming & Navegación (YouTube)",
            "is_web": True,
            "icon": "video",
        }

    # 7. Google Servicios / Búsqueda / Cloud
    if is_google_ip or ip in ("8.8.8.8", "8.8.4.4") or ip.startswith("34.54."):
        if port == 53 or ip in ("8.8.8.8", "8.8.4.4"):
            return {
                "site_name": "Google Public DNS",
                "domain": "dns.google",
                "category": "dns",
                "category_label": "Servidor DNS (Google 8.8.8.8)",
                "is_web": False,
                "icon": "globe",
            }
        if port == 5228:
            return {
                "site_name": "Google Cloud / Chrome Push Services",
                "domain": "google.com",
                "category": "web",
                "category_label": "Servicios Cloud / Push (Google)",
                "is_web": True,
                "icon": "globe",
            }
        clean_g_dom = h if (h and not h.replace('.', '').isdigit() and "1e100" not in h) else "google.com"
        return {
            "site_name": "Google (Búsqueda & Web)",
            "domain": clean_g_dom,
            "category": "web",
            "category_label": "Navegación / Servicios Web (Google)",
            "is_web": True,
            "icon": "globe",
        }

    # 8. WhatsApp / Meta / Facebook / Instagram
    if any(k in h for k in ("whatsapp", "fbcdn", "facebook", "instagram")) or ip.startswith(("157.240.", "31.13.", "179.60.", "185.89.")):
        plat = "WhatsApp" if "whatsapp" in h else "Instagram" if "instagram" in h else "Facebook / Meta"
        return {
            "site_name": f"{plat} (Red Social / Chat)",
            "domain": h if h else "whatsapp.net",
            "category": "messaging",
            "category_label": f"Mensajería & Redes ({plat})",
            "is_web": True,
            "icon": "message-square",
        }

    # 9. Telegram Messenger
    if "telegram" in h or ip.startswith(("149.154.", "91.108.")):
        return {
            "site_name": "Telegram Messenger",
            "domain": "telegram.org",
            "category": "messaging",
            "category_label": "Mensajería (Telegram API/Web)",
            "is_web": True,
            "icon": "message-square",
        }

    # 10. Cloudflare CDN / DNS
    if "cloudflare" in h or ip in ("1.1.1.1", "1.0.0.1") or ip.startswith(("104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "104.22.", "104.23.", "104.24.", "104.25.", "104.26.", "104.27.", "104.28.", "172.64.", "172.65.", "172.66.", "172.67.", "162.159.")):
        if port == 53 or ip in ("1.1.1.1", "1.0.0.1"):
            return {
                "site_name": "Cloudflare 1.1.1.1 DNS",
                "domain": "one.one.one.one",
                "category": "dns",
                "category_label": "Servidor DNS Seguro (Cloudflare)",
                "is_web": False,
                "icon": "globe",
            }
        return {
            "site_name": "Cloudflare CDN / Red Web",
            "domain": h if (h and "cloudflare" not in h) else "cloudflare.com",
            "category": "web",
            "category_label": "Aceleración / CDN Web (Cloudflare)",
            "is_web": True,
            "icon": "globe",
        }

    # 11. OpenAI / ChatGPT
    if any(k in h for k in ("openai", "chatgpt", "oaistatic")) or ip.startswith("104.18.32."):
        return {
            "site_name": "OpenAI / ChatGPT",
            "domain": "chatgpt.com",
            "category": "web",
            "category_label": "Inteligencia Artificial (OpenAI)",
            "is_web": True,
            "icon": "globe",
        }

    # 12. GitHub
    if "github" in h or ip.startswith(("140.82.", "185.199.", "20.201.", "20.205.")):
        return {
            "site_name": "GitHub (Repositorios & Código)",
            "domain": "github.com",
            "category": "web",
            "category_label": "Repositorios de Código (GitHub)",
            "is_web": True,
            "icon": "globe",
        }

    # 13. Microsoft / Azure
    if any(k in h for k in ("microsoft", "azure", "windows", "bing", "live.com", "office.com")) or ip.startswith(("20.", "40.", "52.", "13.")):
        return {
            "site_name": "Microsoft / Azure Cloud",
            "domain": h if h else "microsoft.com",
            "category": "web",
            "category_label": "Servicios Microsoft / Azure",
            "is_web": True,
            "icon": "globe",
        }

    # 14. Amazon / AWS
    if any(k in h for k in ("amazonaws", "amazon", "cloudfront")) or ip.startswith(("54.", "3.", "18.", "35.", "44.", "99.84.", "99.86.")):
        return {
            "site_name": "Amazon Web Services (AWS)",
            "domain": h if h else "amazonaws.com",
            "category": "web",
            "category_label": "Servicios Nube (AWS/Cloudfront)",
            "is_web": True,
            "icon": "globe",
        }

    # 15. Wikipedia / Redes y Plataformas Populares
    if any(k in h for k in ("wikimedia", "wikipedia")):
        return {
            "site_name": "Wikipedia (Enciclopedia Libre)",
            "domain": "wikipedia.org",
            "category": "web",
            "category_label": "Portal Web (Wikipedia)",
            "is_web": True,
            "icon": "globe",
        }
    if any(k in h for k in ("netflix", "nflxvideo")):
        return {
            "site_name": "Netflix (Streaming)",
            "domain": "netflix.com",
            "category": "web",
            "category_label": "Streaming de Video (Netflix)",
            "is_web": True,
            "icon": "video",
        }
    if any(k in h for k in ("twitter", "twimg", "x.com")) or ip.startswith("104.244."):
        return {
            "site_name": "X / Twitter",
            "domain": "x.com",
            "category": "web",
            "category_label": "Red Social (X / Twitter)",
            "is_web": True,
            "icon": "globe",
        }
    if any(k in h for k in ("spotify", "scdn.co")):
        return {
            "site_name": "Spotify (Streaming de Música)",
            "domain": "spotify.com",
            "category": "web",
            "category_label": "Música / Streaming (Spotify)",
            "is_web": True,
            "icon": "globe",
        }
    if any(k in h for k in ("reddit", "redd.it")):
        return {
            "site_name": "Reddit",
            "domain": "reddit.com",
            "category": "web",
            "category_label": "Comunidad Web (Reddit)",
            "is_web": True,
            "icon": "globe",
        }

    # 16. Repositorios Linux (Arch Linux, Ubuntu, Debian, Kali)
    if any(k in h for k in ("archlinux", "ubuntu", "debian", "canonical", "kali.org")):
        return {
            "site_name": "Repositorios de Actualización Linux",
            "domain": h if h else "repositorio-linux.org",
            "category": "update",
            "category_label": "Actualizaciones del Sistema (Linux)",
            "is_web": True,
            "icon": "server",
        }

    # 17. Bases de Datos
    if port in (3306, 5432, 6379, 27017) or proc in ("mariadbd", "postgres", "redis-server", "mongod"):
        db_name = "MySQL/MariaDB" if port == 3306 or "maria" in proc else "PostgreSQL" if port == 5432 or "postgre" in proc else "Redis" if port == 6379 else "Base de Datos"
        return {
            "site_name": f"Servidor {db_name}",
            "domain": h or ip,
            "category": "database",
            "category_label": f"Base de Datos {db_name} ({port})",
            "is_web": False,
            "icon": "database",
        }

    # 18. DNS genérico
    if port == 53 or "systemd-resolved" in proc:
        dom = h or ip
        return {
            "site_name": f"Servidor DNS ({dom})",
            "domain": dom,
            "category": "dns",
            "category_label": "Resolución de Nombres DNS (53)",
            "is_web": False,
            "icon": "globe",
        }

    # 19. Red Local WiFi / LAN
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16.") or ip.startswith("172.44."):
        return {
            "site_name": f"Equipo Red Local WiFi ({ip})",
            "domain": h or ip,
            "category": "lan",
            "category_label": f"Dispositivo Red WiFi/LAN ({ip}:{port})",
            "is_web": port in (80, 443, 8080, 8443),
            "icon": "wifi",
        }

    # 20. Web genérico HTTPS / HTTP
    if port == 443:
        dom = h if (h and not h.replace('.', '').isdigit()) else ip
        site_title = f"Sitio Web Seguro ({dom})" if dom != ip else f"Sitio Web HTTPS ({ip})"
        return {
            "site_name": site_title,
            "domain": dom,
            "category": "web",
            "category_label": "Navegación Web Segura (443/HTTPS)",
            "is_web": True,
            "icon": "globe",
        }
    elif port in (80, 8080, 8443):
        dom = h if (h and not h.replace('.', '').isdigit()) else ip
        site_title = f"Sitio Web ({dom})" if dom != ip else f"Sitio Web HTTP ({ip})"
        return {
            "site_name": site_title,
            "domain": dom,
            "category": "web",
            "category_label": f"Navegación Web ({port}/HTTP)",
            "is_web": True,
            "icon": "globe",
        }

    # 21. Localhost
    if ip in ("127.0.0.1", "::1", "localhost"):
        return {
            "site_name": "Servicio Interno (Localhost)",
            "domain": "localhost",
            "category": "local",
            "category_label": f"Servicio Local Interno ({port})",
            "is_web": False,
            "icon": "server",
        }

    dom = h or ip or "desconocido"
    return {
        "site_name": f"Destino de Red ({dom})",
        "domain": dom,
        "category": "service",
        "category_label": f"Servicio de Red ({port}/TCP)",
        "is_web": False,
        "icon": "server",
    }


async def _get_local_host_sockets() -> list[dict[str, Any]]:
    """Obtiene sockets reales en vivo del host manager (Agente 000) de manera no bloqueante."""
    sockets = []
    try:
        proc = await asyncio.create_subprocess_exec(
            "ss", "-tupn",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=1.0)
        lines = stdout.decode("utf-8", errors="ignore").splitlines()
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 5:
                proto = parts[0].upper()
                st = parts[1].lower()
                loc = parts[4]
                rem = parts[5] if len(parts) > 5 else "-:-"

                proc_name = "sistema"
                pid_num = None
                if len(parts) >= 7:
                    rest = parts[6]
                    if '("' in rest:
                        try:
                            proc_name = rest.split('("')[1].split('"')[0]
                        except Exception:
                            pass
                    if 'pid=' in rest:
                        try:
                            pid_num = int(rest.split("pid=")[1].split(",")[0].split(")")[0])
                        except Exception:
                            pass

                def parse_addr(addr_str: str):
                    if "]:" in addr_str:
                        p = addr_str.split("]:")
                        return p[0].replace("[", "").replace("::ffff:", ""), int(p[1]) if p[1].isdigit() else 0
                    elif ":" in addr_str:
                        p = addr_str.rsplit(":", 1)
                        return p[0].replace("::ffff:", ""), int(p[1]) if p[1].isdigit() else 0
                    return addr_str.replace("::ffff:", ""), 0

                loc_ip, loc_port = parse_addr(loc)
                rem_ip, rem_port = parse_addr(rem)

                sockets.append({
                    "protocol": proto,
                    "local_ip": loc_ip,
                    "local_port": loc_port,
                    "remote_ip": rem_ip,
                    "remote_port": rem_port,
                    "process": proc_name,
                    "pid": pid_num,
                    "state": st,
                    "tx_packets": 0,
                    "rx_packets": 0,
                })
    except Exception:
        pass
    return sockets


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


def _read_agents_from_global_db() -> list[dict[str, Any]]:
    """Lee el catálogo de agentes directamente de /var/ossec/queue/db/global.db como fallback ultra-rápido."""
    db_path = "/var/ossec/queue/db/global.db"
    if not os.path.exists(db_path):
        return []
    try:
        uri = f"file:{db_path}?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=1.5) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, name, ip, register_ip, os_name, os_version, os_platform, os_arch, version, last_keepalive, connection_status FROM agent ORDER BY id ASC"
            )
            items = []
            for r in cursor.fetchall():
                aid = str(r["id"]).zfill(3)
                lka = r["last_keepalive"]
                try:
                    lka_str = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(lka)) if lka and lka < 2000000000 else "-"
                except Exception:
                    lka_str = "-"
                items.append({
                    "id": aid,
                    "name": r["name"] or f"agent-{aid}",
                    "ip": r["ip"] or r["register_ip"] or "127.0.0.1",
                    "status": r["connection_status"] or "active",
                    "os": {
                        "name": r["os_name"] or "Linux",
                        "platform": r["os_platform"] or "linux",
                        "version": r["os_version"] or "",
                        "arch": r["os_arch"] or "x86_64",
                    },
                    "version": r["version"] or "Wazuh v4.x",
                    "lastKeepAlive": lka_str,
                })
            return items
    except Exception as e:
        log.debug("read_agents_global_db_failed err=%s", e)
        return []


async def _fetch_network_agents_data() -> list[dict[str, Any]]:
    """Obtiene información de agentes conectados desde la API de Wazuh con fallback a global.db."""
    from ..config import settings
    from ..infrastructure.notifier import _get_token
    import httpx

    mgr_host = settings.wazuh_manager_host or settings.wazuh_server_ip
    if mgr_host and settings.wazuh_manager_api_pass:
        base = f"https://{mgr_host}:{settings.wazuh_manager_api_port}"
        verify = settings.wazuh_manager_api_verify_tls

        try:
            async with httpx.AsyncClient(timeout=10, verify=verify) as client:
                token = await _get_token(client)
                if token:
                    headers = {"Authorization": f"Bearer {token}"}
                    r = await client.get(f"{base}/agents?limit=100", headers=headers)
                    if r.is_success:
                        items = r.json().get("data", {}).get("affected_items", [])
                        if items:
                            return items
        except Exception as e:
            log.debug("fetch_network_agents_api_err err=%s", e)

    # Fallback 1: SQLite local directo (siempre actualizado y sin timeouts)
    local_agents = _read_agents_from_global_db()
    if local_agents:
        return local_agents

    # Fallback 2: Entrada básica del manager
    return [
        {
            "id": "000",
            "name": settings.wazuh_vm_ssh_user or "wazuh-manager",
            "ip": mgr_host or "127.0.0.1",
            "status": "active",
            "os": {"name": "Linux", "arch": "x86_64"},
            "version": "Wazuh v4.x",
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


def _get_agent_wazuh_alerts(agent_id: str = "all", max_items: int = 40) -> list[dict[str, Any]]:
    """Extrae alertas de Wazuh para un agente específico desde alerts.json o telemetría reciente."""
    alerts = []
    path = "/var/ossec/logs/alerts/alerts.json"

    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()[-2000:]
                for line in reversed(lines):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        al = json.loads(line)
                        ag = al.get("agent", {}) or {}
                        ag_id_str = str(ag.get("id", ""))
                        if agent_id == "all" or ag_id_str == str(agent_id):
                            rule = al.get("rule", {}) or {}
                            lvl = int(rule.get("level", 0))
                            desc = rule.get("description", "Evento de seguridad")
                            raw_log = al.get("full_log") or ""
                            rule_id_str = str(rule.get("id", "0"))
                            src_ip_str = data.get("srcip") or data.get("src_ip", "")
                            user_str = data.get("dstuser") or data.get("dst_user", "")
                            if rule_id_str in ("57100", "57101") and src_ip_str in ("192.168.122.1", "127.0.0.1") and user_str in ("tadeou7", "wazuh", "soc"):
                                continue

                            alerts.append({
                                "id": str(al.get("id", "")),
                                "timestamp": al.get("timestamp", ""),
                                "rule_id": rule_id_str,
                                "level": lvl,
                                "level_es": _format_level_es(lvl),
                                "description": _translate_description_es(desc),
                                "agent_id": ag_id_str,
                                "agent_name": ag.get("name", "host"),
                                "srcip": src_ip_str,
                                "srcport": str(data.get("srcport", "")),
                                "dstuser": user_str,
                                "full_log": raw_log[:240],
                                "full_log_es": translate_full_log_es(raw_log)[:240],
                            })
                            if len(alerts) >= max_items:
                                break
                    except Exception:
                        pass
        except Exception:
            pass

    # Complementar con journal y memoria de tráfico en vivo
    if len(alerts) < max_items:
        recent = traffic_watcher.get_recent(limit=max_items * 3)
        for al in reversed(recent):
            ag_id_str = str(al.get("agent_id") or (al.get("agent", {}) or {}).get("id", ""))
            if agent_id == "all" or ag_id_str == str(agent_id):
                al_id = str(al.get("id", ""))
                if any(x.get("id") == al_id for x in alerts if al_id):
                    continue
                rule_id = str(al.get("rule_id") or (al.get("rule", {}) or {}).get("id", "0"))
                try:
                    lvl = int(al.get("level") or (al.get("rule", {}) or {}).get("level", 0))
                except (ValueError, TypeError):
                    lvl = 0
                desc = al.get("description") or (al.get("rule", {}) or {}).get("description", "Evento de seguridad")
                raw_log = al.get("full_log") or ""
                src_ip = al.get("src_ip") or (al.get("data", {}) or {}).get("srcip", "")
                if not src_ip and raw_log:
                    src_ip = extract_clean_ip(al)
                dst_user = al.get("dst_user") or (al.get("data", {}) or {}).get("dstuser", "")

                # Omitir logins de monitoreo del relay para no distorsionar el reporte
                if rule_id in ("57100", "57101") and src_ip in ("192.168.122.1", "127.0.0.1") and dst_user in ("tadeou7", "wazuh", "soc"):
                    continue

                alerts.append({
                    "id": al_id or f"mem-{len(alerts)}",
                    "timestamp": al.get("timestamp", ""),
                    "rule_id": rule_id,
                    "level": lvl,
                    "level_es": _format_level_es(lvl),
                    "description": _translate_description_es(desc),
                    "agent_id": ag_id_str,
                    "agent_name": al.get("agent_name") or (al.get("agent", {}) or {}).get("name", "host"),
                    "srcip": src_ip if not src_ip.startswith("No identificada") else "",
                    "srcport": str(al.get("src_port") or (al.get("data", {}) or {}).get("srcport", "")),
                    "dstuser": dst_user,
                    "full_log": raw_log[:240],
                    "full_log_es": translate_full_log_es(raw_log)[:240],
                })
                if len(alerts) >= max_items:
                    break

    return alerts


_AGENT_TRAFFIC_CACHE: dict[str, tuple[dict[str, Any], float]] = {}
_AGENT_TRAFFIC_CACHE_TTL = 6.0  # 6 segundos de caché para deduplicar llamadas del dashboard


async def _read_agent_queue_db_remote(
    aid: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Lee la DB de syscollector del manager por SSH (cuando el relay no es el manager)."""
    from ..infrastructure.ssh_pool import ssh_pool, SSHError

    if not ssh_pool.configured:
        return [], [], []
    db_path = f"/var/ossec/queue/db/{aid}.db"
    try:
        raw_ports = await ssh_pool.read_sqlite_json(
            db_path,
            "SELECT protocol, local_ip, local_port, remote_ip, remote_port, process, PID as pid, state, tx_queue, rx_queue, scan_time FROM sys_ports",
        )
        raw_ifaces = await ssh_pool.read_sqlite_json(
            db_path,
            "SELECT name, adapter, type, state, mtu, mac, tx_packets, rx_packets, tx_bytes, rx_bytes, tx_errors, rx_errors, tx_dropped, rx_dropped, scan_time FROM sys_netiface",
        )
        raw_procs = await ssh_pool.read_sqlite_json(
            db_path,
            "SELECT PID as pid, name, cmd, euser, state FROM sys_processes LIMIT 200",
        )
    except (SSHError, Exception) as exc:
        log.debug("read_agent_queue_db_remote_failed aid=%s err=%s", aid, exc)
        return [], [], []

    ports = []
    for r in raw_ports:
        ports.append({
            "protocol": (r.get("protocol") or "tcp").upper(),
            "local": {"ip": r.get("local_ip"), "port": r.get("local_port")},
            "remote": {"ip": r.get("remote_ip"), "port": r.get("remote_port")},
            "local_ip": r.get("local_ip"),
            "local_port": r.get("local_port"),
            "remote_ip": r.get("remote_ip"),
            "remote_port": r.get("remote_port"),
            "process": r.get("process") or "sistema",
            "pid": r.get("pid"),
            "state": r.get("state") or "listening",
            "tx": {"packets": r.get("tx_queue") or 0},
            "rx": {"packets": r.get("rx_queue") or 0},
            "scan_time": r.get("scan_time"),
            "_agent_id": aid,
        })
    ifaces = []
    for r in raw_ifaces:
        ifaces.append({
            "name": r.get("name") or "eth0",
            "state": str(r.get("state") or "down").lower(),
            "mac": r.get("mac") or "-",
            "mtu": r.get("mtu") or 1500,
            "type": r.get("type") or "ethernet",
            "tx": {
                "bytes": r.get("tx_bytes") or 0,
                "packets": r.get("tx_packets") or 0,
                "errors": r.get("tx_errors") or 0,
                "drops": r.get("tx_dropped") or 0,
            },
            "rx": {
                "bytes": r.get("rx_bytes") or 0,
                "packets": r.get("rx_packets") or 0,
                "errors": r.get("rx_errors") or 0,
                "drops": r.get("rx_dropped") or 0,
            },
            "tx_bytes": r.get("tx_bytes") or 0,
            "rx_bytes": r.get("rx_bytes") or 0,
            "scan_time": r.get("scan_time"),
            "_agent_id": aid,
        })
    procs = []
    for r in raw_procs:
        procs.append({
            "pid": r.get("pid") or 0,
            "name": r.get("name") or "proceso",
            "cmd": r.get("cmd") or "",
            "euser": r.get("euser") or "root",
            "state": r.get("state") or "running",
            "_agent_id": aid,
        })
    return ports, ifaces, procs


async def _fetch_netaddr_map(agents: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Devuelve IPv4/IPv6 por agente desde syscollector netaddr (API) o DB remota."""
    from ..infrastructure.ssh_pool import ssh_pool

    out: dict[str, list[dict[str, Any]]] = {}
    for ag in agents:
        aid = str(ag.get("id", ""))
        if not aid:
            continue
        rows: list[dict[str, Any]] = []
        try:
            data = await wazuh_api.affected_items(
                f"/syscollector/{aid}/netaddr?limit=200", timeout=10
            )
            for r in data:
                rows.append({
                    "iface": r.get("iface") or r.get("interface") or "",
                    "address": r.get("address") or "",
                    "proto": r.get("proto") or "",
                    "netmask": r.get("netmask") or "",
                })
        except Exception:
            pass
        if not rows and ssh_pool.configured:
            try:
                raw = await ssh_pool.read_sqlite_json(
                    f"/var/ossec/queue/db/{aid}.db",
                    "SELECT iface, proto, address, netmask FROM sys_netaddr",
                )
                rows = [
                    {"iface": r.get("iface"), "address": r.get("address"),
                     "proto": r.get("proto"), "netmask": r.get("netmask")}
                    for r in raw
                ]
            except Exception:
                pass
        out[aid] = rows
    return out


def _read_agent_queue_db(aid: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Lee syscollector (sockets, interfaces y procesos) directamente de /var/ossec/queue/db/{aid}.db.
    Es de ultra-baja latencia (<2ms), en modo solo lectura (mode=ro) y evita completamente bloqueos
    de SQLite o timeouts 500 (error 3021) en la API REST de Wazuh."""
    db_path = f"/var/ossec/queue/db/{aid}.db"
    if not os.path.exists(db_path):
        return [], [], []

    raw_ports: list[dict[str, Any]] = []
    raw_ifaces: list[dict[str, Any]] = []
    raw_procs: list[dict[str, Any]] = []

    try:
        uri = f"file:{db_path}?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=1.5) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # 1. Sockets y puertos
            try:
                cursor.execute(
                    "SELECT protocol, local_ip, local_port, remote_ip, remote_port, process, PID as pid, state, tx_queue, rx_queue, scan_time FROM sys_ports"
                )
                for r in cursor.fetchall():
                    raw_ports.append({
                        "protocol": (r["protocol"] or "tcp").upper(),
                        "local": {"ip": r["local_ip"], "port": r["local_port"]},
                        "remote": {"ip": r["remote_ip"], "port": r["remote_port"]},
                        "local_ip": r["local_ip"],
                        "local_port": r["local_port"],
                        "remote_ip": r["remote_ip"],
                        "remote_port": r["remote_port"],
                        "process": r["process"] or "sistema",
                        "pid": r["pid"],
                        "state": r["state"] or "listening",
                        "tx": {"packets": r["tx_queue"] or 0},
                        "rx": {"packets": r["rx_queue"] or 0},
                        "scan_time": r["scan_time"] if "scan_time" in r.keys() else None,
                        "_agent_id": aid,
                    })
            except Exception:
                pass

            # 2. Interfaces de Red
            try:
                cursor.execute(
                    "SELECT name, adapter, type, state, mtu, mac, tx_packets, rx_packets, tx_bytes, rx_bytes, tx_errors, rx_errors, tx_dropped, rx_dropped, scan_time FROM sys_netiface"
                )
                for r in cursor.fetchall():
                    raw_ifaces.append({
                        "name": r["name"] or "eth0",
                        "state": str(r["state"] or "down").lower(),
                        "mac": r["mac"] or "-",
                        "mtu": r["mtu"] or 1500,
                        "type": r["type"] or "ethernet",
                        "tx": {
                            "bytes": r["tx_bytes"] or 0,
                            "packets": r["tx_packets"] or 0,
                            "errors": r["tx_errors"] or 0,
                            "drops": r["tx_dropped"] or 0,
                        },
                        "rx": {
                            "bytes": r["rx_bytes"] or 0,
                            "packets": r["rx_packets"] or 0,
                            "errors": r["rx_errors"] or 0,
                            "drops": r["rx_dropped"] or 0,
                        },
                        "tx_bytes": r["tx_bytes"] or 0,
                        "rx_bytes": r["rx_bytes"] or 0,
                        "scan_time": r["scan_time"] if "scan_time" in r.keys() else None,
                        "_agent_id": aid,
                    })
            except Exception:
                pass

            # 3. Procesos
            try:
                cursor.execute(
                    "SELECT PID as pid, name, cmd, euser, state FROM sys_processes LIMIT 200"
                )
                for r in cursor.fetchall():
                    raw_procs.append({
                        "pid": r["pid"] or 0,
                        "name": r["name"] or "proceso",
                        "cmd": r["cmd"] or "",
                        "euser": r["euser"] or "root",
                        "state": r["state"] or "running",
                        "_agent_id": aid,
                    })
            except Exception:
                pass
    except Exception:
        pass

    return raw_ports, raw_ifaces, raw_procs


async def _fetch_agent_traffic_details(agent_id: str) -> dict[str, Any]:
    """Obtiene sockets activos enriquecidos con sitios web, interfaces, procesos y alertas."""
    agent_id_str = str(agent_id).strip()

    # Comprobar caché en memoria para evitar saturación ante múltiples llamadas simultáneas
    now_t = time.time()
    if agent_id_str in _AGENT_TRAFFIC_CACHE:
        cached_val, cached_ts = _AGENT_TRAFFIC_CACHE[agent_id_str]
        if now_t - cached_ts < _AGENT_TRAFFIC_CACHE_TTL:
            return cached_val

    from ..config import settings
    from ..infrastructure.notifier import _get_token
    import httpx

    mgr_host = settings.wazuh_manager_host or settings.wazuh_server_ip
    base = f"https://{mgr_host}:{settings.wazuh_manager_api_port}"
    verify = settings.wazuh_manager_api_verify_tls

    all_agents = await _fetch_network_agents_data()

    # Determinar qué agentes consultar
    if agent_id_str == "all":
        target_agents = all_agents
        agent_info = None
    else:
        target_agents = [a for a in all_agents if str(a.get("id")) == agent_id_str]
        if not target_agents:
            target_agents = [{"id": agent_id_str, "name": f"agente-{agent_id_str}", "ip": "127.0.0.1"}]
        agent_info = target_agents[0]

    all_raw_ports: list[dict[str, Any]] = []
    all_raw_ifaces: list[dict[str, Any]] = []
    all_raw_procs: list[dict[str, Any]] = []

    # 1. DB local (si el relay corre en el manager) o DB remota por SSH.
    remaining_agents_to_api: list[dict[str, Any]] = []
    netaddr_map = await _fetch_netaddr_map(target_agents)
    for ag in target_agents:
        aid = str(ag.get("id", "000"))
        ag_name = ag.get("name", "host")
        ag_ip = ag.get("ip", "127.0.0.1")

        p_list, i_list, pr_list = _read_agent_queue_db(aid)
        if not (p_list or i_list or pr_list):
            p_list, i_list, pr_list = await _read_agent_queue_db_remote(aid)
        if p_list or i_list or pr_list:
            for p in p_list:
                p["_agent_name"] = ag_name
                p["_agent_ip"] = ag_ip
            for i in i_list:
                i["_agent_name"] = ag_name
                i["_agent_ip"] = ag_ip
                i["_netaddr"] = netaddr_map.get(aid, [])
            for pr in pr_list:
                pr["_agent_name"] = ag_name

            all_raw_ports.extend(p_list)
            all_raw_ifaces.extend(i_list)
            all_raw_procs.extend(pr_list)
        else:
            remaining_agents_to_api.append(ag)

    # 2. Si algún agente no tiene archivo DB local, consultar API REST de forma secuencial segura
    if remaining_agents_to_api and mgr_host and settings.wazuh_manager_api_pass:
        try:
            async with httpx.AsyncClient(timeout=10.0, verify=verify) as client:
                token = await _get_token(client)
                if token:
                    headers = {"Authorization": f"Bearer {token}"}
                    for ag_dict in remaining_agents_to_api:
                        aid = str(ag_dict.get("id", "000"))
                        ag_name = ag_dict.get("name", "host")
                        ag_ip = ag_dict.get("ip", "127.0.0.1")

                        async def safe_fetch(path: str) -> list[dict[str, Any]]:
                            try:
                                r = await client.get(f"{base}{path}", headers=headers, timeout=8.0)
                                if r.is_success:
                                    return r.json().get("data", {}).get("affected_items", [])
                            except Exception:
                                pass
                            return []

                        raw_p = await safe_fetch(f"/syscollector/{aid}/ports?limit=500")
                        for p in raw_p:
                            p["_agent_id"] = aid
                            p["_agent_name"] = ag_name
                            p["_agent_ip"] = ag_ip
                        all_raw_ports.extend(raw_p)

                        raw_i = await safe_fetch(f"/syscollector/{aid}/netiface")
                        for iface in raw_i:
                            iface["_agent_id"] = aid
                            iface["_agent_name"] = ag_name
                        all_raw_ifaces.extend(raw_i)

                        raw_pr = await safe_fetch(f"/syscollector/{aid}/processes?limit=100")
                        for pr in raw_pr:
                            pr["_agent_id"] = aid
                        all_raw_procs.extend(raw_pr)
        except Exception:
            pass

    # Normalizar sockets y clasificar sitios/destinos
    normalized_ports: list[dict[str, Any]] = []
    unique_remote_ips = set()

    def _direction(state: str, local_port: int, remote_port: int) -> str:
        st = (state or "").lower()
        rp = int(remote_port or 0)
        lp = int(local_port or 0)
        if rp == 0:
            return "listen"
        if "listen" in st and rp == 0:
            return "listen"
        if lp < 32768 <= rp:
            return "inbound"
        if rp < 32768 <= lp:
            return "outbound"
        return "connection"

    for p in all_raw_ports:
        loc = p.get("local") if isinstance(p.get("local"), dict) else {}
        rem = p.get("remote") if isinstance(p.get("remote"), dict) else {}

        proto = (p.get("protocol") or "tcp").upper()
        raw_loc = loc.get("ip") or p.get("local_ip") or "0.0.0.0"
        loc_ip = str(raw_loc).replace("::ffff:", "").strip()
        loc_port = loc.get("port") if loc.get("port") is not None else p.get("local_port", 0)

        raw_rem = rem.get("ip") or p.get("remote_ip") or "-"
        rem_ip = str(raw_rem).replace("::ffff:", "").strip()
        rem_port = rem.get("port") if rem.get("port") is not None else p.get("remote_port", 0)

        proc_name = p.get("process") or p.get("program_name") or "sistema"
        pid_val = p.get("pid")
        st = str(p.get("state") or "listening").lower()
        aid = p.get("_agent_id") or "000"
        aname = p.get("_agent_name") or "host"
        aip = p.get("_agent_ip") or loc_ip

        if rem_ip and rem_ip not in ("-", "0.0.0.0", "::", "::0", "127.0.0.1", "::1", "localhost") and not rem_ip.startswith("127."):
            unique_remote_ips.add(rem_ip)

        normalized_ports.append({
            "protocol": proto,
            "local_ip": loc_ip,
            "local_port": loc_port,
            "remote_ip": rem_ip,
            "remote_port": rem_port,
            "process": proc_name,
            "pid": pid_val,
            "state": st,
            "agent_id": aid,
            "agent_name": aname,
            "agent_ip": aip,
            "direction": _direction(str(p.get("state") or ""), int(loc_port or 0), int(rem_port or 0)),
            "scan_time": p.get("scan_time") or (p.get("scan") or {}).get("time") or "",
            "tx_packets": p.get("tx", {}).get("packets", 0) if isinstance(p.get("tx"), dict) else 0,
            "rx_packets": p.get("rx", {}).get("packets", 0) if isinstance(p.get("rx"), dict) else 0,
        })

    # Resolución concurrente de hostnames para las IPs remotas
    ip_to_host: dict[str, str] = {}
    if unique_remote_ips:
        lookups = await asyncio.gather(*[_resolve_ip_hostname(ip) for ip in unique_remote_ips], return_exceptions=True)
        for ip, host_res in zip(unique_remote_ips, lookups):
            ip_to_host[ip] = str(host_res) if isinstance(host_res, str) else ""

    # Enriquecer cada socket con la clasificación del sitio/servicio
    sites_activity: list[dict[str, Any]] = []
    seen_sites = set()

    for sock in normalized_ports:
        rem_ip = sock["remote_ip"]
        rem_port = sock["remote_port"]
        hostname = ip_to_host.get(rem_ip, "")
        proc = sock["process"]

        classification = _classify_network_site(
            ip=rem_ip,
            port=rem_port,
            hostname=hostname,
            process=proc,
        )

        sock["remote_hostname"] = hostname
        sock["site_name"] = classification["site_name"]
        sock["domain"] = classification["domain"]
        sock["category"] = classification["category"]
        sock["category_label"] = classification["category_label"]
        sock["is_web"] = classification["is_web"]
        sock["icon"] = classification["icon"]

        # Filtrar sockets locales o sin destino: solo destinos remotos reales entran en Sitios Web & Destinos
        is_loopback = (
            rem_ip in ("-", "0.0.0.0", "::", "::0", "127.0.0.1", "::1", "localhost")
            or rem_ip.startswith("127.")
            or classification["category"] == "local"
        )
        if not is_loopback and rem_port > 0:
            site_key = f"{sock['agent_id']}:{classification['domain']}:{rem_port}:{sock['protocol']}"
            is_estab = (
                "estab" in sock["state"]
                or "syn" in sock["state"]
                or (sock["protocol"] == "UDP" and rem_port in (443, 80, 53))
            )
            state_lbl = "CONEXIÓN ACTIVA" if is_estab else "EN ESPERA" if "wait" in sock["state"] else sock["state"].upper()

            rec = {
                "site_name": classification["site_name"],
                "domain": classification["domain"],
                "remote_ip": rem_ip,
                "remote_port": rem_port,
                "protocol": sock["protocol"],
                "process": proc,
                "pid": sock["pid"],
                "category": classification["category"],
                "category_label": classification["category_label"],
                "is_web": classification["is_web"],
                "state": sock["state"],
                "state_label": state_lbl,
                "agent_id": sock["agent_id"],
                "agent_name": sock["agent_name"],
                "agent_ip": sock.get("agent_ip", ""),
                "direction": sock.get("direction", "unknown"),
                "scan_time": sock.get("scan_time", ""),
                "last_seen": time.strftime("%H:%M:%S"),
                "_ts": time.time(),
            }

            # Guardar en caché histórico para persistencia de sesión
            _SITES_HISTORY_CACHE[site_key] = rec

            if site_key not in seen_sites:
                seen_sites.add(site_key)
                sites_activity.append(rec)

    # Incorporar sitios históricos recientemente visitados (retención de sesión de 30 min)
    now_ts = time.time()
    for s_key, hist_rec in list(_SITES_HISTORY_CACHE.items()):
        if now_ts - hist_rec.get("_ts", 0) > _SITES_CACHE_TTL:
            _SITES_HISTORY_CACHE.pop(s_key, None)
            continue

        if s_key not in seen_sites:
            if agent_id_str == "all" or hist_rec.get("agent_id") == agent_id_str:
                recent_copy = dict(hist_rec)
                recent_copy["state"] = "recent"
                recent_copy["state_label"] = "RECIENTE"
                sites_activity.append(recent_copy)
                seen_sites.add(s_key)

    # Ordenar: conexiones activas primero, luego recientes por timestamp
    sites_activity.sort(
        key=lambda x: (
            0 if ("estab" in x.get("state", "").lower() or "activa" in x.get("state_label", "").lower()) else 1,
            -x.get("_ts", 0),
        )
    )

    # Normalizar interfaces
    normalized_ifaces = []
    total_rx_b = 0
    total_tx_b = 0
    for i in all_raw_ifaces:
        rx_b = i.get("rx", {}).get("bytes", 0) if isinstance(i.get("rx"), dict) else 0
        tx_b = i.get("tx", {}).get("bytes", 0) if isinstance(i.get("tx"), dict) else 0
        total_rx_b += rx_b
        total_tx_b += tx_b
        iface_name = i.get("name") or "eth0"
        netaddrs = i.get("_netaddr") or []
        ipv4_addrs = [
            a.get("address") for a in netaddrs
            if str(a.get("proto", "")).lower() == "ipv4" and a.get("address")
            and (not a.get("iface") or a.get("iface") == iface_name)
        ]
        ipv6_addrs = [
            a.get("address") for a in netaddrs
            if str(a.get("proto", "")).lower() == "ipv6" and a.get("address")
            and (not a.get("iface") or a.get("iface") == iface_name)
        ]
        legacy_ipv4 = i.get("ipv4", {}).get("address", "") if isinstance(i.get("ipv4"), dict) else ""
        normalized_ifaces.append({
            "name": i.get("name") or "eth0",
            "state": str(i.get("state") or "down").lower(),
            "mac": i.get("mac") or "-",
            "mtu": i.get("mtu") or 1500,
            "type": i.get("type") or "ethernet",
            "tx_bytes": tx_b,
            "rx_bytes": rx_b,
            "tx_packets": i.get("tx", {}).get("packets", 0) if isinstance(i.get("tx"), dict) else 0,
            "rx_packets": i.get("rx", {}).get("packets", 0) if isinstance(i.get("rx"), dict) else 0,
            "tx_errors": i.get("tx", {}).get("errors", 0) if isinstance(i.get("tx"), dict) else 0,
            "rx_errors": i.get("rx", {}).get("errors", 0) if isinstance(i.get("rx"), dict) else 0,
            "tx_drops": i.get("tx", {}).get("drops", 0) if isinstance(i.get("tx"), dict) else 0,
            "rx_drops": i.get("rx", {}).get("drops", 0) if isinstance(i.get("rx"), dict) else 0,
            "ipv4": ipv4_addrs[0] if ipv4_addrs else legacy_ipv4,
            "ipv4_addresses": ipv4_addrs,
            "ipv6": ipv6_addrs[0] if ipv6_addrs else "",
            "ipv6_addresses": ipv6_addrs,
            "agent_id": i.get("_agent_id", "000"),
            "agent_name": i.get("_agent_name", "host"),
            "scan_time": i.get("scan_time") or (i.get("scan") or {}).get("time") or "",
        })

    # Normalizar procesos
    normalized_procs = []
    for pr in all_raw_procs:
        normalized_procs.append({
            "pid": pr.get("pid") or 0,
            "name": pr.get("name") or "proceso",
            "cmd": pr.get("cmd") or "",
            "euser": pr.get("euser") or "root",
            "state": pr.get("state") or "running",
            "agent_id": pr.get("_agent_id", "000"),
        })

    # Frescura de los datos de syscollector
    scan_times = [p.get("scan_time") for p in normalized_ports if p.get("scan_time")]
    scan_times += [i.get("scan_time") for i in normalized_ifaces if i.get("scan_time")]
    latest_scan = max(scan_times) if scan_times else ""
    stale = False
    if latest_scan:
        try:
            from datetime import datetime, timezone
            ts = latest_scan
            if "T" in ts:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            else:
                dt = datetime.strptime(ts, "%Y/%m/%d %H:%M:%S").replace(tzinfo=timezone.utc)
            stale = (datetime.now(timezone.utc) - dt).total_seconds() > 600
        except Exception:
            stale = False
    agent_status = (agent_info or {}).get("status", "unknown") if agent_info else "all"
    if agent_status not in ("active", "all"):
        stale = True

    # Extraer alertas Wazuh
    wazuh_alerts = _get_agent_wazuh_alerts(agent_id=agent_id_str, max_items=40)

    # Métricas y KPIs
    listening_count = sum(1 for p in normalized_ports if "listen" in p["state"])
    established_count = sum(1 for p in normalized_ports if "estab" in p["state"] or "syn" in p["state"])
    active_ifaces_count = sum(1 for i in normalized_ifaces if i["state"] == "up")
    web_sites_count = sum(1 for s in sites_activity if s.get("is_web"))

    result = {
        "ok": True,
        "agent_id": agent_id_str,
        "agent_info": agent_info,
        "agent_status": agent_status,
        "last_keep_alive": (agent_info or {}).get("lastKeepAlive", "") if agent_info else "",
        "scan_time": latest_scan,
        "stale": stale,
        "kpis": {
            "total_sockets": len(normalized_ports),
            "listening_sockets": listening_count,
            "established_connections": established_count,
            "total_sites": len(sites_activity),
            "web_sites_active": web_sites_count,
            "active_interfaces": active_ifaces_count,
            "total_rx_mb": round(total_rx_b / (1024 * 1024), 2),
            "total_tx_mb": round(total_tx_b / (1024 * 1024), 2),
            "total_wazuh_alerts": len(wazuh_alerts),
        },
        "ports": normalized_ports,
        "sites_activity": sites_activity,
        "ifaces": normalized_ifaces,
        "processes": normalized_procs,
        "wazuh_detections": wazuh_alerts,
        "timestamp": time.time(),
    }
    _AGENT_TRAFFIC_CACHE[agent_id_str] = (result, time.time())
    return result


def _get_local_hardware_fallback() -> dict[str, Any]:
    """Obtiene datos de hardware locales mediante /proc como fallback de alta disponibilidad."""
    cpu_name = "CPU Genérica"
    cores = os.cpu_count() or 1
    mhz = 2000
    try:
        with open("/proc/cpuinfo", "r") as f:
            for line in f:
                if "model name" in line:
                    cpu_name = line.split(":", 1)[1].strip()
                    break
    except Exception:
        pass

    tot_mb = 8192
    free_mb = 4096
    used_mb = 4096
    usage_pct = 50.0
    try:
        with open("/proc/meminfo", "r") as f:
            mem = {}
            for line in f:
                parts = line.split(":")
                if len(parts) == 2:
                    k = parts[0].strip()
                    v = parts[1].strip().split()[0]
                    if v.isdigit():
                        mem[k] = int(v)
            if "MemTotal" in mem:
                tot_mb = round(mem["MemTotal"] / 1024, 1)
                free_kb = mem.get("MemAvailable", mem.get("MemFree", 0))
                free_mb = round(free_kb / 1024, 1)
                used_mb = max(0, round(tot_mb - free_mb, 1))
                usage_pct = round((used_mb / tot_mb) * 100, 1) if tot_mb else 0.0
    except Exception:
        pass

    return {
        "cpu_name": cpu_name,
        "cpu_cores": cores,
        "cpu_mhz": mhz,
        "ram_total_mb": tot_mb,
        "ram_free_mb": free_mb,
        "ram_used_mb": used_mb,
        "ram_usage_percent": usage_pct,
        "board_serial": "-",
    }


_AGENT_PROFILE_CACHE: dict[str, dict[str, Any]] = {}
_AGENT_PROFILE_TTL = 45  # 45 segundos de retención para telemetría forense


async def _fetch_agent_full_profile(agent_id: str) -> dict[str, Any]:
    """Recopila la ficha forense exhaustiva de un agente: Hardware, SO, Red, SCA, FIM, Procesos y Software."""
    aid = str(agent_id).strip()
    now = time.time()

    if aid in _AGENT_PROFILE_CACHE:
        cached = _AGENT_PROFILE_CACHE[aid]
        if now - cached.get("_ts", 0) < _AGENT_PROFILE_TTL:
            return cached["data"]

    from ..config import settings
    from ..infrastructure.notifier import _get_token
    import httpx

    mgr_host = settings.wazuh_manager_host or settings.wazuh_server_ip
    base = f"https://{mgr_host}:{settings.wazuh_manager_api_port}"
    verify = settings.wazuh_manager_api_verify_tls

    traffic_data = await _fetch_agent_traffic_details(aid)
    agent_info = traffic_data.get("agent_info") or {}
    ag_name = agent_info.get("name") or f"agente-{aid}"
    ag_ip = agent_info.get("ip") or "127.0.0.1"
    ag_status = agent_info.get("status") or "active"

    hw_fallback = _get_local_hardware_fallback()

    profile: dict[str, Any] = {
        "ok": True,
        "agent_id": aid,
        "name": ag_name,
        "ip": ag_ip,
        "status": ag_status,
        "version": agent_info.get("version", "Wazuh v4.x"),
        "last_keep_alive": agent_info.get("lastKeepAlive", "-"),
        "hardware": hw_fallback,
        "os": {
            "name": agent_info.get("os", {}).get("name", "Linux") if isinstance(agent_info.get("os"), dict) else "Linux",
            "platform": agent_info.get("os", {}).get("platform", "linux") if isinstance(agent_info.get("os"), dict) else "linux",
            "version": agent_info.get("os", {}).get("version", "-") if isinstance(agent_info.get("os"), dict) else "-",
            "kernel": agent_info.get("os", {}).get("uname", "-") if isinstance(agent_info.get("os"), dict) else "-",
            "architecture": agent_info.get("os", {}).get("arch", "x86_64") if isinstance(agent_info.get("os"), dict) else "x86_64",
            "hostname": ag_name,
        },
        "network": {
            "interfaces": traffic_data.get("ifaces", []),
            "total_rx_mb": traffic_data.get("kpis", {}).get("total_rx_mb", 0.0),
            "total_tx_mb": traffic_data.get("kpis", {}).get("total_tx_mb", 0.0),
        },
        "sca": {
            "name": "Evaluación de Seguridad (CIS Benchmark)",
            "policy_id": "cis_standard",
            "score": 0,
            "pass": 0,
            "fail": 0,
            "total_checks": 0,
            "failed_checks": [],
        },
        "fim": {
            "total_monitored": 0,
            "recent_files": [],
        },
        "software": {
            "total_packages": 0,
            "sample_packages": [],
        },
        "rootcheck": {
            "total_items": 0,
            "items": [],
        },
        "ports": {
            "total_count": len(traffic_data.get("ports", [])),
            "items": traffic_data.get("ports", []),
        },
        "processes": {
            "total_count": len(traffic_data.get("processes", [])),
            "top_processes": traffic_data.get("processes", [])[:25],
        },
        "active_sites": traffic_data.get("sites_activity", []),
        "recent_detections": traffic_data.get("wazuh_detections", []),
        "timestamp": now,
    }

    if mgr_host and settings.wazuh_manager_api_pass:
        try:
            async with httpx.AsyncClient(timeout=15.0, verify=verify) as client:
                token = await _get_token(client)
                if token:
                    headers = {"Authorization": f"Bearer {token}"}

                    t_hw = client.get(f"{base}/syscollector/{aid}/hardware", headers=headers)
                    t_os = client.get(f"{base}/syscollector/{aid}/os", headers=headers)
                    t_pkg = client.get(f"{base}/syscollector/{aid}/packages?limit=25", headers=headers)
                    t_sca = client.get(f"{base}/sca/{aid}", headers=headers)
                    t_fim = client.get(f"{base}/syscheck/{aid}?limit=25", headers=headers)
                    t_root = client.get(f"{base}/rootcheck/{aid}?limit=25", headers=headers)
                    t_ports = client.get(f"{base}/syscollector/{aid}/ports?limit=50", headers=headers)
                    t_proc = client.get(f"{base}/syscollector/{aid}/processes?limit=50", headers=headers)
                    t_net = client.get(f"{base}/syscollector/{aid}/netiface", headers=headers)

                    (
                        r_hw,
                        r_os,
                        r_pkg,
                        r_sca,
                        r_fim,
                        r_root,
                        r_ports,
                        r_proc,
                        r_net,
                    ) = await asyncio.gather(
                        t_hw,
                        t_os,
                        t_pkg,
                        t_sca,
                        t_fim,
                        t_root,
                        t_ports,
                        t_proc,
                        t_net,
                        return_exceptions=True,
                    )

                    # 1. Hardware
                    if isinstance(r_hw, httpx.Response) and r_hw.is_success:
                        items = r_hw.json().get("data", {}).get("affected_items", [])
                        if items:
                            hw = items[0]
                            cpu = hw.get("cpu", {})
                            ram = hw.get("ram", {})
                            tot_kb = ram.get("total", 0)
                            free_kb = ram.get("free", 0)
                            tot_mb = round(tot_kb / 1024, 1) if tot_kb else 0
                            free_mb = round(free_kb / 1024, 1) if free_kb else 0
                            used_mb = max(0, round(tot_mb - free_mb, 1))
                            usage_pct = ram.get("usage")
                            if usage_pct is None and tot_mb > 0:
                                usage_pct = round((used_mb / tot_mb) * 100, 1)

                            profile["hardware"] = {
                                "cpu_name": cpu.get("name", hw_fallback["cpu_name"]),
                                "cpu_cores": cpu.get("cores", hw_fallback["cpu_cores"]),
                                "cpu_mhz": cpu.get("mhz", hw_fallback["cpu_mhz"]),
                                "ram_total_mb": tot_mb or hw_fallback["ram_total_mb"],
                                "ram_free_mb": free_mb or hw_fallback["ram_free_mb"],
                                "ram_used_mb": used_mb or hw_fallback["ram_used_mb"],
                                "ram_usage_percent": usage_pct if usage_pct is not None else hw_fallback["ram_usage_percent"],
                                "board_serial": hw.get("board_serial", "-"),
                            }

                    # 2. SO & Kernel
                    if isinstance(r_os, httpx.Response) and r_os.is_success:
                        items = r_os.json().get("data", {}).get("affected_items", [])
                        if items:
                            osi = items[0]
                            os_dict = osi.get("os", {})
                            profile["os"] = {
                                "name": os_dict.get("name") or osi.get("sysname", "Linux"),
                                "platform": os_dict.get("platform", "linux"),
                                "version": os_dict.get("version") or os_dict.get("build", "-"),
                                "kernel": osi.get("release", "-"),
                                "architecture": osi.get("architecture", "x86_64"),
                                "hostname": osi.get("hostname", ag_name),
                            }
                    elif isinstance(agent_info.get("os"), dict) and agent_info.get("os", {}).get("name"):
                        # Fallback robusto desde metadatos del agente
                        ag_os = agent_info["os"]
                        profile["os"] = {
                            "name": ag_os.get("name", "Linux"),
                            "platform": ag_os.get("platform", "linux"),
                            "version": ag_os.get("version", "-"),
                            "kernel": ag_os.get("uname", "-"),
                            "architecture": ag_os.get("arch", "x86_64"),
                            "hostname": ag_name,
                        }

                    # 3. Paquetes instalados (SBOM)
                    if isinstance(r_pkg, httpx.Response) and r_pkg.is_success:
                        d_pkg = r_pkg.json().get("data", {})
                        profile["software"] = {
                            "total_packages": d_pkg.get("total_affected_items", 0),
                            "sample_packages": [
                                {
                                    "name": p.get("name", ""),
                                    "version": p.get("version", ""),
                                    "vendor": p.get("vendor", ""),
                                    "description": (p.get("description") or "")[:80],
                                }
                                for p in d_pkg.get("affected_items", [])
                            ],
                        }

                    # 4. SCA CIS Benchmark
                    if isinstance(r_sca, httpx.Response) and r_sca.is_success:
                        items = r_sca.json().get("data", {}).get("affected_items", [])
                        if items:
                            sca_pol = items[0]
                            pol_id = sca_pol.get("policy_id")
                            profile["sca"] = {
                                "name": sca_pol.get("name", "CIS Benchmark"),
                                "policy_id": pol_id,
                                "score": sca_pol.get("score", 0),
                                "pass": sca_pol.get("pass", 0),
                                "fail": sca_pol.get("fail", 0),
                                "total_checks": sca_pol.get("total_checks", 0),
                                "failed_checks": [],
                            }
                            if pol_id:
                                try:
                                    r_checks = await client.get(
                                        f"{base}/sca/{aid}/checks/{pol_id}?limit=10&result=failed",
                                        headers=headers,
                                    )
                                    if r_checks.is_success:
                                        c_items = r_checks.json().get("data", {}).get("affected_items", [])
                                        profile["sca"]["failed_checks"] = [
                                            {
                                                "id": c.get("id"),
                                                "title": c.get("title", "Control fallado"),
                                                "rationale": (c.get("rationale") or "")[:140],
                                                "remediation": (c.get("remediation") or "")[:140],
                                            }
                                            for c in c_items
                                        ]
                                except Exception:
                                    pass

                    # 5. FIM Syscheck
                    if isinstance(r_fim, httpx.Response) and r_fim.is_success:
                        d_fim = r_fim.json().get("data", {})
                        profile["fim"] = {
                            "total_monitored": d_fim.get("total_affected_items", 0),
                            "recent_files": [
                                {
                                    "file": f.get("file", ""),
                                    "size": f.get("size", 0),
                                    "perm": f.get("perm", ""),
                                    "uname": f.get("uname", ""),
                                    "date": f.get("date", ""),
                                    "md5": f.get("md5", ""),
                                }
                                for f in d_fim.get("affected_items", [])
                            ],
                        }

                    # 6. Rootcheck (Detección de malware / rootkits)
                    if isinstance(r_root, httpx.Response) and r_root.is_success:
                        d_root = r_root.json().get("data", {})
                        root_items = d_root.get("affected_items", [])
                        profile["rootcheck"] = {
                            "total_items": d_root.get("total_affected_items", len(root_items)),
                            "items": [
                                {
                                    "event": rt.get("event", ""),
                                    "file": rt.get("file", ""),
                                    "status": rt.get("status", "outstanding"),
                                }
                                for rt in root_items
                            ],
                        }

                    # 7. Puertos de red y sockets activos (Syscollector)
                    if isinstance(r_ports, httpx.Response) and r_ports.is_success:
                        d_ports = r_ports.json().get("data", {})
                        p_items = d_ports.get("affected_items", [])
                        if p_items:
                            profile["ports"] = {
                                "total_count": d_ports.get("total_affected_items", len(p_items)),
                                "items": [
                                    {
                                        "protocol": p.get("protocol", "tcp"),
                                        "local_ip": p.get("local", {}).get("ip", "") if isinstance(p.get("local"), dict) else "",
                                        "local_port": p.get("local", {}).get("port", 0) if isinstance(p.get("local"), dict) else 0,
                                        "process": p.get("process", ""),
                                        "pid": p.get("pid", 0),
                                        "state": p.get("state", "listening"),
                                    }
                                    for p in p_items
                                ],
                            }

                    # 8. Procesos activos (Syscollector)
                    if isinstance(r_proc, httpx.Response) and r_proc.is_success:
                        d_proc = r_proc.json().get("data", {})
                        proc_items = d_proc.get("affected_items", [])
                        if proc_items:
                            profile["processes"] = {
                                "total_count": d_proc.get("total_affected_items", len(proc_items)),
                                "top_processes": [
                                    {
                                        "pid": pr.get("pid", 0),
                                        "name": pr.get("name", "proceso"),
                                        "cmd": pr.get("cmd", ""),
                                        "euser": pr.get("euser", "root"),
                                        "state": pr.get("state", "running"),
                                    }
                                    for pr in proc_items[:30]
                                ],
                            }

                    # 9. Interfaces de red (Syscollector)
                    if isinstance(r_net, httpx.Response) and r_net.is_success:
                        d_net = r_net.json().get("data", {})
                        net_items = d_net.get("affected_items", [])
                        if net_items:
                            profile["network"]["interfaces"] = [
                                {
                                    "name": i.get("name", ""),
                                    "type": i.get("type", "ethernet"),
                                    "state": i.get("state", "up"),
                                    "mac": i.get("mac", ""),
                                    "ipv4": i.get("ipv4", {}).get("address", "") if isinstance(i.get("ipv4"), dict) else "",
                                    "mtu": i.get("mtu", 1500),
                                }
                                for i in net_items
                            ]
        except Exception:
            pass

    # Enriquecimiento y fallbacks directos desde SQLite (/var/ossec/queue/db/{aid}.db)
    _enrich_profile_from_sqlite(profile, aid)

    _AGENT_PROFILE_CACHE[aid] = {"data": profile, "_ts": now}
    return profile


def _enrich_profile_from_sqlite(profile: dict[str, Any], aid: str) -> None:
    """Extrae datos de módulos forenses directamente desde /var/ossec/queue/db/{aid}.db."""
    db_path = f"/var/ossec/queue/db/{aid}.db"
    if not os.path.exists(db_path):
        return
    try:
        uri = f"file:{db_path}?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=1.5) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # 1. Cuentas de usuario (sys_users)
            try:
                cursor.execute("SELECT COUNT(*) FROM sys_users")
                total_users = cursor.fetchone()[0]
                cursor.execute(
                    "SELECT user_name, user_id, user_group_id, user_home, user_shell FROM sys_users ORDER BY user_id ASC LIMIT 30"
                )
                users_list = [
                    {
                        "user_name": r["user_name"],
                        "uid": r["user_id"],
                        "gid": r["user_group_id"],
                        "home": r["user_home"],
                        "shell": r["user_shell"],
                    }
                    for r in cursor.fetchall()
                ]
                profile["users"] = {
                    "total_users": total_users,
                    "sample_users": users_list,
                }
            except Exception:
                pass

            # 2. Servicios del sistema (sys_services)
            try:
                cursor.execute("SELECT COUNT(*) FROM sys_services")
                total_services = cursor.fetchone()[0]
                cursor.execute(
                    "SELECT service_name, service_description, service_state, service_enabled, service_start_type FROM sys_services ORDER BY service_name ASC LIMIT 40"
                )
                services_list = [
                    {
                        "name": r["service_name"],
                        "description": r["service_description"] or "-",
                        "state": r["service_state"] or "running",
                        "enabled": r["service_enabled"] or "-",
                        "start_type": r["service_start_type"] or "-",
                    }
                    for r in cursor.fetchall()
                ]
                profile["services"] = {
                    "total_services": total_services,
                    "sample_services": services_list,
                }
            except Exception:
                pass

            # 3. FIM fallback si API no trajo datos
            if not profile.get("fim", {}).get("total_monitored"):
                try:
                    cursor.execute("SELECT COUNT(*) FROM fim_entry")
                    total_fim = cursor.fetchone()[0]
                    cursor.execute(
                        "SELECT file, size, perm, uname, date, md5 FROM fim_entry ORDER BY rowid DESC LIMIT 25"
                    )
                    fim_files = [
                        {
                            "file": r["file"],
                            "size": r["size"] or 0,
                            "perm": r["perm"] or "-",
                            "uname": r["uname"] or "-",
                            "date": r["date"] or "-",
                            "md5": r["md5"] or "-",
                        }
                        for r in cursor.fetchall()
                    ]
                    profile["fim"] = {
                        "total_monitored": total_fim,
                        "recent_files": fim_files,
                    }
                except Exception:
                    pass

            # 4. SCA fallback si API no trajo datos
            if not profile.get("sca", {}).get("total_checks"):
                try:
                    cursor.execute("SELECT COUNT(*) FROM sca_check WHERE result='passed'")
                    pass_c = cursor.fetchone()[0]
                    cursor.execute("SELECT COUNT(*) FROM sca_check WHERE result='failed'")
                    fail_c = cursor.fetchone()[0]
                    tot = pass_c + fail_c
                    score = round((pass_c / tot * 100), 1) if tot > 0 else 0
                    cursor.execute(
                        "SELECT id, title, rationale, remediation FROM sca_check WHERE result='failed' LIMIT 15"
                    )
                    failed = [
                        {
                            "id": r["id"],
                            "title": r["title"] or "Control fallado",
                            "rationale": (r["rationale"] or "")[:140],
                            "remediation": (r["remediation"] or "")[:140],
                        }
                        for r in cursor.fetchall()
                    ]
                    profile["sca"] = {
                        "name": "CIS Benchmark (Auditoría Integral)",
                        "policy_id": "cis",
                        "score": score,
                        "pass": pass_c,
                        "fail": fail_c,
                        "total_checks": tot,
                        "failed_checks": failed,
                    }
                except Exception:
                    pass

            # 5. Software fallback si API no trajo datos
            if not profile.get("software", {}).get("total_packages"):
                try:
                    cursor.execute("SELECT COUNT(*) FROM sys_programs")
                    tot_pkg = cursor.fetchone()[0]
                    cursor.execute(
                        "SELECT name, version, vendor, description FROM sys_programs ORDER BY name ASC LIMIT 30"
                    )
                    pkgs = [
                        {
                            "name": r["name"],
                            "version": r["version"] or "-",
                            "vendor": r["vendor"] or "-",
                            "description": (r["description"] or "")[:80],
                        }
                        for r in cursor.fetchall()
                    ]
                    profile["software"] = {
                        "total_packages": tot_pkg,
                        "sample_packages": pkgs,
                    }
                except Exception:
                    pass

            # 6. Puertos fallback si no hay datos
            if not profile.get("ports", {}).get("total_count"):
                try:
                    cursor.execute("SELECT COUNT(*) FROM sys_ports")
                    tot_ports = cursor.fetchone()[0]
                    cursor.execute(
                        "SELECT protocol, local_ip, local_port, process, PID as pid, state FROM sys_ports LIMIT 50"
                    )
                    ports_items = [
                        {
                            "protocol": (r["protocol"] or "tcp").upper(),
                            "local_ip": r["local_ip"] or "",
                            "local_port": r["local_port"] or 0,
                            "process": r["process"] or "sistema",
                            "pid": r["pid"] or 0,
                            "state": r["state"] or "listening",
                        }
                        for r in cursor.fetchall()
                    ]
                    profile["ports"] = {
                        "total_count": tot_ports,
                        "items": ports_items,
                    }
                except Exception:
                    pass
    except Exception as e:
        log.debug("enrich_profile_sqlite_err aid=%s err=%s", aid, e)


@router.get("/api/v1/telemetry/agents/{agent_id}/full-profile")
async def agent_full_profile(
    agent_id: str,
    _: None = Depends(verify_api_key),
) -> JSONResponse:
    """Devuelve la ficha forense integral del agente: Hardware, SO, Red, SCA CIS, FIM, Procesos y Paquetes."""
    data = await _fetch_agent_full_profile(agent_id)
    return JSONResponse(content=data)


@router.get("/api/v1/telemetry/agents/{agent_id}/breakdown")
async def agent_module_breakdown(
    agent_id: str,
    _: None = Depends(verify_api_key),
) -> JSONResponse:
    """Devuelve el desglose módulo por módulo, regla por regla y en español de la postura del agente."""
    from ..domain.wazuh_breakdown import build_wazuh_module_breakdown
    profile = await _fetch_agent_full_profile(agent_id)
    breakdown = build_wazuh_module_breakdown(profile)
    return JSONResponse(content={"ok": True, "breakdown": breakdown})


@router.get("/api/v1/telemetry/agents/{agent_id}/traffic")
async def agent_traffic_details(
    agent_id: str,
    _: None = Depends(verify_api_key),
) -> JSONResponse:
    """Devuelve conexiones activas, sockets, sitios web visitados, interfaces y alertas Wazuh."""
    data = await _fetch_agent_traffic_details(agent_id)
    return JSONResponse(content=data)


@router.get("/api/v1/telemetry/network/sites")
async def network_sites(
    agent_id: str = "all",
    _: None = Depends(verify_api_key),
) -> JSONResponse:
    """Devuelve el inventario de sitios web, dominios y destinos visitados por los equipos."""
    details = await _fetch_agent_traffic_details(agent_id)
    sites = details.get("sites_activity", [])
    agents = await _fetch_network_agents_data()

    # Contadores por categoría
    by_category: dict[str, int] = {}
    for s in sites:
        cat = s.get("category", "otros")
        by_category[cat] = by_category.get(cat, 0) + 1

    # Construir mapa de dispositivos en la misma red WiFi/LAN
    lan_devices = []
    for ag in agents:
        aid = str(ag.get("id", "000"))
        ag_sites = [s for s in sites if s.get("agent_id") == aid]
        ag_ifaces = [i for i in details.get("ifaces", []) if i.get("agent_id") == aid]
        wifi_iface = next((i for i in ag_ifaces if "wlan" in i.get("name", "") or "wifi" in i.get("name", "")), None)
        active_iface = wifi_iface or (ag_ifaces[0] if ag_ifaces else None)

        lan_devices.append({
            "agent_id": aid,
            "agent_name": ag.get("name", "host"),
            "ip": ag.get("ip") or ag.get("registerIP") or "127.0.0.1",
            "status": str(ag.get("status", "active")),
            "os": ag.get("os", {}).get("name") if isinstance(ag.get("os"), dict) else "Linux",
            "interface_name": active_iface.get("name") if active_iface else ("wlan0" if aid == "001" else "eth0"),
            "mac": active_iface.get("mac", "-") if active_iface else "-",
            "rx_mb": round(active_iface.get("rx_bytes", 0) / (1024 * 1024), 2) if active_iface else 0.0,
            "tx_mb": round(active_iface.get("tx_bytes", 0) / (1024 * 1024), 2) if active_iface else 0.0,
            "active_sites_count": len(ag_sites),
            "synced": True,
        })

    web_count = sum(1 for s in sites if s.get("is_web"))
    active_count = sum(1 for s in sites if "estab" in s.get("state", "").lower() or "activa" in s.get("state_label", "").lower())

    return JSONResponse(
        content={
            "ok": True,
            "agent_id": agent_id,
            "total_sites": len(sites),
            "web_sites_count": web_count,
            "active_connections_count": active_count,
            "sites": sites,
            "by_category": by_category,
            "lan_devices": lan_devices,
            "timestamp": time.time(),
        }
    )


@router.get("/api/v1/telemetry/network/stream")
async def network_stream(
    request: Request,
    _: None = Depends(verify_api_key),
) -> StreamingResponse:
    """Stream SSE con conexiones de red reales y alertas Wazuh (sin datos sintéticos)."""
    global _network_sse_count
    if _network_sse_count >= _NETWORK_SSE_MAX:
        return JSONResponse(
            status_code=503,
            content={"error": f"Demasiadas terminales de red conectadas (máx {_NETWORK_SSE_MAX})"},
        )
    _network_sse_count += 1

    queue = network_bus.subscribe()
    traffic_q = traffic_watcher.subscribe()
    step = 0

    async def network_event_generator():
        nonlocal step
        global _network_sse_count
        try:
            yield f"data: {json.dumps({'type':'connected','msg':'Terminal de Red real conectada','ts':time.time()})}\n\n"

            snap = network_bus.snapshot()
            for conn in snap.get("connections", [])[:250]:
                evt = dict(conn)
                evt["type"] = "network_event"
                evt["subtype"] = "connection"
                yield f"data: {json.dumps({'type':'network_event','data':evt}, default=str)}\n\n"
            yield f"data: {json.dumps({'type':'network_stats','data':snap.get('stats',{}),'ts':time.time()})}\n\n"

            while True:
                if await request.is_disconnected():
                    break
                step += 1

                try:
                    conn = await asyncio.wait_for(queue.get(), timeout=1.4)
                    evt = dict(conn)
                    evt["type"] = "network_event"
                    evt["subtype"] = "connection"
                    yield f"data: {json.dumps({'type':'network_event','data':evt}, default=str)}\n\n"
                except asyncio.TimeoutError:
                    pass

                # Alertas/eventos Wazuh reales (sin inventar destino).
                drained = 0
                while drained < 20:
                    try:
                        ev = traffic_q.get_nowait()
                    except asyncio.QueueEmpty:
                        break
                    drained += 1
                    alert_evt = {
                        "type": "network_traffic",
                        "subtype": "wazuh_alert",
                        "id": ev.get("id") or f"alert-{int(time.time()*1000)}-{drained}",
                        "timestamp": ev.get("timestamp"),
                        "agent_id": ev.get("agent_id", "000"),
                        "agent_name": ev.get("agent_name", "host"),
                        "src_ip": ev.get("src_ip") or "",
                        "src_port": ev.get("src_port") or "",
                        "dst_ip": "",
                        "dst_port": "",
                        "protocol": "",
                        "process": ev.get("command") or ev.get("process") or "",
                        "rule_id": ev.get("rule_id", "0"),
                        "level": ev.get("level", 0),
                        "description": ev.get("description", ""),
                        "status": "DETECTED" if int(ev.get("level", 0)) >= 5 else "EVENT",
                        "full_log": ev.get("full_log", ""),
                    }
                    yield f"data: {json.dumps({'type':'network_event','data':alert_evt}, default=str)}\n\n"

                if step % 3 == 0:
                    snap = network_bus.snapshot()
                    yield f"data: {json.dumps({'type':'network_stats','data':snap.get('stats',{}),'ts':time.time()})}\n\n"
                    try:
                        for ag in await _fetch_network_agents_data():
                            hb = {
                                "type": "agent_heartbeat",
                                "subtype": "keepalive",
                                "id": f"hb-{ag.get('id','000')}-{int(time.time()*1000)}",
                                "timestamp": ag.get("lastKeepAlive") or time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                                "agent_id": str(ag.get("id", "000")),
                                "agent_name": ag.get("name", "agente"),
                                "agent_ip": ag.get("ip", ""),
                                "status": ag.get("status", "unknown"),
                                "os": (ag.get("os") or {}).get("name", "Linux") if isinstance(ag.get("os"), dict) else "Linux",
                                "version": ag.get("version", ""),
                                "last_keep_alive": ag.get("lastKeepAlive", ""),
                                "description": f"Agente {ag.get('name','')}: {ag.get('status','unknown')}",
                            }
                            yield f"data: {json.dumps({'type':'network_event','data':hb}, default=str)}\n\n"
                    except Exception:
                        pass
                yield f"data: {json.dumps({'type':'stream_tick','ts':time.time()})}\n\n"

        except asyncio.CancelledError:
            pass
        finally:
            _network_sse_count -= 1
            network_bus.unsubscribe(queue)
            traffic_watcher.unsubscribe(traffic_q)

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
    """Sonda real por TCP (SYN/connect) a los agentes y puertos del stack."""
    agents = await _fetch_network_agents_data()
    now = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    mgr_host = settings.wazuh_manager_host or settings.wazuh_server_ip

    async def probe(host: str, port: int, timeout: float = 1.5) -> tuple[bool, float]:
        t0 = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True, round((time.perf_counter() - t0) * 1000, 2)
        except Exception:
            return False, round((time.perf_counter() - t0) * 1000, 2)

    probe_results = []
    for ag in agents:
        ag_id = str(ag.get("id", "000"))
        ag_ip = ag.get("ip") or ("127.0.0.1" if ag_id == "000" else "")
        if not ag_ip:
            continue
        # Los agentes no escuchan 1514; se sondea SSH (22) para medir alcance real.
        ok, rtt = await probe(ag_ip, 22)
        probe_results.append({
            "agent_id": ag_id,
            "agent_name": ag.get("name", "host"),
            "ip": ag_ip,
            "status": ag.get("status", "unknown"),
            "port": 22,
            "rtt_ms": rtt if ok else None,
            "timestamp": now,
            "success": ok,
            "detail": "TCP 22 accesible" if ok else "TCP 22 no responde / filtrado",
        })

    services = []
    for port in (1514, 1515, settings.wazuh_manager_api_port, settings.relay_port):
        ok, rtt = await probe(mgr_host, port)
        services.append({
            "service": {1514: "wazuh-remoted", 1515: "wazuh-authd",
                        settings.wazuh_manager_api_port: "wazuh-api",
                        settings.relay_port: "relay"}.get(port, str(port)),
            "host": mgr_host,
            "port": port,
            "rtt_ms": rtt if ok else None,
            "success": ok,
        })

    return JSONResponse(
        content={
            "ok": True,
            "probed_count": len(probe_results),
            "results": probe_results,
            "services": services,
            "timestamp": time.time(),
        }
    )




# ─────────────────────────────────────────────────────────────────────────────
# Enriquecimiento determinista: consulta, catálogos y métricas
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/api/v1/telemetry/events/{event_id}/enrichment")
async def event_enrichment(
    event_id: str,
    _: None = Depends(verify_api_key),
) -> JSONResponse:
    """Devuelve el evento enriquecido más reciente con ese id."""
    wanted = str(event_id)
    for item in reversed(traffic_watcher.get_recent(limit=400)):
        if str(item.get("id")) == wanted:
            return JSONResponse(content={"ok": True, "item": item})
    return JSONResponse(
        status_code=404,
        content={"ok": False, "error": "evento no encontrado en el buffer reciente"},
    )


@router.get("/api/v1/telemetry/enrichment/glossary")
async def enrichment_glossary(_: None = Depends(verify_api_key)) -> JSONResponse:
    """Glosario de términos para tooltips del dashboard."""
    from ..domain.enrichment import get_glossary

    data = get_glossary()
    return JSONResponse(content={"ok": True, "version": data.get("version"), "terms": data.get("terms") or {}})


@router.get("/api/v1/telemetry/enrichment/catalogs/status")
async def enrichment_catalogs_status(_: None = Depends(verify_api_key)) -> JSONResponse:
    """Estado y tamaño de los catálogos de enriquecimiento."""
    from ..domain.enrichment import get_catalog_version
    from ..domain.enrichment.catalogs import get_assets, get_mitre, get_rules, get_services

    rules = get_rules()
    assets = get_assets()
    services = get_services()
    mitre = get_mitre()
    return JSONResponse(
        content={
            "ok": True,
            "catalog_version": get_catalog_version(),
            "rules": len((rules.get("rules") or {})),
            "assets": len((assets.get("assets") or {})),
            "services": len((services.get("services") or {})),
            "mitre_techniques": len((mitre.get("techniques") or {})),
            "enabled": bool(settings.enrich_enabled),
            "geoip_db": settings.enrich_geoip_db,
            "assets_file": settings.enrich_assets_file,
        }
    )


@router.get("/api/v1/telemetry/enrichment/metrics")
async def enrichment_metrics(_: None = Depends(verify_api_key)) -> JSONResponse:
    """Métricas básicas del pipeline y de la caché de enriquecimiento."""
    from ..domain.enrichment import get_catalog_version, get_enrichment_pipeline

    pipeline = get_enrichment_pipeline()
    cache_stats = pipeline.cache.stats() if pipeline.cache else {"enabled": False}
    return JSONResponse(
        content={
            "ok": True,
            "enabled": bool(settings.enrich_enabled),
            "enrichers": [e.name for e in pipeline.enrichers],
            "cache": cache_stats,
            "catalog_version": get_catalog_version(),
            "timestamp": time.time(),
        }
    )


@router.post("/api/v1/telemetry/enrichment/reload")
async def enrichment_reload(_: None = Depends(verify_write)) -> JSONResponse:
    """Recarga catálogos y reinicia el pipeline (sin reiniciar el relay)."""
    from ..domain.enrichment import (
        clear_catalog_cache,
        get_catalog_version,
        reset_enrichment_pipeline,
    )

    clear_catalog_cache()
    reset_enrichment_pipeline()
    return JSONResponse(
        content={
            "ok": True,
            "catalog_version": get_catalog_version(),
            "detail": "Catálogos recargados y pipeline reiniciado",
        }
    )
