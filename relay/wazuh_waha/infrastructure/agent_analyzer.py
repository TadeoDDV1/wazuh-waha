"""
agent_analyzer.py — Orquestador de análisis de seguridad, diagnóstico de hardening
y auditoría automática al conectarse un agente Wazuh.

Funcionalidades:
1. Dispara análisis y escaneos de integridad en el Wazuh Manager (Syscheck / FIM).
2. Recopila la postura de seguridad global del endpoint (CIS Benchmark SCA, CVEs, Red, SO).
3. Genera un Plan de Mejoras y Hardening con comandos directos de remediación.
4. Despacha automáticamente la notificación a Telegram y WhatsApp.
5. Watcher en segundo plano para detección reactiva de transiciones de conexión.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx

from ..config import settings

log = logging.getLogger("wazuh-waha.agent_analyzer")

# Caché de control para evitar spam de análisis si hay microcortes de red (cooldown de 30 min)
_LAST_AGENT_STATUSES: dict[str, str] = {}
_LAST_ANALYSIS_TS: dict[str, float] = {}
_ANALYSIS_COOLDOWN_SECONDS = 1800  # 30 minutos


def _render_progress_bar(pct: float) -> str:
    """Renderiza una barra de porcentaje visual para la postura de seguridad."""
    filled = max(0, min(10, int(round(pct / 10))))
    return "█" * filled + "░" * (10 - filled)


async def trigger_wazuh_scans(agent_id: str) -> dict[str, Any]:
    """Solicita al Wazuh Manager que ejecute escaneos de integridad (Syscheck / FIM) en el agente."""
    aid = str(agent_id).strip()
    host = settings.wazuh_server_ip or settings.wazuh_manager_host
    if not host or not settings.wazuh_manager_api_pass:
        return {"ok": False, "error": "Credenciales de API de Wazuh no configuradas"}

    base = f"https://{host}:{settings.wazuh_manager_api_port}"
    auth = (settings.wazuh_manager_api_user, settings.wazuh_manager_api_pass)
    verify = settings.wazuh_manager_api_verify_tls

    try:
        async with httpx.AsyncClient(verify=verify, timeout=12.0) as client:
            # 1. Autenticación
            r_auth = await client.post(f"{base}/security/user/authenticate", auth=auth)
            if r_auth.status_code != 200:
                return {"ok": False, "error": "Fallo de autenticación con Wazuh Manager API"}
            token = r_auth.json().get("data", {}).get("token")
            headers = {"Authorization": f"Bearer {token}"}

            # 2. Disparar Syscheck (FIM)
            # Solo para agentes remotos (aid != '000') para evitar colisiones con colas internas del manager
            syscheck_res = {}
            if aid != "000":
                try:
                    r_sys = await client.put(f"{base}/syscheck?agents_list={aid}", headers=headers)
                    syscheck_res = r_sys.json()
                except Exception as e:
                    syscheck_res = {"error": str(e)}

            log.info("wazuh_scans_triggered agent_id=%s syscheck=%s", aid, syscheck_res)
            return {"ok": True, "agent_id": aid, "syscheck": syscheck_res}
    except Exception as e:
        log.warning("wazuh_scans_trigger_err agent_id=%s err=%s", aid, e)
        return {"ok": False, "error": str(e)}


async def generate_agent_security_report(agent_id: str) -> dict[str, Any]:
    """Recopila la postura de seguridad integral del agente desde el perfil forense y la API de Wazuh."""
    aid = str(agent_id).strip()
    try:
        from ..api.telemetry import _fetch_agent_full_profile
        profile = await _fetch_agent_full_profile(aid)
    except Exception as e:
        log.warning("fetch_agent_profile_failed aid=%s err=%s", aid, e)
        profile = {}

    if not profile or not profile.get("ok"):
        return {
            "ok": False,
            "agent_id": aid,
            "error": f"No se pudo obtener el perfil de seguridad del agente {aid}",
        }

    return {
        "ok": True,
        "agent_id": aid,
        "profile": profile,
    }


def format_hardening_report(profile: dict[str, Any], agent_id: str, trigger_reason: str = "conexión") -> str:
    """Construye la tarjeta de postura de seguridad y el Plan de Hardening en español."""
    aid = str(agent_id).strip()
    name = profile.get("name") or f"agente-{aid}"
    ip = profile.get("ip") or "N/D"
    hw = profile.get("hardware", {}) or {}
    os_info = profile.get("os", {}) or {}
    sca = profile.get("sca", {}) or {}
    failed_checks = sca.get("failed_checks", []) or []
    score = float(sca.get("score", 0.0))
    total_checks = sca.get("total_checks", 0)
    passed_checks = sca.get("pass", 0)
    fail_checks = sca.get("fail", 0)
    bar = _render_progress_bar(score)

    os_desc = f"{os_info.get('name', 'Linux')} {os_info.get('version', '')}".strip()
    arch = os_info.get("architecture", hw.get("cpu_name", "x86_64"))
    kernel = os_info.get("kernel", "-")

    lines = [
        "🟢 *[AGENTE CONECTADO • ANÁLISIS DE SEGURIDAD SOC]*",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"🛡️ *Endpoint en Línea:* `{name}` _(ID: {aid})_",
        f"🌐 *Dirección IP:* `{ip}`",
        f"🐧 *Sistema Operativo:* `{os_desc}` ({arch}) • Kernel `{kernel}`",
        f"🔔 *Evento:* `Detección de {trigger_reason} y auditoría inicial completada`",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━",
        "📊 *Postura de Seguridad CIS Benchmark (SCA):*",
        f"• Cumplimiento Global: `[{bar}] {score:.1f}%`",
        f"• Controles Evaluados: `{total_checks}` (✅ {passed_checks} Aprobados | ❌ {fail_checks} Fallados)",
        f"• Política Aplicada: *{sca.get('name', 'CIS Benchmark')}* (`{sca.get('policy_id', 'cis')}`)",
    ]

    # Resumen de vulnerabilidades si existen
    recent_detections = profile.get("recent_detections", []) or []
    vuln_count = len([d for d in recent_detections if "vulnerab" in str(d.get("description", "")).lower()])
    if vuln_count > 0:
        lines.append(f"• Alertas de Vulnerabilidad: `⚠️ {vuln_count} eventos detectados`")

    lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━")
    lines.append("🔧 *PLAN DE MEJORAS & HARDENING RECOMENDADO:*")

    if failed_checks:
        for idx, check in enumerate(failed_checks[:4], 1):
            title = check.get("title", "Control de seguridad").strip()
            rationale = check.get("rationale", "Reducir superficie de ataque").strip()
            remediation = check.get("remediation", "Aplicar configuración recomendada por fabricante").strip()

            # Acortar textos largos para que quepan estéticamente en pantalla móvil
            if len(rationale) > 130:
                rationale = rationale[:127] + "..."
            if len(remediation) > 180:
                remediation = remediation[:177] + "..."

            lines.append(f"\n{idx}. *{title}*")
            lines.append(f"   💡 _Riesgo:_ {rationale}")
            lines.append(f"   🛠️ _Remediación:_ `{remediation}`")
    else:
        lines.append("\n✅ *¡Excelente! No se detectaron fallos críticos de configuración CIS en este escaneo.*")

    lines.append("\n━━━━━━━━━━━━━━━━━━━━━━━━━━")
    lines.append("⚡ *Acciones inmediatas:*")
    lines.append(f"• Descargar PDF forense: `/reporte {aid}`")
    lines.append(f"• Ficha forense completa: `/agente {aid}`")
    lines.append(f"• Lista de chequeos CIS: `/sca {aid}`")

    return "\n".join(lines)


async def analyze_and_notify_agent(agent_id: str, reason: str = "conexión") -> str:
    """Orquesta el escaneo, recopilación, formateo y notificación multi-canal del agente."""
    aid = str(agent_id).strip()

    # 1. Disparar escaneos en Wazuh Manager
    await trigger_wazuh_scans(aid)

    # 2. Breve pausa para asimilación de telemetría inicial
    await asyncio.sleep(2.0)

    # 3. Recopilar perfil forense
    res = await generate_agent_security_report(aid)
    if not res.get("ok"):
        return f"⚠️ No se pudo completar el análisis del agente `{aid}`: {res.get('error')}"

    profile = res.get("profile", {})
    report_text = format_hardening_report(profile, aid, trigger_reason=reason)

    # 4. Despachar a Telegram si está activo
    try:
        from .telegram_bot import send_message
        if getattr(settings, "telegram_enabled", False):
            await send_message(report_text)
    except Exception as e:
        log.warning("telegram_notify_analyzer_failed aid=%s err=%s", aid, e)

    # 5. Despachar a WhatsApp si está activo
    try:
        from .waha_client import waha_client
        if getattr(settings, "whatsapp_enabled", True) and settings.admin_phone:
            chat_id = f"{settings.admin_phone}@c.us"
            await waha_client.send_text(chat_id, report_text)
    except Exception as e:
        log.warning("whatsapp_notify_analyzer_failed aid=%s err=%s", aid, e)

    return report_text


class AgentConnectionWatcher:
    """Vigila en segundo plano las transiciones de estado de conexión de los agentes."""

    def __init__(self, check_interval: float = 30.0):
        self._interval = check_interval
        self._running = False
        self._task: asyncio.Task | None = None

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._watch_loop())
        log.info("agent_connection_watcher_started interval=%.1fs", self._interval)

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        log.info("agent_connection_watcher_stopped")

    async def _watch_loop(self) -> None:
        # Pausa inicial al arrancar el servicio para dar tiempo a que la red y API estén arriba
        await asyncio.sleep(8.0)

        while self._running:
            try:
                await self._check_agents_state()
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.debug("agent_connection_watcher_err err=%s", e)

            await asyncio.sleep(self._interval)

    async def _check_agents_state(self) -> None:
        host = settings.wazuh_server_ip or settings.wazuh_manager_host
        if not host or not settings.wazuh_manager_api_pass:
            return

        base = f"https://{host}:{settings.wazuh_manager_api_port}"
        auth = (settings.wazuh_manager_api_user, settings.wazuh_manager_api_pass)
        verify = settings.wazuh_manager_api_verify_tls

        try:
            async with httpx.AsyncClient(verify=verify, timeout=8.0) as client:
                r_auth = await client.post(f"{base}/security/user/authenticate", auth=auth)
                if r_auth.status_code != 200:
                    return
                token = r_auth.json().get("data", {}).get("token")
                headers = {"Authorization": f"Bearer {token}"}

                r_ag = await client.get(f"{base}/agents?limit=100", headers=headers)
                if r_ag.status_code != 200:
                    return

                agents = r_ag.json().get("data", {}).get("affected_items", []) or []
                now = time.time()

                for ag in agents:
                    aid = str(ag.get("id", ""))
                    status = str(ag.get("status", "")).lower()
                    prev_status = _LAST_AGENT_STATUSES.get(aid)

                    # Detección de transición a activo
                    if status == "active" and prev_status in ("disconnected", "never_connected"):
                        last_ts = _LAST_ANALYSIS_TS.get(aid, 0.0)
                        if now - last_ts >= _ANALYSIS_COOLDOWN_SECONDS:
                            log.info("agent_connection_detected aid=%s prev=%s cur=%s triggering_analysis=True", aid, prev_status, status)
                            _LAST_ANALYSIS_TS[aid] = now
                            asyncio.create_task(analyze_and_notify_agent(aid, reason="reconexión"))
                        else:
                            log.debug("agent_connection_cooldown_active aid=%s elapsed=%.1fs", aid, now - last_ts)

                    _LAST_AGENT_STATUSES[aid] = status

        except Exception as e:
            log.debug("check_agents_state_failed err=%s", e)


agent_watcher = AgentConnectionWatcher()
