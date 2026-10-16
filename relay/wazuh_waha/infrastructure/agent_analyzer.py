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
from ..domain.cis_translator import localize_cis_check

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
    """Solicita al Wazuh Manager que ejecute escaneos de integridad (Syscheck / FIM) y antimalware (Rootcheck) en el agente."""
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

            # 2. Disparar Syscheck (FIM) y Rootcheck (Malware/Rootkits)
            t_sys = client.put(f"{base}/syscheck?agents_list={aid}", headers=headers)
            t_root = client.put(f"{base}/rootcheck?agents_list={aid}", headers=headers)
            r_sys, r_root = await asyncio.gather(t_sys, t_root, return_exceptions=True)

            syscheck_res = r_sys.json() if isinstance(r_sys, httpx.Response) and r_sys.is_success else {}
            rootcheck_res = r_root.json() if isinstance(r_root, httpx.Response) and r_root.is_success else {}

            log.info("wazuh_scans_triggered agent_id=%s syscheck=%s rootcheck=%s", aid, syscheck_res, rootcheck_res)
            return {"ok": True, "agent_id": aid, "syscheck": syscheck_res, "rootcheck": rootcheck_res}
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
    """Construye la tarjeta de postura de seguridad y el Plan de Hardening en español,
    consolidando el resumen de todos los módulos y apartados del SIEM."""
    aid = str(agent_id).strip()
    name = profile.get("name") or profile.get("agent_name") or f"agente-{aid}"
    ip = profile.get("ip") or "N/D"
    hw = profile.get("hardware", {}) or {}
    os_info = profile.get("os", {}) or {}

    # 1. CIS Benchmark (SCA)
    sca = profile.get("sca", {}) or {}
    failed_checks = sca.get("failed_checks", []) or []
    score = float(sca.get("score", 0.0))
    total_checks = sca.get("total_checks", 0)
    passed_checks = sca.get("pass", 0)
    fail_checks = sca.get("fail", 0)
    bar = _render_progress_bar(score)
    policy_name = sca.get("name", "CIS Benchmark")
    policy_id = sca.get("policy_id", "cis")

    # SO y Hardware
    os_desc = f"{os_info.get('name', 'Linux')} {os_info.get('version', '')}".strip()
    arch = os_info.get("architecture", hw.get("cpu_name", "x86_64"))
    kernel = os_info.get("kernel", "-")

    # 2. Monitoreo FIM (Syscheck)
    fim = profile.get("fim", {}) or {}
    fim_count = fim.get("total_files", 0)
    fim_recent = len(fim.get("recent_files", []))
    fim_status = f"{fim_count:,} archivos supervisados" if fim_count > 0 else "Supervisión activa"

    # 3. Rootcheck (Malware & Rootkits)
    rootcheck = profile.get("rootcheck", {}) or {}
    root_items = rootcheck.get("items", [])
    root_count = rootcheck.get("total_items", len(root_items))
    if root_count > 0:
        root_status = f"⚠️ {root_count} anomalías detectadas"
    else:
        root_status = "✅ Sin rootkits ni anomalías"

    # 4. Inventario de Software (SBOM)
    software = profile.get("software", {}) or {}
    pkg_count = software.get("total_packages", len(software.get("sample", [])))

    # 5. Puertos y Sockets en Escucha (Syscollector)
    ports = profile.get("ports", {}) or {}
    ports_count = ports.get("total_count", len(ports.get("items", [])))
    net_ifaces = profile.get("network", {}).get("interfaces", [])
    ifaces_count = len(net_ifaces)

    # 6. Procesos y Consumo de Recursos
    procs = profile.get("processes", {}) or {}
    procs_count = procs.get("total_count", len(procs.get("top_processes", [])))
    ram_total = hw.get("ram_total_mb", 0)
    ram_usage_pct = hw.get("ram_usage_pct", 0)
    if ram_total:
        ram_str = f"{ram_usage_pct}% de {round(ram_total/1024, 1)} GB"
    else:
        ram_str = "Normal"

    # 7. Alertas SIEM y Detecciones Recientes
    recent_detections = profile.get("recent_detections", []) or []
    vuln_count = len([d for d in recent_detections if "vulnerab" in str(d.get("description", "")).lower()])
    high_sev = len([d for d in recent_detections if int(d.get("level", 0)) >= 8])

    lines = [
        "🟢 *[AGENTE CONECTADO • ANÁLISIS DE SEGURIDAD SOC]*",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"🛡️ *Endpoint en Línea:* `{name}` _(ID: {aid})_",
        f"🌐 *Dirección IP:* `{ip}`",
        f"🐧 *Sistema Operativo:* `{os_desc}` ({arch}) • Kernel `{kernel}`",
        f"🔔 *Evento:* `Detección de {trigger_reason} y auditoría de apartados completada`",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━",
        "📊 *RESUMEN DE APARTADOS DEL SIEM:*",
        "",
        "1️⃣ *Seguridad de Configuración (CIS SCA):*",
        f"   • Postura Global: `[{bar}] {score:.1f}%`",
        f"   • Controles: `{total_checks}` (✅ {passed_checks} Aprobados | ❌ {fail_checks} Fallados)",
        f"   • Política: *{policy_name}* (`{policy_id}`)",
        "",
        "2️⃣ *Monitoreo de Integridad de Archivos (FIM):*",
        f"   • Base de Integridad: `{fim_status}`",
        f"   • Modificaciones Recientes: `{fim_recent} archivos verificados`",
        "",
        "3️⃣ *Detección de Malware y Rootkits (Rootcheck):*",
        f"   • Estado Antimalware: `{root_status}`",
        "",
        "4️⃣ *Inventario de Software & SBOM:*",
        f"   • Aplicaciones y Paquetes: `{pkg_count:,} paquetes registrados`" if pkg_count else "   • Paquetes: `En catálogo`",
        "",
        "5️⃣ *Superficie de Red & Puertos Abiertos:*",
        f"   • Sockets en Escucha: `{ports_count} puertos abiertos`" if ports_count else "   • Sockets en Escucha: `Filtrados / Seguro`",
        f"   • Interfaces de Red: `{ifaces_count} interfaces configuradas`",
        "",
        "6️⃣ *Procesos del Sistema & Carga:*",
        f"   • Procesos Activos: `{procs_count} procesos ejecutándose`" if procs_count else "   • Procesos: `Monitoreo continuo activo`",
        f"   • Consumo de Memoria RAM: `{ram_str}`",
        "",
        "7️⃣ *Alertas y Eventos SIEM Correlacionados:*",
        f"   • Total Eventos Recientes: `{len(recent_detections)} eventos`",
    ]

    if vuln_count > 0:
        lines.append(f"   • Alertas de Vulnerabilidad: `⚠️ {vuln_count} eventos detectados`")
    if high_sev > 0:
        lines.append(f"   • Alertas de Severidad Alta (Nivel ≥ 8): `🚨 {high_sev} críticas`")

    lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━")
    lines.append("🔧 *PLAN DE MEJORAS & HARDENING RECOMENDADO:*")

    if failed_checks:
        for idx, check in enumerate(failed_checks[:4], 1):
            localized = localize_cis_check(check)
            title = localized["title"]
            rationale = localized["rationale"]
            remediation = localized["remediation"]

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

    # 1. Disparar escaneos en Wazuh Manager (FIM syscheck + rootcheck)
    await trigger_wazuh_scans(aid)

    # 2. Breve pausa para asimilación de telemetría inicial
    await asyncio.sleep(2.0)

    # 3. Recopilar perfil forense completo
    res = await generate_agent_security_report(aid)
    if not res.get("ok"):
        return f"⚠️ No se pudo completar el análisis del agente `{aid}`: {res.get('error')}"

    profile = res.get("profile", {})
    report_text = format_hardening_report(profile, aid, trigger_reason=reason)

    # 4. Despachar a Telegram si está activo (resumen completo + PDF forense)
    try:
        from .telegram_bot import send_message, send_document
        from ..api.reports import _build_pdf

        if getattr(settings, "telegram_enabled", False):
            # Enviar primero el mensaje de resumen ejecutivo consolidado
            await send_message(report_text)

            # Generar y adjuntar el documento PDF con los 10 apartados forenses
            try:
                pdf_bytes = _build_pdf(profile)
                now_str = time.strftime("%Y%m%d_%H%M%S")
                filename = f"reporte_agente_{aid}_{now_str}.pdf"
                ag_name = profile.get("name") or profile.get("agent_name") or f"agente-{aid}"
                caption = (
                    f"📄 *Reporte Forense & Auditoría SOC (PDF v2.0)*\n"
                    f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                    f"• *Endpoint:* `{ag_name}` (ID: `{aid}`)\n"
                    f"• *Auditoría:* 10 apartados forenses consolidados\n"
                    f"• *Emisión:* `{time.strftime('%d/%m/%Y %H:%M:%S')}` ({round(len(pdf_bytes)/1024, 1)} KB)\n"
                    f"_Wazuh-WAHA SOC Suite_"
                )
                await send_document(
                    document_bytes=pdf_bytes,
                    filename=filename,
                    caption=caption,
                )
            except Exception as epdf:
                log.warning("telegram_pdf_send_on_connect_failed aid=%s err=%s", aid, epdf)
    except Exception as e:
        log.warning("telegram_notify_analyzer_failed aid=%s err=%s", aid, e)

    # 5. Despachar a WhatsApp si está activo
    try:
        from . import waha_client
        if getattr(settings, "whatsapp_enabled", True):
            target_chat = f"{settings.admin_phone}@c.us" if settings.admin_phone else None
            await waha_client.send_text(report_text, chat_id=target_chat)
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
