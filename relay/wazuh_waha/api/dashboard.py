"""
Dashboard API: estado read-only del stack wazuh-waha + HTML self-contained.

Endpoints (Fase 1 — read-only):
  GET  /dashboard                     → HTML del dashboard
  GET  /api/v1/dashboard/status       → JSON con estado de todos los componentes
  GET  /api/v1/dashboard/config       → JSON con valores de .env relevantes

Endpoints (Fase 2 — toggles):
  POST /api/v1/dashboard/toggle        → { target, enabled }
  POST /api/v1/dashboard/action        → { target, action }

Auth: reutiliza X-Api-Key (verify_api_key).
"""
import asyncio
import json
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse

from ..common.logging import log
from ..config import ENV_FILE, settings
from .deps import verify_api_key

router = APIRouter(tags=["dashboard"])

PROJECT_ROOT = Path(__file__).resolve().parents[3]  # relay/wazuh_waha/api/dashboard.py -> project root

# ──────────────────────────────────────────────
# Helpers de bajo nivel
# ──────────────────────────────────────────────

def _run_cmd(cmd: list[str], timeout: int = 5) -> tuple[int, str]:
    """Ejecuta un comando y devuelve (returncode, output_unido)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = (r.stdout or "").strip()
        err = (r.stderr or "").strip()
        return r.returncode, out or err
    except FileNotFoundError:
        return -1, "command_not_found"
    except subprocess.TimeoutExpired:
        return -1, "timeout"
    except Exception as e:
        return -1, str(e)


def _check_tcp(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


# ──────────────────────────────────────────────
# Status checkers — cada una devuelve (health, detail)
# health ∈ {"healthy", "warning", "error", "disabled", "unknown"}
# ──────────────────────────────────────────────

def check_systemd_unit(unit: str) -> tuple[str, str, bool]:
    """Chequea un systemd unit (.service o .timer). Devuelve (health, detail, is_enabled)."""
    _, active = _run_cmd(["systemctl", "is-active", unit])
    _, enabled = _run_cmd(["systemctl", "is-enabled", unit])

    is_enabled = enabled == "enabled"
    if unit.endswith(".timer"):
        if active == "active":
            return "healthy", "running (next: every 5 min)", is_enabled
        elif active == "inactive":
            if is_enabled:
                return "warning", "disabled", is_enabled
            return "disabled", "timer not enabled", is_enabled
        else:
            return "error", active or "failed", is_enabled
    else:
        # .service
        if active == "active":
            return "healthy", "active (running)", is_enabled
        elif active in ("inactive", "deactivating"):
            return "error", active, is_enabled
        else:
            return "error", active or "failed", is_enabled


async def check_waha_session() -> tuple[str, str]:
    """Chequea el status de la sesión WAHA via su API HTTP."""
    if not settings.waha_host:
        return "disabled", "WAHA_HOST vacío"
    try:
        async with httpx.AsyncClient(timeout=5, verify=False) as client:
            r = await client.get(
                f"{settings.waha_host}/api/sessions/{settings.waha_session}",
                headers={"X-Api-Key": settings.waha_api_key},
            )
            if r.is_success:
                data = r.json()
                s = data.get("status", "unknown")
                # WORKING → healthy; STARTING/STOPPED → warning; FAILED/unreachable → error
                if s == "WORKING":
                    return "healthy", f"WORKING ({data.get('me', {}).get('name', '')})"
                elif s in ("STARTING", "STOPPED", "SCANNING_QR"):
                    return "warning", s
                else:
                    return "error", f"{s}"
            else:
                return "error", f"HTTP {r.status_code}"
    except httpx.ConnectError:
        return "error", "WAHA unreachable"
    except Exception as e:
        return "error", str(e)[:120]


def check_docker_container(container: str) -> tuple[str, str]:
    code, out = _run_cmd(["docker", "inspect", "-f", "{{.State.Running}}", container])
    if code != 0:
        return "error", f"container not found: {container}"
    if out == "true":
        # también obtener el estado del healthcheck
        _, health = _run_cmd(["docker", "inspect", "-f", "{{.State.Health.Status}}", container])
        if health == "healthy":
            return "healthy", "running (healthy)"
        elif health == "unhealthy":
            return "error", "running (unhealthy)"
        return "healthy", "running"
    return "error", "container stopped"


def check_waha_docker() -> tuple[str, str]:
    return check_docker_container("wazuh-waha")


# ──────────────────────────────────────────────
# Definición de componentes
# ──────────────────────────────────────────────

def _get_component_status_sync(comp: dict) -> dict:
    """Versión sincrónica de _get_component_status para componentes que no requieren httpx."""
    stype = comp["status_type"]
    overrides = _load_overrides()

    if stype in ("systemd_service", "systemd_timer"):
        health, detail, is_enabled = check_systemd_unit(comp["unit"])
        is_active = health == "healthy"
    elif stype == "docker_container":
        health, detail = comp.get("check_fn", lambda: ("unknown", ""))()
        is_enabled = True
        is_active = health == "healthy"
    elif stype == "waha_session":
        health, detail = "unknown", "not checked (async only)"
        is_enabled = True
        is_active = False
    elif stype == "config_toggle":
        is_active, detail = _get_effective_config_value(comp["config_key"])
        health = "healthy" if is_active else "disabled"
        is_enabled = is_active
    elif stype == "wazuh_rules":
        rg = comp.get("rule_group", comp["id"])
        is_active = overrides.get(f"rule_group:{rg}", True)
        health = "healthy" if is_active else "disabled"
        detail = "activo (notificaciones habilitadas)" if is_active else "silenciado (alertas filtradas)"
        is_enabled = is_active
    else:
        health, detail, is_enabled, is_active = "unknown", "unknown", False, False

    return {
        "id": comp["id"],
        "name": comp["name"],
        "category": comp["category"],
        "icon": comp["icon"],
        "description": comp["description"],
        "health": health,
        "detail": detail,
        "toggleable": comp["toggleable"],
        "current_state": is_active,
        "actions": comp.get("actions", []),
        "unit": comp.get("unit", ""),
        "rule_group": comp.get("rule_group", ""),
    }


# ──────────────────────────────────────────────
# Modelo de componentes ordenados según la consola de Wazuh
# ──────────────────────────────────────────────

COMPONENTS: list[dict] = [
    # ─── 1. Security Operations (SIEM & Auth) ───
    {
        "id": "auth_rules",
        "name": "Authentication & Access Security",
        "category": "sec_ops",
        "icon": "🔐",
        "description": "Logins SSH/su/sudo, accesos exitosos y fallidos (Reglas 5710, 5712, 5715, 5401, 57100-57106)",
        "status_type": "wazuh_rules",
        "rule_group": "authentication_success",
        "toggleable": True,
        "actions": [],
    },
    {
        "id": "active_response",
        "name": "Active Response Engine",
        "category": "sec_ops",
        "icon": "⚡",
        "description": "Bloqueo automático de atacantes y contención (Reglas 60000+)",
        "status_type": "wazuh_rules",
        "rule_group": "active_response",
        "toggleable": True,
        "actions": [],
    },

    # ─── 2. Integrity Monitoring (FIM / Syscheck) ───
    {
        "id": "fim_rules",
        "name": "File Integrity Monitoring (Syscheck)",
        "category": "integrity",
        "icon": "📁",
        "description": "Detección de creación, modificación y borrado de archivos críticos (Reglas 550, 553, 554)",
        "status_type": "wazuh_rules",
        "rule_group": "fim",
        "toggleable": True,
        "actions": [],
    },
    {
        "id": "suid_rules",
        "name": "SUID / SGID Privilege Escalation",
        "category": "integrity",
        "icon": "⚠️",
        "description": "Alertas de binarios con permisos elevados o escalada de privilegios (Regla 520)",
        "status_type": "wazuh_rules",
        "rule_group": "suid",
        "toggleable": True,
        "actions": [],
    },

    # ─── 3. Threat Detection & Vulnerability Management ───
    {
        "id": "vuln_rules",
        "name": "Vulnerability Detector (CVEs)",
        "category": "threat_detection",
        "icon": "🐛",
        "description": "Escaneo y reporte de CVEs activas en paquetes y SO (Reglas 57107-57110)",
        "status_type": "wazuh_rules",
        "rule_group": "vulnerability_detector",
        "toggleable": True,
        "actions": [],
    },
    {
        "id": "net_threat_rules",
        "name": "Threat Intelligence & Downloads",
        "category": "threat_detection",
        "icon": "🌐",
        "description": "Descargas web maliciosas y URLs sospechosas (Reglas 2902, 2903)",
        "status_type": "wazuh_rules",
        "rule_group": "network_threats",
        "toggleable": True,
        "actions": [],
    },

    # ─── 4. Auditing & Policy Monitoring ───
    {
        "id": "sca_rules",
        "name": "Security Configuration Assessment (SCA)",
        "category": "auditing_policy",
        "icon": "📋",
        "description": "Auditoría de cumplimiento de políticas de seguridad y CIS Benchmarks",
        "status_type": "wazuh_rules",
        "rule_group": "sca",
        "toggleable": True,
        "actions": [],
    },
    {
        "id": "rootcheck_rules",
        "name": "Policy & Malware Auditing (Rootcheck)",
        "category": "auditing_policy",
        "icon": "🛡️",
        "description": "Detección de rootkits, troyanos y artefactos anómalos en el sistema",
        "status_type": "wazuh_rules",
        "rule_group": "rootcheck",
        "toggleable": True,
        "actions": [],
    },
    {
        "id": "syscollector_rules",
        "name": "System Inventory (Syscollector)",
        "category": "auditing_policy",
        "icon": "📊",
        "description": "Inventario continuo de hardware, paquetes instalados y puertos abiertos",
        "status_type": "wazuh_rules",
        "rule_group": "syscollector",
        "toggleable": True,
        "actions": [],
    },

    # ─── 5. WhatsApp Gateway & Relay Services ───
    {
        "id": "waha_session",
        "name": "WAHA WhatsApp Session",
        "category": "whatsapp_gateway",
        "icon": "📱",
        "description": "Sesión activa de WhatsApp vía WAHA Docker (Gateway WEBJS / Puppeteer)",
        "status_type": "waha_session",
        "toggleable": True,
        "actions": ["start", "stop"],
    },
    {
        "id": "relay",
        "name": "wazuh-waha Relay Daemon",
        "category": "whatsapp_gateway",
        "icon": "🚀",
        "description": "Servicio FastAPI intermedio de deduplicación y despacho (puerto 8765)",
        "status_type": "systemd_service",
        "unit": "wazuh-waha.service",
        "toggleable": False,
        "actions": ["restart"],
    },
    {
        "id": "wazuh_agent",
        "name": "Wazuh Agent Service",
        "category": "whatsapp_gateway",
        "icon": "🛡️",
        "description": "Agente Wazuh local de monitoreo y telemetría de seguridad",
        "status_type": "systemd_service",
        "unit": "wazuh-agent.service",
        "toggleable": False,
        "actions": ["restart"],
    },

    # ─── 6. Proactive Watchdogs & Self-Healing ───
    {
        "id": "waha_watchdog",
        "name": "WAHA Auto-Recovery Watchdog",
        "category": "watchdogs",
        "icon": "🐕",
        "description": "Supervisa y recupera la sesión de WhatsApp automáticamente si cae (cada 5 min)",
        "status_type": "systemd_timer",
        "unit": "wazuh-waha-watchdog.timer",
        "toggleable": True,
        "actions": [],
    },
    {
        "id": "ip_drift",
        "name": "Manager IP Drift Detector",
        "category": "watchdogs",
        "icon": "🧭",
        "description": "Detecta cambios de IP en la VM/Manager de Wazuh para evitar pérdidas de conexión",
        "status_type": "systemd_timer",
        "unit": "watch_manager_ip.timer",
        "toggleable": True,
        "actions": [],
    },
    {
        "id": "boot_notify",
        "name": "Host Boot Heartbeat Notify",
        "category": "watchdogs",
        "icon": "🔔",
        "description": "Envía reporte de salud por correo y WhatsApp 90s tras arrancar el sistema",
        "status_type": "systemd_timer",
        "unit": "wazuh-waha-boot-notify.timer",
        "toggleable": True,
        "actions": [],
    },
    {
        "id": "agent_health",
        "name": "Wazuh Agent Health Watchdog",
        "category": "watchdogs",
        "icon": "❤️",
        "description": "Verifica conectividad y estado del agente Wazuh periódicamente",
        "status_type": "systemd_timer",
        "unit": "wazuh-agent-health.timer",
        "toggleable": True,
        "actions": [],
    },

    # ─── 7. Backup Notification Channels & AI ───
    {
        "id": "email_notifications",
        "name": "Email Backup Notifications",
        "category": "notifications",
        "icon": "📧",
        "description": "Canal de respaldo por correo electrónico en caso de fallo (SMTP o Hyvor Relay)",
        "status_type": "config_toggle",
        "config_key": "EMAIL_PROVIDER",
        "toggleable": True,
        "actions": [],
    },
    {
        "id": "ollama_ai",
        "name": "Ollama Local AI Summarizer",
        "category": "notifications",
        "icon": "🧠",
        "description": "Resumen y enriquecimiento de alertas con modelo de lenguaje local (Ollama)",
        "status_type": "config_toggle",
        "config_key": "OLLAMA_ENABLED",
        "toggleable": True,
        "actions": [],
    },
    {
        "id": "waha_health_rules",
        "name": "Stack Health Event Alerts",
        "category": "notifications",
        "icon": "💓",
        "description": "Notificaciones de incidentes y auto-recuperaciones del stack (Regla 999001)",
        "status_type": "wazuh_rules",
        "rule_group": "waha_health",
        "toggleable": True,
        "actions": [],
    },
]

# Mapeo de category → label amigable ordenado según la consola de Wazuh
CATEGORY_LABELS = {
    "sec_ops": "Security Operations & SIEM",
    "integrity": "Integrity Monitoring (FIM)",
    "threat_detection": "Threat Detection & Vulnerabilities",
    "auditing_policy": "Auditing & Policy Monitoring",
    "whatsapp_gateway": "WhatsApp Gateway & Relay",
    "watchdogs": "Proactive Watchdogs & Health",
    "notifications": "Backup Channels & AI",
}



# ──────────────────────────────────────────────
# Status checker (async wrapper)
# ──────────────────────────────────────────────

async def gather_status() -> dict[str, Any]:
    """Recolecta el estado de todos los componentes sincronicamente (subprocess no es async)."""
    results: list[dict] = []
    for comp in COMPONENTS:
        # Check WAHA session is async (httpx); everything else is sync
        if comp["status_type"] == "waha_session":
            wa_health, wa_detail = await _check_waha_session_async()
            results.append({
                "id": comp["id"],
                "name": comp["name"],
                "category": comp["category"],
                "icon": comp["icon"],
                "description": comp["description"],
                "health": wa_health,
                "detail": wa_detail,
                "toggleable": comp["toggleable"],
                "current_state": wa_health in ("healthy", "warning"),
                "actions": comp["actions"],
                "unit": comp.get("unit", ""),
        
        # Rule Groups Overrides
        "wazuh_rule_groups": {
            "authentication_success": _load_overrides().get("rule_group:authentication_success", True),
            "fim": _load_overrides().get("rule_group:fim", True),
            "vulnerability_detector": _load_overrides().get("rule_group:vulnerability_detector", True),
            "network_threats": _load_overrides().get("rule_group:network_threats", True),
            "active_response": _load_overrides().get("rule_group:active_response", True),
            "suid": _load_overrides().get("rule_group:suid", True),
            "sca": _load_overrides().get("rule_group:sca", True),
            "rootcheck": _load_overrides().get("rule_group:rootcheck", True),
            "syscollector": _load_overrides().get("rule_group:syscollector", True),
        }
    })

        else:
            result = _get_component_status_sync(comp)
            results.append(result)

    return {
        "host": os.uname().nodename,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "uptime_sec": int(time.time() - _boot_time()),
        "local_ip": _local_ip(),
        "components": results,
    }


async def _check_waha_session_async() -> tuple[str, str]:
    """Async version of check_waha_session."""
    if not settings.waha_host:
        return "disabled", "WAHA_HOST empty"
    try:
        log.info(f"Checking WAHA session status for session: {settings.waha_session}")
        async with httpx.AsyncClient(timeout=5, verify=False) as client:
            r = await client.get(
                f"{settings.waha_host}/api/sessions/{settings.waha_session}",
                headers={"X-Api-Key": settings.waha_api_key},
            )
            if r.is_success:
                data = r.json()
                s = data.get("status", "unknown")
                if s == "WORKING":
                    me = data.get("me", {})
                    name = me.get("name", "") if isinstance(me, dict) else ""
                    log.info(f"WAHA session {settings.waha_session} is WORKING. Linked to: {name}")
                    return "healthy", f"WORKING{f' ({name})' if name else ''}"
                elif s in ("STARTING", "STOPPED", "SCAN_QR_CODE", "SCANNING_QR"):
                    return "warning", s
                else:
                    return "error", s
            elif r.status_code == 404:
                return "error", "session missing - create it"
            else:
                return "error", f"HTTP {r.status_code}"
    except httpx.ConnectError:
        return "error", "WAHA unreachable"
    except Exception as e:
        return "error", str(e)[:120]


def _boot_time() -> float:
    try:
        with open("/proc/stat") as f:
            for line in f:
                if line.startswith("btime"):
                    return float(line.split()[1])
    except Exception:
        pass
    return time.time()


def _local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("1.1.1.1", 53))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "unknown"


# ──────────────────────────────────────────────
# Control helpers (Fase 2)
# ──────────────────────────────────────────────

def _toggle_systemd(unit: str, enabled: bool) -> tuple[bool, str]:
    """Enable/disable un systemd unit."""
    action = "enable" if enabled else "disable"
    code, out = _run_cmd(["sudo", "-n", "systemctl", action, unit, "--now"])
    if code == 0:
        return True, f"{action}d {unit}"
    # Intentar sin sudo (quizás el usuario ya tiene permisos)
    code2, out2 = _run_cmd(["systemctl", action, unit, "--now"])
    if code2 == 0:
        return True, f"{action}d {unit}"
    return False, f"failed: {out or out2}"


def _restart_service(unit: str) -> tuple[bool, str]:
    code, out = _run_cmd(["sudo", "-n", "systemctl", "restart", unit])
    if code == 0:
        return True, f"restarted {unit}"
    code2, out2 = _run_cmd(["systemctl", "restart", unit])
    if code2 == 0:
        return True, f"restarted {unit}"
    return False, f"failed: {out or out2}"


def _toggle_waha_session(start: bool) -> tuple[bool, str]:
    """Start/stop la sesión WAHA via su API."""
    action = "start" if start else "stop"
    url = f"{settings.waha_host}/api/sessions/{settings.waha_session}/{action}"
    try:
        r = subprocess.run(
            ["curl", "-sS", "-m", "10",
             "-H", f"X-Api-Key: {settings.waha_api_key}",
             "-X", "POST", url],
            capture_output=True, text=True, timeout=15,
        )
        if r.returncode == 0:
            return True, f"session {action}ed"
        return False, r.stderr.strip()[:200]
    except Exception as e:
        return False, str(e)


def _load_overrides() -> dict:
    """Lee el archivo de overrides desde relay_lib_dir."""
    try:
        from ..config import load_overrides
        return _load_overrides()
    except Exception:
        return {}


def _save_overrides(data: dict) -> bool:
    """Guarda overrides en relay_lib_dir (writable por el service)."""
    try:
        from ..config import save_overrides
        save_overrides(data)
        return True
    except Exception as e:
        log.error("save_overrides_failed err=%s", e)
        return False


def _get_effective_config_value(key: str) -> tuple[bool, str]:
    """
    Determina el valor efectivo de una config key considerando overrides.
    Devuelve (is_active, detail_string).
    """
    overrides = _load_overrides()

    # Mapeo de keys → settings attr
    setting_map = {
        "EMAIL_PROVIDER": ("email_provider", "smtp"),
        "OLLAMA_ENABLED": ("ollama_enabled", "true"),
    }
    if key not in setting_map:
        return False, f"unknown config key: {key}"

    attr, true_val = setting_map[key]

    # Si hay override, usarlo; si no, usar el valor de settings (de .env)
    if key in overrides:
        override_val = overrides[key]
        if isinstance(override_val, bool):
            return override_val, f"override: {key}={override_val}"
        return bool(override_val), f"override: {key}={override_val}"

    # Leer desde settings (que ya incluye overrides aplicados al startup)
    current = getattr(settings, attr, "")
    if key == "EMAIL_PROVIDER":
        is_active = current not in ("", "none", None)
    else:
        is_active = current in (True, "true", "1", "yes", "True", 1)
    return is_active, f"{key}={current}"


def _toggle_config_override(key: str, enabled: bool) -> tuple[bool, str]:
    """
    Escribe un override en config_overrides.json. Requiere restart del relay
    para aplicar (los overrides se aplican al inicio en config.py).
    """
    setting_map = {
        "EMAIL_PROVIDER": ("email_provider", "smtp"),
        "OLLAMA_ENABLED": ("ollama_enabled", bool),
    }
    if key not in setting_map:
        return False, f"unknown config key: {key}"

    attr, true_val = setting_map[key]

    overrides = _load_overrides()
    if true_val == bool:
        overrides[key] = enabled
    else:
        overrides[key] = true_val if enabled else ""

    if not _save_overrides(overrides):
        return False, "failed to save overrides file"

    # Aplicar in-memory también (para que el status refleje el cambio inmediato)
    try:
        if true_val == bool:
            setattr(settings, attr, enabled)
        else:
            setattr(settings, attr, true_val if enabled else "")
    except Exception:
        pass

    return True, f"{key} override set to {enabled}; relay restart recommended"


# ──────────────────────────────────────────────
# Endpoints: GET (status)
# ──────────────────────────────────────────────
@router.get("/api/v1/dashboard/status", response_class=JSONResponse)
async def dashboard_status(request: Request):
    """JSON con el estado de todos los componentes."""
    await verify_api_key(request)
    status_data = await gather_status()
    return JSONResponse(content=status_data)


@router.get("/api/v1/dashboard/config", response_class=JSONResponse)
async def dashboard_config(request: Request):
    """JSON con valores de .env relevantes para el dashboard."""
    await verify_api_key(request)
    env_vals = {}
    for key in [
        "WAZUH_SERVER_IP", "WAZUH_SERVER_IP_FALLBACK", "AUTO_RECONCILE",
        "WAZUH_MANAGER_HOST", "WAZUH_MANAGER_API_PORT", "WAZUH_MANAGER_API_USER", "WAZUH_MANAGER_API_VERIFY_TLS",
        "ADMIN_PHONE", "WAHA_HOST", "WAHA_SESSION", "WAHA_LOG_LEVEL", "WAHA_HOOK_URL",
        "RELAY_WORKERS", "RELAY_PORT", "RELAY_DEDUP_TTL", "RELAY_MIN_LEVEL_UNKNOWN",
        "EMAIL_PROVIDER", "SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_FROM", "ADMIN_EMAIL", "SMTP_TLS",
        "HYVOR_BASE_URL", "HYVOR_FROM", "ADMIN_EMAIL",
        "OLLAMA_ENABLED", "OLLAMA_HOST", "OLLAMA_MODEL", "OLLAMA_TIMEOUT",
        "WAHA_RECOVERY_COOLDOWN_SEC", "WAHA_RECOVERY_MAX_WAIT_SEC", "WAHA_WATCHDOG_INTERVAL_SEC",
    ]:
        val = os.environ.get(key, "")
        env_vals[key] = val

    return JSONResponse(content={
        "env": env_vals,
        "settings": {
            "relay_api_key_configured": bool(settings.relay_api_key) and settings.relay_api_key != "changeme",
            "email_provider": settings.email_provider,
            "ollama_enabled": settings.ollama_enabled,
            "waha_host": settings.waha_host,
            "waha_session": settings.waha_session,
            "relay_workers": settings.relay_workers,
            "relay_port": settings.relay_port,
            "relay_min_level_unknown": settings.relay_min_level_unknown,
            "relay_dedup_ttl": settings.relay_dedup_ttl,
        },
        # Valores seguros para prellenar el formulario de Settings en el front.
        # NUNCA incluir claves/secrets (solo flags "xxx_set").
        "form": {
            # Wazuh & Network
            "wazuh_server_ip": os.environ.get("WAZUH_SERVER_IP", "") or getattr(settings, "wazuh_server_ip", ""),
            "wazuh_server_ip_fallback": os.environ.get("WAZUH_SERVER_IP_FALLBACK", "") or getattr(settings, "wazuh_server_ip_fallback", ""),
            "auto_reconcile": os.environ.get("AUTO_RECONCILE", "0") in ("1", "true", "True", True),
            "wazuh_manager_api_port": settings.wazuh_manager_api_port,
            "wazuh_manager_api_user": settings.wazuh_manager_api_user,
            "wazuh_manager_api_pass_set": bool(settings.wazuh_manager_api_pass),
            "wazuh_manager_api_verify_tls": settings.wazuh_manager_api_verify_tls,
            # WhatsApp & WAHA
            "admin_phone": settings.admin_phone,
            "waha_host": settings.waha_host,
            "waha_session": settings.waha_session,
            "waha_api_key_set": bool(settings.waha_api_key) and settings.waha_api_key != "changeme",
            "waha_log_level": getattr(settings, "waha_log_level", "info"),
            "waha_hook_url": getattr(settings, "waha_hook_url", ""),
            "waha_recovery_cooldown_sec": settings.waha_recovery_cooldown_sec,
            "waha_recovery_max_wait_sec": settings.waha_recovery_max_wait_sec,
            "waha_watchdog_interval_sec": settings.waha_watchdog_interval_sec,
            # Email Backup
            "email_provider": settings.email_provider,
            "smtp_host": settings.smtp_host,
            "smtp_port": settings.smtp_port,
            "smtp_user": settings.smtp_user,
            "smtp_from": settings.smtp_from,
            "admin_email": settings.admin_email,
            "smtp_tls": settings.smtp_tls,
            "smtp_pass_set": bool(settings.smtp_pass),
            "hyvor_base_url": settings.hyvor_base_url,
            "hyvor_from": settings.hyvor_from,
            "hyvor_api_key_set": bool(settings.hyvor_api_key),
            # Ollama AI
            "ollama_enabled": settings.ollama_enabled,
            "ollama_host": settings.ollama_host,
            "ollama_model": settings.ollama_model,
            "ollama_timeout": settings.ollama_timeout,
            # Relay params
            "relay_port": settings.relay_port,
            "relay_dedup_ttl": settings.relay_dedup_ttl,
            "relay_min_level_unknown": settings.relay_min_level_unknown,
            "relay_workers": settings.relay_workers,
        },

        # Rule Groups Overrides
        "wazuh_rule_groups": {
            "authentication_success": _load_overrides().get("rule_group:authentication_success", True),
            "fim": _load_overrides().get("rule_group:fim", True),
            "vulnerability_detector": _load_overrides().get("rule_group:vulnerability_detector", True),
            "network_threats": _load_overrides().get("rule_group:network_threats", True),
            "active_response": _load_overrides().get("rule_group:active_response", True),
            "suid": _load_overrides().get("rule_group:suid", True),
            "sca": _load_overrides().get("rule_group:sca", True),
            "rootcheck": _load_overrides().get("rule_group:rootcheck", True),
            "syscollector": _load_overrides().get("rule_group:syscollector", True),
        }
    })



# ──────────────────────────────────────────────
# Endpoints: POST (toggle + action) — Fase 2
# ──────────────────────────────────────────────

@router.post("/api/v1/dashboard/toggle")
async def dashboard_toggle(request: Request):
    """Toggle un componente on/off. Body: { target, enabled }"""
    await verify_api_key(request)
    body = await request.json()
    target: str = body.get("target", "")
    enabled: bool = body.get("enabled", True)

    if not target:
        raise HTTPException(status_code=400, detail="target required")

    comp = next((c for c in COMPONENTS if c["id"] == target), None)
    if comp is None:
        raise HTTPException(status_code=404, detail=f"unknown target: {target}")

    if not comp["toggleable"]:
        raise HTTPException(status_code=400, detail=f"{target} is not toggleable")

    stype = comp["status_type"]
    log.info("dashboard_toggle target=%s enabled=%s user=%s", target, enabled,
             request.client.host if request.client else "?")

    if stype == "systemd_timer":
        ok, msg = _toggle_systemd(comp["unit"], enabled)
        return {"ok": ok, "result": msg, "target": target, "enabled": enabled}

    elif stype == "waha_session":
        ok, msg = _toggle_waha_session(enabled)
        return {"ok": ok, "result": msg, "target": target, "enabled": enabled}

    elif stype == "config_toggle":
        ok, msg = _toggle_config_override(comp["config_key"], enabled)
        return {"ok": ok, "result": msg, "target": target, "enabled": enabled,
                "note": "relay restart recommended for full effect"}

    elif stype == "wazuh_rules":
        rg = comp.get("rule_group", target)
        overrides = _load_overrides()
        overrides[f"rule_group:{rg}"] = enabled
        if not _save_overrides(overrides):
            return {"ok": False, "result": "falló al guardar overrides", "target": target, "enabled": enabled}
        state_str = "habilitadas" if enabled else "silenciadas"
        return {
            "ok": True,
            "result": f"Alertas de '{comp['name']}' {state_str}",
            "target": target,
            "enabled": enabled,
        }

    else:
        raise HTTPException(status_code=400, detail=f"unsupported toggle type: {stype}")


@router.post("/api/v1/dashboard/action")
async def dashboard_action(request: Request):
    """Perform an action on a component. Body: { target, action }"""
    await verify_api_key(request)
    body = await request.json()
    target: str = body.get("target", "")
    action: str = body.get("action", "")

    if not target or not action:
        raise HTTPException(status_code=400, detail="target and action required")

    comp = next((c for c in COMPONENTS if c["id"] == target), None)
    if comp is None:
        raise HTTPException(status_code=404, detail=f"unknown target: {target}")

    log.info("dashboard_action target=%s action=%s user=%s", target, action,
             request.client.host if request.client else "?")

    if action == "restart" and comp["status_type"] == "systemd_service":
        ok, msg = _restart_service(comp["unit"])
        return {"ok": ok, "result": msg, "target": target, "action": action}

    elif action == "start" and comp["status_type"] == "waha_session":
        ok, msg = _toggle_waha_session(True)
        return {"ok": ok, "result": msg, "target": target, "action": action}

    elif action == "stop" and comp["status_type"] == "waha_session":
        ok, msg = _toggle_waha_session(False)
        return {"ok": ok, "result": msg, "target": target, "action": action}

    else:
        raise HTTPException(status_code=400, detail=f"unsupported action '{action}' for {target}")


# ──────────────────────────────────────────────
# Endpoints: Config persistente (.env) — Fase 3
# ──────────────────────────────────────────────

# Whitelist de claves que el dashboard puede escribir en el .env.
# NUNCA agregar RELAY_API_KEY / WAHA_API_KEY (rotacion solo manual).
_EDITABLE_ENV_KEYS = {
    # Server Wazuh (manager)
    "WAZUH_SERVER_IP",
    "WAZUH_SERVER_IP_FALLBACK",
    "AUTO_RECONCILE",
    "WAZUH_MANAGER_HOST",
    "WAZUH_MANAGER_API_PORT",
    "WAZUH_MANAGER_API_USER",
    "WAZUH_MANAGER_API_PASS",
    "WAZUH_MANAGER_API_VERIFY_TLS",
    # WhatsApp & WAHA
    "ADMIN_PHONE",
    "WAHA_HOST",
    "WAHA_SESSION",
    "WAHA_API_KEY",
    "WAHA_LOG_LEVEL",
    "WAHA_HOOK_URL",
    "WAHA_RECOVERY_COOLDOWN_SEC",
    "WAHA_RECOVERY_MAX_WAIT_SEC",
    "WAHA_WATCHDOG_INTERVAL_SEC",
    # Email backup
    "EMAIL_PROVIDER",
    "SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS",
    "SMTP_FROM", "ADMIN_EMAIL", "SMTP_TLS",
    "HYVOR_BASE_URL", "HYVOR_API_KEY", "HYVOR_FROM", "ADMIN_EMAIL",
    # Ollama
    "OLLAMA_ENABLED", "OLLAMA_HOST", "OLLAMA_MODEL", "OLLAMA_TIMEOUT",
    # Relay
    "RELAY_PORT", "RELAY_DEDUP_TTL", "RELAY_MIN_LEVEL_UNKNOWN", "RELAY_WORKERS",
}

# Claves cuyo valor Settings espera como bool o int
_BOOL_KEYS = {"SMTP_TLS", "OLLAMA_ENABLED", "WAZUH_MANAGER_API_VERIFY_TLS", "AUTO_RECONCILE"}
_INT_KEYS = {
    "SMTP_PORT", "WAZUH_MANAGER_API_PORT", "WAHA_RECOVERY_COOLDOWN_SEC",
    "WAHA_RECOVERY_MAX_WAIT_SEC", "WAHA_WATCHDOG_INTERVAL_SEC",
    "RELAY_PORT", "RELAY_DEDUP_TTL", "RELAY_MIN_LEVEL_UNKNOWN", "RELAY_WORKERS",
    "OLLAMA_TIMEOUT",
}


def _validate_config_pair(key: str, value: str) -> list[str]:
    """Validaciones de formato antes de escribir en .env."""
    warnings: list[str] = []
    if not value:
        return warnings
    if key == "ADMIN_PHONE" and not value.isdigit():
        warnings.append("ADMIN_PHONE debe contener solo dígitos (formato internacional sin '+')")
    elif key in ("WAZUH_SERVER_IP", "WAZUH_MANAGER_HOST"):
        parts = value.split(".")
        if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            warnings.append(f"{key}: no parece una IPv4 válida ({value})")
    elif key == "WAZUH_SERVER_IP_FALLBACK":
        for ip in value.split(","):
            ip = ip.strip()
            if ip:
                parts = ip.split(".")
                if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                    warnings.append(f"Fallback IP inválida: {ip}")
    elif key in _INT_KEYS:
        if not value.isdigit():
            warnings.append(f"{key} debe ser un número entero")
        elif "PORT" in key and not (1 <= int(value) <= 65535):
            warnings.append(f"{key} fuera de rango de puerto (1-65535)")
    return warnings


def _write_env_batch(updates: dict[str, str]) -> bool:
    """Actualiza o agrega múltiples pares KEY=value en el .env del proyecto, con un único backup."""
    if not ENV_FILE.exists():
        return False
    try:
        ts = int(time.time())
        shutil.copy2(ENV_FILE, ENV_FILE.with_name(f".env.bak.{ts}"))
        lines = ENV_FILE.read_text().splitlines()
        out: list[str] = []
        handled = set()

        for line in lines:
            stripped = line.lstrip()
            matched_key = None
            for k in updates:
                if stripped.startswith(f"{k}=") or stripped.startswith(f"{k} "):
                    matched_key = k
                    break

            if matched_key:
                if matched_key not in handled:
                    out.append(f"{matched_key}={updates[matched_key]}")
                    handled.add(matched_key)
                continue
            out.append(line)

        for k, v in updates.items():
            if k not in handled:
                out.append(f"{k}={v}")

        ENV_FILE.write_text("\n".join(out) + "\n")
        return True
    except Exception as e:
        log.error("env_write_batch_failed err=%s", e)
        return False


def _write_env_key(key: str, value: str) -> bool:
    """Actualiza una sola key (wrapper de _write_env_batch)."""
    return _write_env_batch({key: value})


def _apply_setting_in_memory(key: str, value: str) -> None:
    """Refleja el cambio en settings (y os.environ) sin restart cuando es posible."""
    os.environ[key] = value
    attr = key.lower()
    if hasattr(settings, attr):
        try:
            if key in _BOOL_KEYS:
                setattr(settings, attr, value.strip().lower() in ("1", "true", "yes", "on"))
            elif key in _INT_KEYS:
                setattr(settings, attr, int(value) if value else 0)
            else:
                setattr(settings, attr, value)
        except Exception as e:
            log.warning("setting_apply_failed key=%s err=%s", key, e)


def _sync_relay_env() -> bool:
    """Regenera /etc/wazuh-waha/relay.env desde el .env del repo.

    El EnvironmentFile= del unit tiene precedencia sobre el dotenv al reiniciar,
    asi que cada escritura al .env debe espejarse ahi o el cambio se pierde.
    """
    sync_script = PROJECT_ROOT / "scripts" / "sync_relay_env.sh"
    if not sync_script.exists():
        log.warning("sync_relay_env_missing script=%s", sync_script)
        return False
    code, out = _run_cmd(["sudo", "-n", "bash", str(sync_script), "apply"], timeout=15)
    if code != 0:
        log.warning("sync_relay_env_failed out=%s", out[:200])
        return False
    return True


@router.post("/api/v1/dashboard/config/update")
async def dashboard_config_update(request: Request):
    """Escribe una clave editable en el .env (con backup) y la aplica en memoria."""
    await verify_api_key(request)
    body = await request.json()
    key: str = str(body.get("key", "")).strip()
    value: str = str(body.get("value", "")).strip()

    if not key:
        raise HTTPException(status_code=400, detail="key required")
    if key not in _EDITABLE_ENV_KEYS:
        raise HTTPException(status_code=403, detail=f"key not editable: {key}")

    warnings = _validate_config_pair(key, value)

    if not _write_env_batch({key: value}):
        raise HTTPException(status_code=500, detail="failed to write .env")

    _apply_setting_in_memory(key, value)
    log.info("dashboard_config_update key=%s value_len=%d user=%s", key, len(value),
             request.client.host if request.client else "?")

    if not _sync_relay_env():
        warnings.append("relay.env no sincronizado - correr: sudo bash scripts/sync_relay_env.sh apply")

    restart_recommended = key in ("RELAY_PORT", "RELAY_WORKERS", "SMTP_PORT")
    return {"ok": True, "key": key, "restart_recommended": restart_recommended, "warnings": warnings}


@router.post("/api/v1/dashboard/config/batch")
async def dashboard_config_batch(request: Request):
    """Escribe múltiples claves editables en el .env en un solo paso atómico."""
    await verify_api_key(request)
    body = await request.json()
    raw_settings = body.get("settings", body)
    if not isinstance(raw_settings, dict):
        raise HTTPException(status_code=400, detail="settings dict required")

    updates: dict[str, str] = {}
    all_warnings: list[str] = []
    restart_recommended = False

    for k, v in raw_settings.items():
        key = str(k).strip()
        val = str(v).strip()
        if not key or key not in _EDITABLE_ENV_KEYS:
            continue
        # Evitar sobreescribir contraseñas si el frontend las manda vacías (sin cambio)
        if key in ("SMTP_PASS", "HYVOR_API_KEY", "WAHA_API_KEY", "WAZUH_MANAGER_API_PASS") and not val:
            continue

        warns = _validate_config_pair(key, val)
        all_warnings.extend(warns)
        updates[key] = val
        if key in ("RELAY_PORT", "RELAY_WORKERS", "SMTP_PORT"):
            restart_recommended = True

    if not updates:
        return {"ok": True, "updated_count": 0, "message": "no valid keys to update"}

    if not _write_env_batch(updates):
        raise HTTPException(status_code=500, detail="failed to write .env")

    for k, v in updates.items():
        _apply_setting_in_memory(k, v)

    log.info("dashboard_config_batch updated=%d keys=%s user=%s",
             len(updates), list(updates.keys()),
             request.client.host if request.client else "?")

    if not _sync_relay_env():
        all_warnings.append("relay.env no sincronizado - correr: sudo bash scripts/sync_relay_env.sh apply")

    return {
        "ok": True,
        "updated_count": len(updates),
        "updated_keys": list(updates.keys()),
        "restart_recommended": restart_recommended,
        "warnings": all_warnings,
    }


@router.post("/api/v1/dashboard/test-whatsapp")
async def dashboard_test_whatsapp(request: Request):
    """Manda un mensaje de prueba a WhatsApp via WAHA."""
    await verify_api_key(request)
    from ..infrastructure import waha_client

    if not settings.admin_phone:
        raise HTTPException(status_code=400, detail="ADMIN_PHONE no está configurado")

    msg = (
        "🔔 *[wazuh-waha]* Test de notificación desde el panel.\n"
        f"⏱️ *Hora:* {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        "✅ Conexión con WAHA y número destino funcionando correctamente."
    )
    try:
        res = await waha_client.send_text(msg)
        return {"ok": True, "detail": f"Mensaje enviado a {settings.admin_phone}", "res": res}
    except Exception as e:
        log.error("test_whatsapp_failed err=%s", e)
        return {"ok": False, "detail": f"Error al enviar WhatsApp: {e}"}


@router.post("/api/v1/dashboard/test-wazuh")
async def dashboard_test_wazuh(request: Request):
    """Prueba conectividad con el Manager Wazuh (puerto 1514 y opcionalmente API 55000)."""
    await verify_api_key(request)
    target_ip = settings.wazuh_server_ip or os.environ.get("WAZUH_SERVER_IP", "")
    if not target_ip:
        raise HTTPException(status_code=400, detail="WAZUH_SERVER_IP no configurada")

    agent_port_ok = _check_tcp(target_ip, 1514, timeout=3.0)
    api_port_ok = _check_tcp(target_ip, settings.wazuh_manager_api_port, timeout=3.0)

    detail = (
        f"Manager IP {target_ip} — Puerto Agente 1514: {'ABIERTO ✅' if agent_port_ok else 'CERRADO/INACCESIBLE ❌'}, "
        f"Puerto API {settings.wazuh_manager_api_port}: {'ABIERTO ✅' if api_port_ok else 'CERRADO ❌'}"
    )
    return {
        "ok": agent_port_ok,
        "agent_port_ok": agent_port_ok,
        "api_port_ok": api_port_ok,
        "detail": detail,
    }


@router.post("/api/v1/dashboard/test-email")
async def dashboard_test_email(request: Request):
    """Manda un email de prueba con la config actual. Diagnostico inmediato."""
    await verify_api_key(request)

    from ..infrastructure import notifier

    subject = "[wazuh-waha] Test email"
    body_txt = (
        "Email de prueba enviado desde el dashboard.\n"
        f"Hora: {time.strftime('%Y-%m-%d %H:%M:%S %z')}\n"
        f"Provider: {settings.email_provider}"
    )

    if settings.email_provider == "hyvor_relay":
        ok = await notifier.notify_email_hyvor(subject, body_txt)
        dest = settings.admin_email or "(ADMIN_EMAIL vacio)"
    else:
        ok = await asyncio.to_thread(notifier.notify_email, subject, body_txt)
        dest = settings.admin_email or "(ADMIN_EMAIL vacio)"

    log.info("dashboard_test_email provider=%s ok=%s user=%s",
             settings.email_provider, ok,
             request.client.host if request.client else "?")
    return {"ok": ok, "detail": f"destino: {dest}" if ok else "fallo - revisar logs del relay (journalctl -u wazuh-waha)"}


# ──────────────────────────────────────────────
# Endpoints: Sesion WAHA + QR — Fase 3
# ──────────────────────────────────────────────

@router.get("/api/v1/dashboard/waha/qr")
async def waha_qr(request: Request):
    """Proxy del QR de vinculacion de la sesion WAHA (devuelve PNG)."""
    await verify_api_key(request)
    url = f"{settings.waha_host}/api/{settings.waha_session}/auth/qr?format=image"
    try:
        async with httpx.AsyncClient(timeout=15, verify=False) as client:
            r = await client.get(url, headers={"X-Api-Key": settings.waha_api_key})
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"waha unreachable: {e}")

    ctype = r.headers.get("content-type", "")
    if r.status_code == 200 and "image" in ctype:
        log.info(f"QR code generated successfully for session {settings.waha_session}")
        return Response(
            content=r.content,
            media_type=ctype,
            headers={"Cache-Control": "no-store"},
        )
    if r.status_code == 404:
        raise HTTPException(status_code=404, detail="session_missing")
    # 422 = la sesion no esta esperando QR (ya vinculada, o todavia STARTING)
    raise HTTPException(status_code=502, detail=f"waha {r.status_code}: {r.text[:200]}")

@router.post("/api/v1/dashboard/waha/session")
async def waha_session_action(request: Request):
    """Acciones sobre la sesion WAHA: create | start | stop | logout."""
    await verify_api_key(request)
    body = await request.json()
    action: str = str(body.get("action", "")).strip()
    s = settings.waha_session

    if action == "create":
        url, payload = f"{settings.waha_host}/api/sessions", {"name": s}
    elif action in ("start", "stop", "logout"):
        url, payload = f"{settings.waha_host}/api/sessions/{s}/{action}", None
    else:
        raise HTTPException(status_code=400, detail=f"unknown action: {action}")

    log.info("waha_session_action action=%s user=%s", action,
              request.client.host if request.client else "?")

    try:
        async with httpx.AsyncClient(timeout=30, verify=False) as client:
            if payload is not None:
                r = await client.post(url, json=payload,
                                      headers={"X-Api-Key": settings.waha_api_key})
            else:
                r = await client.post(url, headers={"X-Api-Key": settings.waha_api_key})

        # Handle special case: session already exists for create action
        if action == "create" and r.status_code == 422:
            try:
                error_data = r.json()
                if error_data.get("message", "").find("already exists") >= 0:
                    # Session already exists - treat as success
                    return {"ok": True, "result": "session already exists", "status": "existing"}
            except:
                pass  # If we can't parse JSON, fall through to normal error handling

        if r.is_success:
            status_now = ""
            try:
                status_now = r.json().get("status", "")
            except Exception:
                pass
            return {"ok": True, "result": f"session {action} OK", "status": status_now}
        return {"ok": False, "result": f"waha {r.status_code}: {r.text[:200]}"}
    except Exception as e:
        return {"ok": False, "result": f"waha unreachable: {e}"}



@router.get("/api/v1/dashboard/wazuh/agents")
async def get_wazuh_agents(request: Request, _: None = Depends(verify_api_key)):
    from ..infrastructure.notifier import _get_token
    from ..config import settings
    import httpx

    if not settings.wazuh_manager_host or not settings.wazuh_manager_api_pass:
        return {"error": "Wazuh API no configurada (faltan credenciales)"}

    base = f"https://{settings.wazuh_manager_host}:{settings.wazuh_manager_api_port}"
    verify = settings.wazuh_manager_api_verify_tls

    try:
        async with httpx.AsyncClient(timeout=10, verify=verify) as client:
            token = await _get_token(client)
            if not token:
                return {"error": "Error de autenticación con Wazuh Manager API"}
            
            headers = {"Authorization": f"Bearer {token}"}
            r = await client.get(f"{base}/agents", headers=headers)
            
            if r.is_success:
                data = r.json()
                agents = data.get("data", {}).get("affected_items", [])
                return {"agents": agents}
            else:
                return {"error": f"Error de Wazuh API: {r.status_code} {r.text[:100]}"}
    except Exception as e:
        return {"error": str(e)}

