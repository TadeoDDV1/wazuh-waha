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
from .deps import verify_api_key, verify_write

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
        "toggleable": True,
        "actions": ["start", "stop", "restart"],
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
    # ─── 8. Caza de Amenazas y Frameworks ───
    {
        "id": "threat_hunting",
        "name": "Caza de Amenazas (Threat Hunting)",
        "category": "threat_detection",
        "icon": "🎯",
        "description": "Filtra alertas avanzadas de comportamiento malicioso y caza de amenazas",
        "status_type": "wazuh_rules",
        "rule_group": "threat_hunting",
        "toggleable": True,
        "actions": [],
    },
    {
        "id": "mitre_attack",
        "name": "MITRE ATT&CK Framework",
        "category": "threat_detection",
        "icon": "⚔️",
        "description": "Filtra alertas mapeadas con tácticas y técnicas del framework MITRE ATT&CK",
        "status_type": "wazuh_rules",
        "rule_group": "mitre",
        "toggleable": True,
        "actions": [],
    },
    {
        "id": "it_hygiene",
        "name": "Higiene Informática (IT Hygiene)",
        "category": "auditing_policy",
        "icon": "🧹",
        "description": "Filtra alertas relacionadas con buenas prácticas, control de software y vulnerabilidades básicas",
        "status_type": "wazuh_rules",
        "rule_group": "it_hygiene",
        "toggleable": True,
        "actions": [],
    },

    # ─── 9. Cumplimiento Normativo (Compliance) ───
    {
        "id": "pci_dss",
        "name": "PCI DSS Compliance",
        "category": "compliance",
        "icon": "💳",
        "description": "Filtra alertas para requerimientos de tarjetas de pago PCI DSS",
        "status_type": "wazuh_rules",
        "rule_group": "pci_dss",
        "toggleable": True,
        "actions": [],
    },
    {
        "id": "gdpr",
        "name": "RGPD / GDPR Compliance",
        "category": "compliance",
        "icon": "🇪🇺",
        "description": "Filtra alertas relacionadas con el Reglamento General de Protección de Datos",
        "status_type": "wazuh_rules",
        "rule_group": "gdpr",
        "toggleable": True,
        "actions": [],
    },
    {
        "id": "hipaa",
        "name": "HIPAA Compliance",
        "category": "compliance",
        "icon": "🏥",
        "description": "Filtra alertas de privacidad y seguridad de información médica (HIPAA)",
        "status_type": "wazuh_rules",
        "rule_group": "hipaa",
        "toggleable": True,
        "actions": [],
    },
    {
        "id": "nist_800_53",
        "name": "NIST 800-53 Compliance",
        "category": "compliance",
        "icon": "🏛️",
        "description": "Filtra alertas del estándar federal de sistemas de información",
        "status_type": "wazuh_rules",
        "rule_group": "nist_800_53",
        "toggleable": True,
        "actions": [],
    },
    {
        "id": "tsc",
        "name": "TSC (Trust Services Criteria)",
        "category": "compliance",
        "icon": "🤝",
        "description": "Filtra alertas de seguridad, disponibilidad y privacidad (SOC 2 / TSC)",
        "status_type": "wazuh_rules",
        "rule_group": "tsc",
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
    "compliance": "Regulatory Compliance & Standards",
}



# ──────────────────────────────────────────────
# Status checker (async wrapper)
# ──────────────────────────────────────────────

_wazuh_services_cache: dict[str, Any] = {}
_wazuh_services_cache_ts: float = 0.0


async def get_wazuh_services_overview() -> dict[str, Any]:
    """Consulta el estado de los módulos de Wazuh (API, FIM, SCA, MITRE, Vuln) con cache de 15s."""
    global _wazuh_services_cache, _wazuh_services_cache_ts
    now = time.time()
    if _wazuh_services_cache and (now - _wazuh_services_cache_ts < 15):
        return _wazuh_services_cache

    from ..infrastructure.notifier import _get_token

    host = settings.wazuh_manager_host or settings.wazuh_server_ip
    if not host or not settings.wazuh_manager_api_pass:
        overview = {
            "connected": False,
            "error": "Wazuh API no configurada (faltan credenciales o IP)",
            "manager_api": {"connected": False, "status": "No configurado", "version": "N/A"},
            "fim": {"connected": False, "status": "No levantado", "monitored_files": 0},
            "sca": {"connected": False, "status": "No levantado", "policies_count": 0, "score": None},
            "vuln": {"connected": False, "status": "No levantado"},
            "mitre": {"connected": False, "status": "No levantado", "tactics_count": 0, "techniques_count": 0},
        }
        _wazuh_services_cache = overview
        _wazuh_services_cache_ts = now
        return overview

    base = f"https://{host}:{settings.wazuh_manager_api_port}"
    verify = settings.wazuh_manager_api_verify_tls

    try:
        async with httpx.AsyncClient(timeout=8, verify=verify) as client:
            token = await _get_token(client)
            if not token:
                overview = {
                    "connected": False,
                    "error": "Fallo de autenticación con Wazuh Manager API",
                    "manager_api": {"connected": False, "status": "Error auth", "version": "N/A"},
                    "fim": {"connected": False, "status": "No levantado", "monitored_files": 0},
                    "sca": {"connected": False, "status": "No levantado", "policies_count": 0, "score": None},
                    "vuln": {"connected": False, "status": "No levantado"},
                    "mitre": {"connected": False, "status": "No levantado", "tactics_count": 0, "techniques_count": 0},
                }
                _wazuh_services_cache = overview
                _wazuh_services_cache_ts = now
                return overview

            headers = {"Authorization": f"Bearer {token}"}

            # 1. Manager info
            manager_ver = "4.x"
            try:
                r_mgr = await client.get(f"{base}/manager/info", headers=headers)
                if r_mgr.is_success:
                    manager_ver = r_mgr.json().get("data", {}).get("affected_items", [{}])[0].get("version", "4.x")
            except Exception:
                pass

            # 2. FIM (Syscheck)
            fim_count = 0
            fim_status = "Levantado"
            try:
                r_fim = await client.get(f"{base}/syscheck/000?limit=1", headers=headers)
                if r_fim.is_success:
                    fim_count = r_fim.json().get("data", {}).get("total_affected_items", 0)
                else:
                    fim_status = "No levantado"
            except Exception:
                fim_status = "No levantado"

            # 3. SCA
            sca_count = 0
            sca_score = None
            sca_status = "Levantado"
            try:
                r_sca = await client.get(f"{base}/sca/000?limit=5", headers=headers)
                if r_sca.is_success:
                    sca_items = r_sca.json().get("data", {}).get("affected_items", [])
                    sca_count = len(sca_items)
                    if sca_items:
                        sca_score = sca_items[0].get("score")
                else:
                    sca_status = "No levantado"
            except Exception:
                sca_status = "No levantado"

            # 4. MITRE
            mitre_tactics = 0
            mitre_techniques = 0
            mitre_status = "Levantado"
            try:
                r_mitre_tac = await client.get(f"{base}/mitre/tactics?limit=1", headers=headers)
                if r_mitre_tac.is_success:
                    mitre_tactics = r_mitre_tac.json().get("data", {}).get("total_affected_items", 14)
                r_mitre_tec = await client.get(f"{base}/mitre/techniques?limit=1", headers=headers)
                if r_mitre_tec.is_success:
                    mitre_techniques = r_mitre_tec.json().get("data", {}).get("total_affected_items", 750)
            except Exception:
                mitre_status = "No levantado"

            overview = {
                "connected": True,
                "manager_api": {"connected": True, "status": "Levantado", "version": manager_ver},
                "fim": {"connected": fim_status == "Levantado", "status": fim_status, "monitored_files": fim_count},
                "sca": {"connected": sca_status == "Levantado", "status": sca_status, "policies_count": sca_count, "score": sca_score},
                "vuln": {"connected": True, "status": "Levantado"},
                "mitre": {"connected": mitre_status == "Levantado", "status": mitre_status, "tactics_count": mitre_tactics, "techniques_count": mitre_techniques},
            }
            _wazuh_services_cache = overview
            _wazuh_services_cache_ts = now
            return overview
    except Exception as e:
        overview = {
            "connected": False,
            "error": str(e),
            "manager_api": {"connected": False, "status": "Error conexión", "version": "N/A"},
            "fim": {"connected": False, "status": "No levantado", "monitored_files": 0},
            "sca": {"connected": False, "status": "No levantado", "policies_count": 0, "score": None},
            "vuln": {"connected": False, "status": "No levantado"},
            "mitre": {"connected": False, "status": "No levantado", "tactics_count": 0, "techniques_count": 0},
        }
        _wazuh_services_cache = overview
        _wazuh_services_cache_ts = now
        return overview


async def gather_status() -> dict[str, Any]:
    """Recolecta el estado de todos los componentes sincronicamente (subprocess no es async)."""
    results: list[dict] = []
    wazuh_overview = await get_wazuh_services_overview()

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
            })

        else:
            result = _get_component_status_sync(comp)

            # Enriquecer con marcas de conexión a Wazuh en tiempo real
            cid = comp["id"]
            if cid == "fim_rules":
                if wazuh_overview.get("fim", {}).get("connected"):
                    files_n = wazuh_overview["fim"].get("monitored_files", 0)
                    result["wazuh_connected"] = True
                    result["wazuh_status"] = "Levantado"
                    result["detail"] = f"{files_n:,} archivos monitoreados (Wazuh FIM Levantado)"
                else:
                    result["wazuh_connected"] = False
                    result["wazuh_status"] = "No levantado"
                    result["detail"] = "Wazuh FIM no levantado / sin conexión"
            elif cid == "sca_rules":
                if wazuh_overview.get("sca", {}).get("connected"):
                    score = wazuh_overview["sca"].get("score")
                    score_txt = f" (Score: {score}%)" if score is not None else ""
                    result["wazuh_connected"] = True
                    result["wazuh_status"] = "Levantado"
                    result["detail"] = f"CIS Benchmark activo{score_txt} (Wazuh SCA Levantado)"
                else:
                    result["wazuh_connected"] = False
                    result["wazuh_status"] = "No levantado"
                    result["detail"] = "Wazuh SCA no levantado / sin conexión"
            elif cid == "vuln_rules":
                if wazuh_overview.get("vuln", {}).get("connected"):
                    result["wazuh_connected"] = True
                    result["wazuh_status"] = "Levantado"
                    result["detail"] = "Detector de Vulnerabilidades CVEs activo (Levantado)"
                else:
                    result["wazuh_connected"] = False
                    result["wazuh_status"] = "No levantado"
            elif cid == "mitre_attack":
                if wazuh_overview.get("mitre", {}).get("connected"):
                    tactics = wazuh_overview["mitre"].get("tactics_count", 14)
                    techniques = wazuh_overview["mitre"].get("techniques_count", 750)
                    result["wazuh_connected"] = True
                    result["wazuh_status"] = "Levantado"
                    result["detail"] = f"{tactics} tácticas / {techniques} técnicas mapeadas (Levantado)"
                else:
                    result["wazuh_connected"] = False
                    result["wazuh_status"] = "No levantado"
                    result["detail"] = "Framework MITRE no levantado / sin conexión"
            elif comp.get("category") in ("integrity", "threat_detection", "auditing_policy"):
                result["wazuh_connected"] = wazuh_overview.get("connected", False)
                result["wazuh_status"] = "Levantado" if wazuh_overview.get("connected") else "No levantado"

            results.append(result)

    return {
        "host": os.uname().nodename,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "uptime_sec": int(time.time() - _boot_time()),
        "local_ip": _local_ip(),
        "wazuh_services": wazuh_overview,
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
        return load_overrides()
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
        "WHATSAPP_ENABLED", "EMAIL_ALERTS_ENABLED",
        "TELEGRAM_ENABLED", "TELEGRAM_CHAT_ID", "TELEGRAM_MIN_LEVEL",
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
            # Canales de Notificación (WhatsApp, Telegram, Email)
            "whatsapp_enabled": getattr(settings, "whatsapp_enabled", True),
            "email_alerts_enabled": getattr(settings, "email_alerts_enabled", False),
            # Telegram Bot
            "telegram_enabled": getattr(settings, "telegram_enabled", False),
            "telegram_bot_token_set": bool(getattr(settings, "telegram_bot_token", "")),
            "telegram_chat_id": getattr(settings, "telegram_chat_id", ""),
            "telegram_min_level": getattr(settings, "telegram_min_level", 8),
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
            "threat_hunting": _load_overrides().get("rule_group:threat_hunting", True),
            "mitre": _load_overrides().get("rule_group:mitre", True),
            "it_hygiene": _load_overrides().get("rule_group:it_hygiene", True),
            "pci_dss": _load_overrides().get("rule_group:pci_dss", True),
            "gdpr": _load_overrides().get("rule_group:gdpr", True),
            "hipaa": _load_overrides().get("rule_group:hipaa", True),
            "nist_800_53": _load_overrides().get("rule_group:nist_800_53", True),
            "tsc": _load_overrides().get("rule_group:tsc", True),
        }
    })



@router.post("/api/v1/dashboard/auto-detect-phone")
async def auto_detect_phone(request: Request):
    """Detecta el número de teléfono del admin desde la sesión WAHA activa y lo guarda en .env."""
    await verify_write(request)
    if not settings.waha_host:
        return {"ok": False, "result": "WAHA_HOST no configurado"}
    try:
        async with httpx.AsyncClient(timeout=5, verify=False) as client:
            r = await client.get(
                f"{settings.waha_host}/api/sessions/{settings.waha_session}",
                headers={"X-Api-Key": settings.waha_api_key},
            )
            if not r.is_success:
                return {"ok": False, "result": f"WAHA respondió HTTP {r.status_code}"}
            data = r.json()
            if data.get("status") != "WORKING":
                return {"ok": False, "result": f"Sesión no está WORKING (estado: {data.get('status')})"}
            me = data.get("me", {})
            phone_id = me.get("id", "") if isinstance(me, dict) else ""
            # phone_id viene como "5219214380943@c.us", extraer solo el número
            phone = phone_id.split("@")[0] if "@" in phone_id else phone_id
            if not phone or not phone.isdigit():
                return {"ok": False, "result": f"No se pudo extraer número de la sesión (me.id={phone_id})"}
            # Guardar en .env y en memoria
            if not _write_env_batch({"ADMIN_PHONE": phone}):
                return {"ok": False, "result": "Número detectado pero falló al escribir en .env"}
            _apply_setting_in_memory("ADMIN_PHONE", phone)
            _sync_relay_env()
            name = me.get("name", "") if isinstance(me, dict) else ""
            log.info("auto_detect_phone phone=%s name=%s", phone, name)
            return {"ok": True, "phone": phone, "name": name, "result": f"Número detectado: {phone} ({name})"}
    except httpx.ConnectError:
        return {"ok": False, "result": "No se pudo conectar a WAHA"}
    except Exception as e:
        return {"ok": False, "result": str(e)[:200]}


# ──────────────────────────────────────────────
# Endpoints: POST (toggle + action) — Fase 2
# ──────────────────────────────────────────────

@router.post("/api/v1/dashboard/toggle")
async def dashboard_toggle(request: Request):
    """Toggle un componente on/off. Body: { target, enabled }"""
    await verify_write(request)
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
    await verify_write(request)
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
    # Canales de Notificación
    "WHATSAPP_ENABLED", "EMAIL_ALERTS_ENABLED",
    # Telegram Bot
    "TELEGRAM_ENABLED", "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "TELEGRAM_MIN_LEVEL",
    # Relay
    "RELAY_PORT", "RELAY_DEDUP_TTL", "RELAY_MIN_LEVEL_UNKNOWN", "RELAY_WORKERS",
}

# Claves cuyo valor Settings espera como bool o int
_BOOL_KEYS = {
    "SMTP_TLS", "OLLAMA_ENABLED", "WAZUH_MANAGER_API_VERIFY_TLS", "AUTO_RECONCILE",
    "TELEGRAM_ENABLED", "WHATSAPP_ENABLED", "EMAIL_ALERTS_ENABLED",
}
_INT_KEYS = {
    "SMTP_PORT", "WAZUH_MANAGER_API_PORT", "WAHA_RECOVERY_COOLDOWN_SEC",
    "WAHA_RECOVERY_MAX_WAIT_SEC", "WAHA_WATCHDOG_INTERVAL_SEC",
    "RELAY_PORT", "RELAY_DEDUP_TTL", "RELAY_MIN_LEVEL_UNKNOWN", "RELAY_WORKERS",
    "OLLAMA_TIMEOUT", "TELEGRAM_MIN_LEVEL",
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
    target = Path("/etc/wazuh-waha/relay.env")
    try:
        if target.parent.exists() and os.access(target.parent, os.W_OK):
            shutil.copy2(ENV_FILE, target)
            try:
                os.chmod(target, 0o600)
            except Exception:
                pass
            return True
    except Exception as e:
        log.warning("direct_sync_relay_env_failed err=%s", e)

    sync_script = PROJECT_ROOT / "scripts" / "sync_relay_env.sh"
    if not sync_script.exists():
        log.warning("sync_relay_env_missing script=%s", sync_script)
    code, out = _run_cmd(["sudo", "-n", str(sync_script), "apply"], timeout=15)
    if code != 0:
        # Fallback si el script requiriera bash explícito
        code, out = _run_cmd(["sudo", "-n", "bash", str(sync_script), "apply"], timeout=15)
    if code != 0:
        log.warning("sync_relay_env_failed out=%s", out[:200])
        return False
    return True


@router.post("/api/v1/dashboard/config/update")
async def dashboard_config_update(request: Request):
    """Escribe una clave editable en el .env (con backup) y la aplica en memoria."""
    await verify_write(request)
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
    await verify_write(request)
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

    if any(k.startswith("TELEGRAM_") for k in updates):
        try:
            from ..infrastructure.telegram_bot import save_telegram_session
            save_telegram_session(
                token=updates.get("TELEGRAM_BOT_TOKEN"),
                chat_id=updates.get("TELEGRAM_CHAT_ID"),
                enabled=updates.get("TELEGRAM_ENABLED") == "true" if "TELEGRAM_ENABLED" in updates else None,
                min_level=int(updates["TELEGRAM_MIN_LEVEL"]) if "TELEGRAM_MIN_LEVEL" in updates else None,
            )
        except Exception as _e:
            log.warning("telegram_session_save_error: %s", _e)

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
    await verify_write(request)
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
    await verify_write(request)
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
    await verify_write(request)

    body = {}
    try:
        body = await request.json()
    except Exception:
        pass

    dest = (body.get("dest") or body.get("admin_email") or settings.admin_email or os.environ.get("ADMIN_EMAIL", "")).strip()
    if not dest:
        raise HTTPException(status_code=400, detail="Falta dirección de correo destinatario (ADMIN_EMAIL)")

    from ..infrastructure import notifier

    smtp_host = settings.smtp_host or os.environ.get("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(settings.smtp_port or os.environ.get("SMTP_PORT", 587))
    smtp_user = settings.smtp_user or os.environ.get("SMTP_USER", "")
    smtp_pass = settings.smtp_pass or os.environ.get("SMTP_PASS", "")
    smtp_from = settings.smtp_from or smtp_user or "wazuh-waha@localhost"
    smtp_tls = settings.smtp_tls if settings.smtp_tls is not None else True

    subject = "[Wazuh SOC] Notificación de Prueba del Sistema"
    body_txt = (
        "🔐 Notificación de Prueba — Stack Wazuh-WAHA SOC\n\n"
        "Este es un correo de verificación enviado desde el Dashboard.\n"
        f"Fecha y Hora: {time.strftime('%Y-%m-%d %H:%M:%S %z')}\n"
        f"Destinatario: {dest}\n"
        f"Servidor SMTP: {smtp_host}:{smtp_port}\n"
        f"Remitente: {smtp_from}\n\n"
        "Si recibiste este mensaje, la integración de respaldo por correo funciona correctamente."
    )

    if settings.email_provider == "hyvor_relay" and settings.hyvor_base_url:
        ok = await notifier.notify_email_hyvor(subject, body_txt)
        detail = f"Enviado vía Hyvor Relay a {dest}" if ok else "Fallo con proveedor Hyvor Relay (verificar credenciales)"
    else:
        def _send_smtp():
            from email.message import EmailMessage
            import smtplib
            import ssl

            msg = EmailMessage()
            msg["Subject"] = subject
            msg["From"] = smtp_from
            msg["To"] = dest
            msg.set_content(body_txt)

            if smtp_port == 465:
                ctx = ssl.create_default_context()
                with smtplib.SMTP_SSL(smtp_host, 465, context=ctx, timeout=12) as s:
                    if smtp_user and smtp_pass:
                        s.login(smtp_user, smtp_pass)
                    s.send_message(msg)
            else:
                with smtplib.SMTP(smtp_host, smtp_port, timeout=12) as s:
                    if smtp_tls:
                        ctx = ssl.create_default_context()
                        s.starttls(context=ctx)
                    if smtp_user and smtp_pass:
                        s.login(smtp_user, smtp_pass)
                    s.send_message(msg)

        try:
            await asyncio.to_thread(_send_smtp)
            ok = True
            detail = f"Correo de prueba enviado exitosamente a {dest}"
        except Exception as e:
            ok = False
            detail = f"Error SMTP ({smtp_host}:{smtp_port}): {e}"

    log.info("dashboard_test_email ok=%s dest=%s detail=%s", ok, dest, detail)
    return {"ok": ok, "detail": detail}


# ──────────────────────────────────────────────
# Endpoints: Telegram Bot & Monitoreo
# ──────────────────────────────────────────────

@router.get("/api/v1/dashboard/telegram/status")
async def telegram_status(request: Request):
    """Consulta el estado del Bot de Telegram (conexión y username)."""
    await verify_api_key(request)
    from ..infrastructure.telegram_bot import get_bot_info
    info = await get_bot_info()
    return {
        "enabled": getattr(settings, "telegram_enabled", False),
        "configured": bool(getattr(settings, "telegram_bot_token", "")),
        "chat_id": getattr(settings, "telegram_chat_id", ""),
        "min_level": getattr(settings, "telegram_min_level", 8),
        "bot_info": info,
    }


@router.post("/api/v1/dashboard/telegram/pair")
async def telegram_pair(request: Request):
    """Inicia el proceso de emparejamiento con Telegram para detectar chat_id."""
    await verify_write(request)
    from ..infrastructure.telegram_bot import pair_session, telegram_bot, save_telegram_session
    res = await pair_session()
    if res.get("ok") and res.get("chat_id"):
        cid = str(res["chat_id"])
        save_telegram_session(chat_id=cid, enabled=True)
        telegram_bot.start()
    return res


@router.post("/api/v1/dashboard/telegram/test")
async def telegram_test(request: Request):
    """Envía un mensaje de prueba al chat de Telegram configurado."""
    await verify_write(request)
    from ..infrastructure.telegram_bot import send_message
    if not settings.telegram_bot_token or not settings.telegram_chat_id:
        return {"ok": False, "detail": "Token o Chat ID de Telegram no configurados"}

    import platform
    txt = (
        "🛡️ *Wazuh-WAHA Security Relay*\n\n"
        "✅ *Mensaje de prueba exitoso.*\n"
        f"🖥️ *Servidor:* `{platform.node()}`\n"
        f"⏰ *Hora:* {time.strftime('%Y-%m-%d %H:%M:%S %z')}\n\n"
        "El canal de Telegram está listo para recibir alertas de seguridad y responder a `/status`."
    )
    ok = await send_message(txt)
    return {
        "ok": ok,
        "detail": "Mensaje enviado exitosamente a Telegram" if ok else "Fallo al enviar mensaje a Telegram (revisa token y chat_id)",
    }


@router.post("/api/v1/dashboard/notifications/channels")
async def update_notification_channels(request: Request):
    """Actualiza la selección activa de canales de notificación (WhatsApp, Telegram, Correo)."""
    await verify_write(request)
    body = await request.json()
    updates = {}

    if "whatsapp_enabled" in body:
        val = bool(body["whatsapp_enabled"])
        setattr(settings, "whatsapp_enabled", val)
        updates["WHATSAPP_ENABLED"] = "true" if val else "false"

    if "telegram_enabled" in body:
        val = bool(body["telegram_enabled"])
        setattr(settings, "telegram_enabled", val)
        updates["TELEGRAM_ENABLED"] = "true" if val else "false"
        try:
            from ..infrastructure.telegram_bot import telegram_bot, save_telegram_session
            save_telegram_session(enabled=val)
            if val:
                telegram_bot.start()
            else:
                import asyncio
                asyncio.create_task(telegram_bot.stop())
        except Exception as _e:
            log.warning("error toggling telegram bot worker: %s", _e)

    if "email_alerts_enabled" in body:
        val = bool(body["email_alerts_enabled"])
        setattr(settings, "email_alerts_enabled", val)
        updates["EMAIL_ALERTS_ENABLED"] = "true" if val else "false"

    if updates:
        _write_env_batch(updates)

    return {
        "ok": True,
        "channels": {
            "whatsapp_enabled": getattr(settings, "whatsapp_enabled", True),
            "telegram_enabled": getattr(settings, "telegram_enabled", False),
            "email_alerts_enabled": getattr(settings, "email_alerts_enabled", False),
        },
    }



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
    await verify_write(request)
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

    if not (settings.wazuh_manager_host or settings.wazuh_server_ip) or not settings.wazuh_manager_api_pass:
        return {"error": "Wazuh API no configurada (faltan credenciales)"}

    base = f"https://{(settings.wazuh_manager_host or settings.wazuh_server_ip)}:{settings.wazuh_manager_api_port}"
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


@router.post("/api/v1/dashboard/wazuh/agents")
async def add_wazuh_agent(request: Request, _: None = Depends(verify_write)):
    from ..infrastructure.notifier import _get_token
    from ..config import settings
    import httpx

    host = settings.wazuh_manager_host or settings.wazuh_server_ip
    if not host or not settings.wazuh_manager_api_pass:
        return {"ok": False, "error": "Wazuh API no configurada"}

    base = f"https://{host}:{settings.wazuh_manager_api_port}"
    verify = settings.wazuh_manager_api_verify_tls

    try:
        body = await request.json()
        name = body.get("name", "").strip()
        ip = body.get("ip", "any").strip() or "any"

        if not name:
            return {"ok": False, "error": "El nombre del agente es obligatorio"}

        async with httpx.AsyncClient(timeout=10, verify=verify) as client:
            token = await _get_token(client)
            if not token:
                return {"ok": False, "error": "Error de autenticación con Wazuh Manager API"}

            headers = {"Authorization": f"Bearer {token}"}
            payload = {"name": name, "ip": ip}
            r = await client.post(f"{base}/agents", headers=headers, json=payload)
            if r.is_success:
                data = r.json().get("data", {})
                return {"ok": True, "agent": data}
            else:
                err_text = r.text[:200]
                return {"ok": False, "error": f"Error Wazuh API ({r.status_code}): {err_text}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@router.delete("/api/v1/dashboard/wazuh/agents/{agent_id}")
async def delete_wazuh_agent(agent_id: str, request: Request, _: None = Depends(verify_write)):
    from ..infrastructure.notifier import _get_token
    from ..config import settings
    import httpx

    host = settings.wazuh_manager_host or settings.wazuh_server_ip
    if not host or not settings.wazuh_manager_api_pass:
        return {"ok": False, "error": "Wazuh API no configurada"}

    base = f"https://{host}:{settings.wazuh_manager_api_port}"
    verify = settings.wazuh_manager_api_verify_tls

    try:
        async with httpx.AsyncClient(timeout=10, verify=verify) as client:
            token = await _get_token(client)
            if not token:
                return {"ok": False, "error": "Error de autenticación con Wazuh Manager API"}

            headers = {"Authorization": f"Bearer {token}"}
            r = await client.delete(f"{base}/agents?agents_list={agent_id}&status=all", headers=headers)
            if r.is_success:
                return {"ok": True, "message": f"Agente {agent_id} eliminado exitosamente"}
            else:
                return {"ok": False, "error": f"Error Wazuh API ({r.status_code}): {r.text[:200]}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}



@router.get("/api/v1/dashboard/logs")
async def get_dashboard_logs(request: Request, lines: int = 100):
    """Obtiene los últimos logs del servicio systemd (journalctl)."""
    await verify_api_key(request)
    lines = max(1, min(lines, 500))

    # Obtenemos los logs del relay
    code, out = _run_cmd(["journalctl", "-u", "wazuh-waha", "-n", str(lines), "--no-pager", "-q"])
    
    if code != 0:
        return {"ok": False, "logs": f"Error leyendo logs: {out}"}
        
    return {"ok": True, "logs": out}



@router.get("/api/v1/dashboard/wazuh/vulnerabilities")
async def get_wazuh_vulnerabilities(request: Request, agent_id: str = "000", _: None = Depends(verify_api_key)):
    from ..infrastructure.notifier import _get_token
    from ..config import settings
    import httpx
    
    host = (settings.wazuh_manager_host or settings.wazuh_server_ip)
    if not host or not settings.wazuh_manager_api_pass:
        return {"error": "Wazuh API no configurada (faltan credenciales)"}

    base = f"https://{host}:{settings.wazuh_manager_api_port}"
    verify = settings.wazuh_manager_api_verify_tls

    try:
        async with httpx.AsyncClient(timeout=10, verify=verify) as client:
            token = await _get_token(client)
            if not token:
                return {"error": "Error de autenticación con Wazuh API"}
            
            headers = {"Authorization": f"Bearer {token}"}
            r = await client.get(f"{base}/vulnerability/{agent_id}", headers=headers)
            
            if r.is_success:
                return {"vulnerabilities": r.json().get("data", {}).get("affected_items", [])}
            return {"error": str(r.text)}
    except Exception as e:
        return {"error": str(e)}

@router.get("/api/v1/dashboard/wazuh/fim")
async def get_wazuh_fim(request: Request, agent_id: str = "000", _: None = Depends(verify_api_key)):
    from ..infrastructure.notifier import _get_token
    from ..config import settings
    import httpx
    
    host = (settings.wazuh_manager_host or settings.wazuh_server_ip)
    if not host or not settings.wazuh_manager_api_pass:
        return {"error": "Wazuh API no configurada"}

    base = f"https://{host}:{settings.wazuh_manager_api_port}"
    verify = settings.wazuh_manager_api_verify_tls

    try:
        async with httpx.AsyncClient(timeout=10, verify=verify) as client:
            token = await _get_token(client)
            if not token:
                return {"error": "Error de autenticación con Wazuh API"}
            
            headers = {"Authorization": f"Bearer {token}"}
            r = await client.get(f"{base}/syscheck/{agent_id}?limit=100", headers=headers)
            
            if r.is_success:
                data = r.json().get("data", {})
                return {
                    "fim": data.get("affected_items", []),
                    "total": data.get("total_affected_items", 0),
                    "agent_id": agent_id,
                }
            return {"error": str(r.text)}
    except Exception as e:
        return {"error": str(e)}

@router.get("/api/v1/dashboard/wazuh/sca")
async def get_wazuh_sca(request: Request, agent_id: str = "000", _: None = Depends(verify_api_key)):
    from ..infrastructure.notifier import _get_token
    from ..config import settings
    import httpx
    
    host = (settings.wazuh_manager_host or settings.wazuh_server_ip)
    if not host or not settings.wazuh_manager_api_pass:
        return {"error": "Wazuh API no configurada"}

    base = f"https://{host}:{settings.wazuh_manager_api_port}"
    verify = settings.wazuh_manager_api_verify_tls

    try:
        async with httpx.AsyncClient(timeout=10, verify=verify) as client:
            token = await _get_token(client)
            if not token:
                return {"error": "Error de autenticación con Wazuh API"}
            
            headers = {"Authorization": f"Bearer {token}"}
            r = await client.get(f"{base}/sca/{agent_id}", headers=headers)
            
            if r.is_success:
                data = r.json().get("data", {})
                return {
                    "sca": data.get("affected_items", []),
                    "total": data.get("total_affected_items", 0),
                    "agent_id": agent_id,
                }
            return {"error": str(r.text)}
    except Exception as e:
        return {"error": str(e)}

@router.get("/api/v1/dashboard/wazuh/mitre")
async def get_wazuh_mitre(request: Request, _: None = Depends(verify_api_key)):
    from ..infrastructure.notifier import _get_token
    from ..config import settings
    import httpx

    host = (settings.wazuh_manager_host or settings.wazuh_server_ip)
    if not host or not settings.wazuh_manager_api_pass:
        return {"error": "Wazuh API no configurada"}

    base = f"https://{host}:{settings.wazuh_manager_api_port}"
    verify = settings.wazuh_manager_api_verify_tls

    try:
        async with httpx.AsyncClient(timeout=10, verify=verify) as client:
            token = await _get_token(client)
            if not token:
                return {"error": "Error de autenticación con Wazuh API"}

            headers = {"Authorization": f"Bearer {token}"}
            r_tactics = await client.get(f"{base}/mitre/tactics?limit=50", headers=headers)
            r_techniques = await client.get(f"{base}/mitre/techniques?limit=50", headers=headers)

            tactics = []
            techniques = []
            total_tactics = 0
            total_techniques = 0

            if r_tactics.is_success:
                t_data = r_tactics.json().get("data", {})
                tactics = t_data.get("affected_items", [])
                total_tactics = t_data.get("total_affected_items", len(tactics))

            if r_techniques.is_success:
                tec_data = r_techniques.json().get("data", {})
                techniques = tec_data.get("affected_items", [])
                total_techniques = tec_data.get("total_affected_items", len(techniques))

            return {
                "connected": True,
                "tactics": tactics,
                "techniques": techniques,
                "total_tactics": total_tactics,
                "total_techniques": total_techniques,
            }
    except Exception as e:
        return {"error": str(e)}

@router.get("/api/v1/dashboard/wazuh/overview")
async def get_wazuh_overview_endpoint(request: Request, _: None = Depends(verify_api_key)):
    return await get_wazuh_services_overview()


# ─── Wazuh Modules Centralized Control (agent.conf & Restart) ───

MODULES_GROUPS = [
    {
        "id": "audit",
        "title": "Auditoría y Configuración del Sistema",
        "icon": "📁",
        "description": "Monitoreo continuo de integridad de archivos, políticas CIS de endurecimiento y detección de malware.",
        "module_ids": ["fim", "sca", "rootcheck"],
    },
    {
        "id": "endpoint",
        "title": "SEGURIDAD DE LOS PUNTOS FINALES",
        "icon": "🎯",
        "description": "Caza de amenazas en tiempo real, detección de vulnerabilidades conocidas (CVEs) y tácticas MITRE ATT&CK.",
        "module_ids": ["threat_hunting", "vulnerabilities", "mitre"],
    },
    {
        "id": "threat_intel",
        "title": "INTELIGENCIA SOBRE AMENAZAS Y CUMPLIMIENTO",
        "icon": "📜",
        "description": "Higiene informática (inventario de activos) y marcos de cumplimiento regulatorio global.",
        "module_ids": ["syscollector", "pci_dss", "gdpr", "hipaa", "nist_800_53", "tsc"],
    },
]

MODULES_METADATA = [
    # ── Grupo 1: Auditoría y Configuración
    {
        "id": "fim",
        "group_id": "audit",
        "name": "Monitoreo de la Integridad de los Archivos",
        "icon": "📁",
        "directive": "syscheck",
        "description": "Alertas relacionadas con cambios en los archivos, incluidos permisos, contenido, propiedad y atributos.",
    },
    {
        "id": "sca",
        "group_id": "audit",
        "name": "Evaluación de la Configuración",
        "icon": "🛡️",
        "directive": "sca",
        "description": "Analice sus activos como parte de una auditoría de evaluación de configuración.",
    },
    {
        "id": "rootcheck",
        "group_id": "audit",
        "name": "Detección de Malware",
        "icon": "🔍",
        "directive": "rootcheck",
        "description": "Compruebe los indicadores de compromiso provocados por infecciones de malware o ciberataques.",
    },
    # ── Grupo 2: Seguridad de los Puntos Finales
    {
        "id": "threat_hunting",
        "group_id": "endpoint",
        "name": "Caza de Amenazas",
        "icon": "⚡",
        "directive": "active-response",
        "description": "Revisa tus alertas de seguridad e identifica problemas y amenazas en tu entorno.",
    },
    {
        "id": "vulnerabilities",
        "group_id": "endpoint",
        "name": "Detección de Vulnerabilidades",
        "icon": "🪲",
        "directive": "vulnerability-detector",
        "description": "Descubra qué aplicaciones de su entorno se ven afectadas por vulnerabilidades conocidas.",
    },
    {
        "id": "mitre",
        "group_id": "endpoint",
        "name": "MITRE ATT&CK",
        "icon": "⚔️",
        "directive": "mitre",
        "description": "Explore las alertas de seguridad vinculadas a las tácticas y técnicas del adversario para comprender mejor las amenazas.",
    },
    # ── Grupo 3: Inteligencia sobre Amenazas y Cumplimiento
    {
        "id": "syscollector",
        "group_id": "threat_intel",
        "name": "Higiene Informática",
        "icon": "💻",
        "directive": "wodle:syscollector",
        "description": "Evaluar las capas del sistema, el software, los procesos y la red para detectar configuraciones incorrectas, cambios no autorizados y anomalías.",
    },
    {
        "id": "pci_dss",
        "group_id": "threat_intel",
        "name": "PCI DSS",
        "icon": "💳",
        "directive": "compliance:pci_dss",
        "description": "Estándar de seguridad global para entidades que procesan, almacenan o transmiten datos de titulares de tarjetas de pago.",
    },
    {
        "id": "gdpr",
        "group_id": "threat_intel",
        "name": "RGPD",
        "icon": "🇪🇺",
        "directive": "compliance:gdpr",
        "description": "El Reglamento General de Protección de Datos (RGPD) establece directrices para el tratamiento de datos personales.",
    },
    {
        "id": "hipaa",
        "group_id": "threat_intel",
        "name": "HIPAA",
        "icon": "🏥",
        "directive": "compliance:hipaa",
        "description": "La Ley de Portabilidad y Responsabilidad del Seguro Médico de 1996 establece disposiciones de privacidad para salvaguardar la información médica.",
    },
    {
        "id": "nist_800_53",
        "group_id": "threat_intel",
        "name": "NIST 800-53",
        "icon": "🏛️",
        "directive": "compliance:nist_800_53",
        "description": "La publicación especial 800-53 del NIST establece directrices para los sistemas de información federales.",
    },
    {
        "id": "tsc",
        "group_id": "threat_intel",
        "name": "TSC",
        "icon": "📜",
        "directive": "compliance:tsc",
        "description": "Criterios de Trust Services en materia de seguridad, disponibilidad, integridad del procesamiento, confidencialidad y privacidad.",
    },
]

ALL_MODULE_IDS = [m["id"] for m in MODULES_METADATA]

DEFAULT_STATE = {mid: True for mid in ALL_MODULE_IDS}


def _parse_agent_conf_response(data: dict) -> dict[str, dict[str, bool]]:
    scopes: dict[str, dict[str, bool]] = {"global": dict(DEFAULT_STATE)}
    items = data.get("affected_items", [])
    for item in items:
        filters = item.get("filters", {})
        config = item.get("config", {})
        scope_id = filters.get("id") or "global"

        base_parent = scopes.get("global", DEFAULT_STATE)
        scope_conf = dict(scopes.get(scope_id, base_parent))

        if "syscheck" in config:
            scope_conf["fim"] = config["syscheck"].get("disabled") != "yes"
        if "sca" in config:
            scope_conf["sca"] = config["sca"].get("enabled") != "no"
        if "syscollector" in config:
            scope_conf["syscollector"] = config["syscollector"].get("disabled") != "yes"
        if "rootcheck" in config:
            scope_conf["rootcheck"] = config["rootcheck"].get("disabled") != "yes"
        if "active-response" in config:
            ar = config["active-response"]
            if isinstance(ar, list) and ar:
                scope_conf["threat_hunting"] = ar[0].get("disabled") != "yes"
            elif isinstance(ar, dict):
                scope_conf["threat_hunting"] = ar.get("disabled") != "yes"

        scopes[scope_id] = scope_conf
    return scopes


def _build_agent_conf_xml(scopes: dict[str, dict[str, bool]]) -> str:
    parts = []
    g = scopes.get("global", DEFAULT_STATE)
    parts.append("<agent_config>")
    
    # FIM (Syscheck)
    fim_en = g.get("fim", True)
    parts.append("  <syscheck>")
    parts.append(f'    <disabled>{"no" if fim_en else "yes"}</disabled>')
    if fim_en:
        parts.append('    <directories check_all="yes" realtime="yes">/etc,/usr/bin,/usr/sbin</directories>')
        parts.append('    <directories check_all="yes" realtime="yes">/bin,/sbin,/boot</directories>')
    parts.append("  </syscheck>")

    # SCA
    sca_en = g.get("sca", True)
    parts.append("  <sca>")
    parts.append(f'    <enabled>{"yes" if sca_en else "no"}</enabled>')
    if sca_en:
        parts.append("    <scan_on_start>yes</scan_on_start>")
    parts.append("  </sca>")

    # Syscollector
    sysc_en = g.get("syscollector", True)
    parts.append('  <wodle name="syscollector">')
    parts.append(f'    <disabled>{"no" if sysc_en else "yes"}</disabled>')
    if sysc_en:
        parts.append("    <interval>1h</interval>")
        parts.append("    <scan_on_start>yes</scan_on_start>")
        parts.append("    <hardware>yes</hardware>")
        parts.append("    <os>yes</os>")
        parts.append("    <network>yes</network>")
        parts.append("    <packages>yes</packages>")
        parts.append('    <ports all="yes">yes</ports>')
        parts.append("    <processes>yes</processes>")
    parts.append("  </wodle>")

    # Rootcheck
    parts.append("  <rootcheck>")
    parts.append(f'    <disabled>{"no" if g.get("rootcheck", True) else "yes"}</disabled>')
    parts.append("  </rootcheck>")

    # Active Response (Caza de Amenazas)
    parts.append("  <active-response>")
    parts.append(f'    <disabled>{"no" if g.get("threat_hunting", True) else "yes"}</disabled>')
    parts.append("  </active-response>")
    parts.append("</agent_config>")

    for scope_id, conf in scopes.items():
        if scope_id == "global" or not scope_id:
            continue
        parts.append(f'<agent_config id="{scope_id}">')
        if "fim" in conf:
            f_en = conf["fim"]
            parts.append("  <syscheck>")
            parts.append(f'    <disabled>{"no" if f_en else "yes"}</disabled>')
            if f_en:
                parts.append('    <directories check_all="yes" realtime="yes">/etc,/usr/bin,/usr/sbin</directories>')
                parts.append('    <directories check_all="yes" realtime="yes">/bin,/sbin,/boot</directories>')
            parts.append("  </syscheck>")
        if "sca" in conf:
            s_en = conf["sca"]
            parts.append("  <sca>")
            parts.append(f'    <enabled>{"yes" if s_en else "no"}</enabled>')
            if s_en:
                parts.append("    <scan_on_start>yes</scan_on_start>")
            parts.append("  </sca>")
        if "syscollector" in conf:
            sy_en = conf["syscollector"]
            parts.append('  <wodle name="syscollector">')
            parts.append(f'    <disabled>{"no" if sy_en else "yes"}</disabled>')
            parts.append("  </wodle>")
        if "rootcheck" in conf:
            parts.append("  <rootcheck>")
            parts.append(f'    <disabled>{"no" if conf["rootcheck"] else "yes"}</disabled>')
            parts.append("  </rootcheck>")
        if "threat_hunting" in conf:
            parts.append("  <active-response>")
            parts.append(f'    <disabled>{"no" if conf["threat_hunting"] else "yes"}</disabled>')
            parts.append("  </active-response>")
        parts.append("</agent_config>")

    return "\n".join(parts)


@router.get("/api/v1/dashboard/wazuh/modules")
async def get_wazuh_modules_control(request: Request, _: None = Depends(verify_api_key)):
    from ..infrastructure.notifier import _get_token
    from ..config import settings
    import httpx

    host = (settings.wazuh_manager_host or settings.wazuh_server_ip)
    if not host or not settings.wazuh_manager_api_pass:
        return {"error": "Wazuh API no configurada"}

    base = f"https://{host}:{settings.wazuh_manager_api_port}"
    verify = settings.wazuh_manager_api_verify_tls

    try:
        async with httpx.AsyncClient(timeout=10, verify=verify) as client:
            token = await _get_token(client)
            if not token:
                return {"error": "Error de autenticación con Wazuh API"}

            headers = {"Authorization": f"Bearer {token}"}

            # 1. Get agents
            scopes = [{"id": "global", "name": "🌐 Todos los Agentes (Global)", "status": "active"}]
            r_agents = await client.get(f"{base}/agents", headers=headers)
            agents_data = []
            if r_agents.is_success:
                agents_data = r_agents.json().get("data", {}).get("affected_items", [])
                for ag in agents_data:
                    ag_id = ag.get("id")
                    ag_name = ag.get("name", f"Agente {ag_id}")
                    ag_status = ag.get("status", "unknown")
                    if ag_id != "000":
                        scopes.append({
                            "id": ag_id,
                            "name": f"💻 {ag_id} - {ag_name}",
                            "status": ag_status,
                            "ip": ag.get("ip", "any"),
                            "os": ag.get("os", {}).get("name", ""),
                        })
                    else:
                        scopes.append({
                            "id": "000",
                            "name": f"🖥️ 000 - {ag_name} (Server)",
                            "status": ag_status,
                            "ip": "127.0.0.1",
                            "os": ag.get("os", {}).get("name", ""),
                        })

            # 2. Get group config
            r_conf = await client.get(f"{base}/groups/default/configuration", headers=headers)
            modules_config = {"global": dict(DEFAULT_STATE)}
            if r_conf.is_success:
                modules_config = _parse_agent_conf_response(r_conf.json().get("data", {}))

            # Ensure all modules exist in all scopes
            for s in scopes:
                sid = s["id"]
                if sid not in modules_config:
                    modules_config[sid] = dict(modules_config.get("global", DEFAULT_STATE))
                else:
                    for mid in ALL_MODULE_IDS:
                        if mid not in modules_config[sid]:
                            modules_config[sid][mid] = modules_config.get("global", {}).get(mid, True)

            # 3. Compute real-time health per agent
            agent_health: dict[str, dict[str, dict]] = {}
            for ag in agents_data:
                aid = ag.get("id")
                is_active = ag.get("status") == "active"
                health_dict = {}
                for m in MODULES_METADATA:
                    mid = m["id"]
                    if is_active:
                        health_dict[mid] = {
                            "connected": True,
                            "status": "Levantado",
                            "badge": "● Levantado",
                            "color": "green",
                            "last_sync": "En tiempo real" if mid in ("fim", "threat_hunting", "mitre") else "Sincronizado",
                        }
                    else:
                        health_dict[mid] = {
                            "connected": False,
                            "status": "Desconectado",
                            "badge": "● Desconectado",
                            "color": "red",
                            "last_sync": "Sin conexión",
                        }
                agent_health[aid] = health_dict

            agent_health["global"] = {
                m["id"]: {
                    "connected": True,
                    "status": "Levantado",
                    "badge": "● Activo Global",
                    "color": "green",
                    "last_sync": "Todos los Agentes",
                } for m in MODULES_METADATA
            }

            return {
                "ok": True,
                "groups": MODULES_GROUPS,
                "scopes": scopes,
                "modules_config": modules_config,
                "modules_meta": MODULES_METADATA,
                "agent_health": agent_health,
            }
    except Exception as e:
        return {"error": str(e)}


@router.get("/api/v1/dashboard/wazuh/rootcheck")
async def get_wazuh_rootcheck(request: Request, agent_id: str = "000", _: None = Depends(verify_api_key)):
    from ..infrastructure.notifier import _get_token
    from ..config import settings
    import httpx

    host = (settings.wazuh_manager_host or settings.wazuh_server_ip)
    if not host or not settings.wazuh_manager_api_pass:
        return {"error": "Wazuh API no configurada"}

    base = f"https://{host}:{settings.wazuh_manager_api_port}"
    verify = settings.wazuh_manager_api_verify_tls

    try:
        async with httpx.AsyncClient(timeout=10, verify=verify) as client:
            token = await _get_token(client)
            if not token:
                return {"error": "Error de autenticación con Wazuh API"}

            headers = {"Authorization": f"Bearer {token}"}
            r = await client.get(f"{base}/rootcheck/{agent_id}?limit=50", headers=headers)
            if r.is_success:
                data = r.json().get("data", {})
                return {
                    "ok": True,
                    "rootcheck": data.get("affected_items", []),
                    "total": data.get("total_affected_items", 0),
                    "agent_id": agent_id,
                }
            return {"error": str(r.text)}
    except Exception as e:
        return {"error": str(e)}


@router.get("/api/v1/dashboard/wazuh/syscollector")
async def get_wazuh_syscollector(request: Request, agent_id: str = "000", _: None = Depends(verify_api_key)):
    from ..infrastructure.notifier import _get_token
    from ..config import settings
    import httpx

    host = (settings.wazuh_manager_host or settings.wazuh_server_ip)
    if not host or not settings.wazuh_manager_api_pass:
        return {"error": "Wazuh API no configurada"}

    base = f"https://{host}:{settings.wazuh_manager_api_port}"
    verify = settings.wazuh_manager_api_verify_tls

    try:
        async with httpx.AsyncClient(timeout=10, verify=verify) as client:
            token = await _get_token(client)
            if not token:
                return {"error": "Error de autenticación con Wazuh API"}

            headers = {"Authorization": f"Bearer {token}"}
            r_os = await client.get(f"{base}/syscollector/{agent_id}/os", headers=headers)
            r_ports = await client.get(f"{base}/syscollector/{agent_id}/ports?limit=500", headers=headers)
            r_hw = await client.get(f"{base}/syscollector/{agent_id}/hardware", headers=headers)

            os_data = r_os.json().get("data", {}).get("affected_items", [{}])[0] if r_os.is_success else {}
            ports = r_ports.json().get("data", {}).get("affected_items", []) if r_ports.is_success else []
            hw = r_hw.json().get("data", {}).get("affected_items", [{}])[0] if r_hw.is_success else {}

            return {
                "ok": True,
                "agent_id": agent_id,
                "os": os_data,
                "hardware": hw,
                "ports": ports,
                "total_ports": len(ports),
            }
    except Exception as e:
        return {"error": str(e)}


@router.get("/api/v1/dashboard/wazuh/recommendations")
async def get_wazuh_recommendations(request: Request, agent_id: str = "000", _: None = Depends(verify_api_key)):
    from ..infrastructure.notifier import _get_token
    from ..config import settings
    import httpx

    host = (settings.wazuh_manager_host or settings.wazuh_server_ip)
    if not host or not settings.wazuh_manager_api_pass:
        return {"ok": False, "error": "Wazuh API no configurada", "recommendations": []}

    base = f"https://{host}:{settings.wazuh_manager_api_port}"
    verify = settings.wazuh_manager_api_verify_tls
    recs = []

    try:
        async with httpx.AsyncClient(timeout=12, verify=verify) as client:
            token = await _get_token(client)
            if not token:
                return {"ok": False, "error": "Error autenticación", "recommendations": []}

            headers = {"Authorization": f"Bearer {token}"}

            # 1. SCA Recommendations
            try:
                r_sca = await client.get(f"{base}/sca/{agent_id}", headers=headers)
                if r_sca.is_success:
                    pols = r_sca.json().get("data", {}).get("affected_items", [])
                    for pol in pols:
                        pid = pol.get("policy_id")
                        score = pol.get("score", 100)
                        fail_count = pol.get("fail", 0)
                        if score < 70 or fail_count > 0:
                            recs.append({
                                "module_id": "sca",
                                "module_name": "Evaluación de la configuración",
                                "severity": "high" if score < 60 else "medium",
                                "title": f"Bajo cumplimiento CIS ({pol.get('name', pid)}: {score}%)",
                                "issue": f"El agente '{agent_id}' no cumple con {fail_count} controles de endurecimiento.",
                                "remediation": "Aplicar remediaciones sugeridas en la auditoría CIS para alcanzar un score > 80%.",
                                "impact": "Fortalece la resistencia del sistema frente a ataques e intrusiones.",
                            })
                        # Top failed checks
                        r_chk = await client.get(f"{base}/sca/{agent_id}/checks/{pid}?result=failed&limit=3", headers=headers)
                        if r_chk.is_success:
                            checks = r_chk.json().get("data", {}).get("affected_items", [])
                            for chk in checks:
                                recs.append({
                                    "module_id": "sca",
                                    "module_name": "Evaluación de la configuración",
                                    "severity": "medium",
                                    "title": chk.get("title", "Check CIS fallido"),
                                    "issue": (chk.get("rationale") or "Parámetro no alineado con benchmark CIS.")[:250],
                                    "remediation": (chk.get("remediation") or "Ajustar parámetro en el archivo de configuración.")[:300],
                                    "impact": "Previene configuraciones inseguras y accesos no autorizados.",
                                })
            except Exception:
                pass

            # 2. Vulnerability Detector Recommendations
            try:
                r_vuln = await client.get(f"{base}/vulnerability/{agent_id}?limit=10", headers=headers)
                if r_vuln.is_success:
                    vulns = r_vuln.json().get("data", {}).get("affected_items", [])
                    if vulns:
                        pkgs = list(set(v.get("name") or v.get("package") for v in vulns if (v.get("name") or v.get("package"))))
                        pkg_str = " ".join(pkgs[:4])
                        recs.append({
                            "module_id": "vulnerabilities",
                            "module_name": "Detección de vulnerabilidades",
                            "severity": "critical",
                            "title": f"Parches urgentes de seguridad ({len(vulns)} CVEs)",
                            "issue": f"Se han detectado paquetes con vulnerabilidades conocidas y exploits documentados.",
                            "remediation": f"sudo apt-get update && sudo apt-get --only-upgrade install -y {pkg_str}",
                            "impact": "Elimina vulnerabilidades críticas explotables de forma remota.",
                        })
            except Exception:
                pass

            # 3. Rootcheck / Malware Recommendations
            try:
                r_rc = await client.get(f"{base}/rootcheck/{agent_id}?limit=5", headers=headers)
                if r_rc.is_success:
                    rc_items = r_rc.json().get("data", {}).get("affected_items", [])
                    unsolved = [it for it in rc_items if it.get("status") != "solved"]
                    if unsolved:
                        for it in unsolved[:2]:
                            recs.append({
                                "module_id": "rootcheck",
                                "module_name": "Detección de malware",
                                "severity": "critical",
                                "title": "Posible anomalía de malware o proceso oculto",
                                "issue": it.get("log", "Proceso oculto o archivo anómalo en /proc detectado por Rootcheck."),
                                "remediation": "sudo rkhunter --check --sk && sudo chkrootkit && ps -ef",
                                "impact": "Identifica y remueve kits de intrusión y procesos maliciosos encubiertos.",
                            })
                    else:
                        recs.append({
                            "module_id": "rootcheck",
                            "module_name": "Detección de malware",
                            "severity": "low",
                            "title": "Mantener base de firmas de rootkits actualizada",
                            "issue": "El motor de detección de malware está levantado y supervisando el kernel.",
                            "remediation": "sudo /var/ossec/bin/rootcheck_control -u all 2>/dev/null || true",
                            "impact": "Asegura detección oportuna de nuevas variantes de troyanos.",
                        })
            except Exception:
                pass

            # 4. FIM Recommendations
            try:
                r_fim = await client.get(f"{base}/syscheck/{agent_id}?limit=5", headers=headers)
                if r_fim.is_success:
                    fim_total = r_fim.json().get("data", {}).get("total_affected_items", 0)
                    recs.append({
                        "module_id": "fim",
                        "module_name": "Monitoreo de la integridad de los archivos",
                        "severity": "medium",
                        "title": f"Asegurar permisos estrictos en {fim_total} archivos monitorizados",
                        "issue": "Wazuh supervisa en tiempo real modificaciones y cambios de permisos en /etc, /bin y /usr/bin.",
                        "remediation": "sudo chmod 644 /etc/*.conf 2>/dev/null; sudo chown -R root:root /etc",
                        "impact": "Previene manipulación no autorizada de archivos esenciales del sistema operativo.",
                    })
            except Exception:
                pass

            # 5. Syscollector / Higiene informática
            try:
                r_ports = await client.get(f"{base}/syscollector/{agent_id}/ports?limit=500", headers=headers)
                if r_ports.is_success:
                    ports = r_ports.json().get("data", {}).get("affected_items", [])
                    open_all = [p for p in ports if p.get("local", {}).get("ip") in ("0.0.0.0", "::") and p.get("state") == "listening"]
                    if open_all:
                        ports_str = ", ".join(str(p.get("local", {}).get("port")) for p in open_all[:5])
                        recs.append({
                            "module_id": "syscollector",
                            "module_name": "Higiene informática",
                            "severity": "low",
                            "title": f"Servicios escuchando en interfaces abiertas ({len(open_all)} puertos)",
                            "issue": f"Puertos {ports_str} están en modo LISTEN en todas las interfaces de red.",
                            "remediation": "sudo ufw default deny incoming && sudo ufw allow from <IP_CONFIANZA>",
                            "impact": "Cierra vectores de reconocimiento y escaneo no deseado desde la red.",
                        })
            except Exception:
                pass

            # 6. Compliance & Threat Hunting Recommendations
            recs.extend([
                {
                    "module_id": "pci_dss",
                    "module_name": "PCI DSS",
                    "severity": "medium",
                    "title": "Política de contraseñas robustas y caducidad (Req. 8.2)",
                    "issue": "Los estándares PCI DSS exigen vigencia máxima de contraseñas y complejidad mínima.",
                    "remediation": "sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs",
                    "impact": "Protege entornos que procesan datos de titulares de tarjetas de pago.",
                },
                {
                    "module_id": "gdpr",
                    "module_name": "RGPD",
                    "severity": "medium",
                    "title": "Registro y trazabilidad de acceso a datos personales (Art. 32)",
                    "issue": "El RGPD exige medidas técnicas para garantizar la integridad y confidencialidad de los datos.",
                    "remediation": "sudo apt-get install -y auditd && sudo systemctl enable --now auditd",
                    "impact": "Garantiza trazabilidad y evidencia forense ante posibles incidentes.",
                },
                {
                    "module_id": "threat_hunting",
                    "module_name": "Caza de amenazas",
                    "severity": "high",
                    "title": "Verificar contención automática de IPs en firewall ante brute-force",
                    "issue": "Wazuh cuenta con scripts de respuesta activa para bloqueo de IPs hostiles.",
                    "remediation": "Verificar directiva <active-response> en ossec.conf y conectividad iptables.",
                    "impact": "Detiene ataques automatizados de diccionario sin intervención humana.",
                },
            ])

            return {
                "ok": True,
                "agent_id": agent_id,
                "total": len(recs),
                "recommendations": recs,
            }
    except Exception as e:
        return {"ok": False, "error": str(e), "recommendations": []}


@router.post("/api/v1/dashboard/wazuh/modules/toggle")
async def toggle_wazuh_module(request: Request, _: None = Depends(verify_write)):
    from ..infrastructure.notifier import _get_token
    from ..config import settings
    import httpx

    body = await request.json()
    scope = body.get("scope", "global")
    module = body.get("module")
    enabled = bool(body.get("enabled", True))

    if not module:
        raise HTTPException(status_code=400, detail="module field required")

    host = (settings.wazuh_manager_host or settings.wazuh_server_ip)
    if not host or not settings.wazuh_manager_api_pass:
        raise HTTPException(status_code=500, detail="Wazuh API no configurada")

    base = f"https://{host}:{settings.wazuh_manager_api_port}"
    verify = settings.wazuh_manager_api_verify_tls

    try:
        async with httpx.AsyncClient(timeout=15, verify=verify) as client:
            token = await _get_token(client)
            if not token:
                raise HTTPException(status_code=500, detail="Error de autenticación con Wazuh API")

            headers = {"Authorization": f"Bearer {token}"}

            # 1. Read existing config
            r_conf = await client.get(f"{base}/groups/default/configuration", headers=headers)
            modules_config = {"global": dict(DEFAULT_STATE)}
            if r_conf.is_success:
                modules_config = _parse_agent_conf_response(r_conf.json().get("data", {}))

            # 2. Update config for scope
            if scope not in modules_config:
                modules_config[scope] = dict(modules_config.get("global", DEFAULT_STATE))
            modules_config[scope][module] = enabled

            # 3. Build XML and send PUT
            xml_data = _build_agent_conf_xml(modules_config)
            xml_headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/xml"}
            r_put = await client.put(f"{base}/groups/default/configuration", headers=xml_headers, content=xml_data)
            if not r_put.is_success:
                raise HTTPException(status_code=500, detail=f"Error actualizando agent.conf: {r_put.text}")

            # 4. Restart agents
            if scope == "global" or scope == "000":
                await client.put(f"{base}/agents/restart", headers=headers)
            else:
                await client.put(f"{base}/agents/restart?agents_list={scope}", headers=headers)

            return {
                "ok": True,
                "scope": scope,
                "module": module,
                "enabled": enabled,
                "modules_config": modules_config,
                "message": f"Módulo {module} {'activado' if enabled else 'desactivado'} para {scope} con reinicio aplicado.",
            }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/v1/dashboard/wazuh/modules/bulk")
async def bulk_toggle_wazuh_modules(request: Request, _: None = Depends(verify_write)):
    from ..infrastructure.notifier import _get_token
    from ..config import settings
    import httpx

    body = await request.json()
    scope = body.get("scope", "global")
    enabled = bool(body.get("enabled", True))

    host = (settings.wazuh_manager_host or settings.wazuh_server_ip)
    if not host or not settings.wazuh_manager_api_pass:
        raise HTTPException(status_code=500, detail="Wazuh API no configurada")

    base = f"https://{host}:{settings.wazuh_manager_api_port}"
    verify = settings.wazuh_manager_api_verify_tls

    try:
        async with httpx.AsyncClient(timeout=15, verify=verify) as client:
            token = await _get_token(client)
            if not token:
                raise HTTPException(status_code=500, detail="Error de autenticación con Wazuh API")

            headers = {"Authorization": f"Bearer {token}"}

            # 1. Read existing config
            r_conf = await client.get(f"{base}/groups/default/configuration", headers=headers)
            modules_config = {"global": dict(DEFAULT_STATE)}
            if r_conf.is_success:
                modules_config = _parse_agent_conf_response(r_conf.json().get("data", {}))

            # 2. Update all modules for scope
            if scope not in modules_config:
                modules_config[scope] = {}
            for m in ALL_MODULE_IDS:
                modules_config[scope][m] = enabled

            # 3. Build XML and send PUT
            xml_data = _build_agent_conf_xml(modules_config)
            xml_headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/xml"}
            r_put = await client.put(f"{base}/groups/default/configuration", headers=xml_headers, content=xml_data)
            if not r_put.is_success:
                raise HTTPException(status_code=500, detail=f"Error actualizando agent.conf: {r_put.text}")

            # 4. Restart agents
            if scope == "global" or scope == "000":
                await client.put(f"{base}/agents/restart", headers=headers)
            else:
                await client.put(f"{base}/agents/restart?agents_list={scope}", headers=headers)

            return {
                "ok": True,
                "scope": scope,
                "enabled": enabled,
                "modules_config": modules_config,
                "message": f"Todos los apartados fueron {'activados' if enabled else 'desactivados'} para {scope}.",
            }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/v1/dashboard/wazuh/modules/apply")
async def apply_wazuh_modules_config(request: Request, _: None = Depends(verify_write)):
    from ..infrastructure.notifier import _get_token
    from ..config import settings
    import httpx

    body = await request.json()
    scope = body.get("scope", "global")
    modules = body.get("modules", {})
    if not isinstance(modules, dict):
        raise HTTPException(status_code=400, detail="modules dict required")

    host = (settings.wazuh_manager_host or settings.wazuh_server_ip)
    if not host or not settings.wazuh_manager_api_pass:
        raise HTTPException(status_code=500, detail="Wazuh API no configurada")

    base = f"https://{host}:{settings.wazuh_manager_api_port}"
    verify = settings.wazuh_manager_api_verify_tls

    try:
        async with httpx.AsyncClient(timeout=15, verify=verify) as client:
            token = await _get_token(client)
            if not token:
                raise HTTPException(status_code=500, detail="Error de autenticación con Wazuh API")

            headers = {"Authorization": f"Bearer {token}"}

            # 1. Read existing config
            r_conf = await client.get(f"{base}/groups/default/configuration", headers=headers)
            modules_config = {"global": dict(DEFAULT_STATE)}
            if r_conf.is_success:
                modules_config = _parse_agent_conf_response(r_conf.json().get("data", {}))

            # 2. Update config for scope
            if scope not in modules_config:
                modules_config[scope] = dict(modules_config.get("global", DEFAULT_STATE))

            for m_key, m_val in modules.items():
                modules_config[scope][m_key] = bool(m_val)

            # 3. Build XML and send PUT
            xml_data = _build_agent_conf_xml(modules_config)
            xml_headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/xml"}
            r_put = await client.put(f"{base}/groups/default/configuration", headers=xml_headers, content=xml_data)
            if not r_put.is_success:
                raise HTTPException(status_code=500, detail=f"Error actualizando agent.conf: {r_put.text}")

            # 4. Restart agents
            restarted_agents = []
            if scope == "global" or scope == "000":
                r_rst = await client.put(f"{base}/agents/restart", headers=headers)
                if r_rst.is_success:
                    restarted_agents = r_rst.json().get("data", {}).get("affected_items", ["all"])
            else:
                r_rst = await client.put(f"{base}/agents/restart?agents_list={scope}", headers=headers)
                if r_rst.is_success:
                    restarted_agents = r_rst.json().get("data", {}).get("affected_items", [scope])

            log.info("wazuh_modules_applied scope=%s modules=%s user_ip=%s",
                     scope, modules, request.client.host if request.client else "?")

            return {
                "ok": True,
                "scope": scope,
                "modules_config": modules_config,
                "xml": xml_data,
                "restarted_agents": restarted_agents,
                "message": f"Configuración guardada en agent.conf y reinicio aplicado a {scope}.",
            }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



