import time

from . import templates
from ..config import load_overrides, settings
from .dedup import deduper


def get_rule_group(rule_id: str) -> str:
    """Mapea un rule_id a su grupo de reglas configurable en el dashboard."""
    if not rule_id:
        return "default"
    
    # Autenticación / Logins (5710 SSH fallido, 5712 múltiple, 5715 su, 5401 sudo, 57100-57106 logins)
    if rule_id in ("5710", "5712", "5715", "5401"):
        return "authentication_success"
    if rule_id.isdigit() and 57100 <= int(rule_id) <= 57106:
        return "authentication_success"
    
    # Integridad de archivos (Syscheck / FIM: 550 nuevo, 553 modificado, 554 eliminado)
    if rule_id in ("550", "553", "554"):
        return "fim"
    
    # Archivos SUID / SGID
    if rule_id == "520":
        return "suid"
    
    # Detección de Vulnerabilidades (CVEs: 57107-57110)
    if rule_id.isdigit() and 57107 <= int(rule_id) <= 57110:
        return "vulnerability_detector"
    
    # Amenazas de Red y Descargas (2902, 2903)
    if rule_id in ("2902", "2903"):
        return "network_threats"
    
    # Eventos de Salud WAHA
    if rule_id == "999001":
        return "waha_health"
    
    # Active Response
    if rule_id.isdigit() and 60000 <= int(rule_id) <= 60500:
        return "active_response"
    
    # SCA, Rootcheck, Syscollector
    if rule_id.startswith("501") or rule_id.startswith("502"):
        return "sca"
    if rule_id.startswith("510"):
        return "rootcheck"
    if rule_id.startswith("505"):
        return "syscollector"
    
    return "default"


async def format_alert(alert: dict) -> tuple[str, dict]:
    rule = alert.get("rule", {}) or {}
    agent = alert.get("agent", {}) or {}
    rule_id = str(rule.get("id", "0"))
    agent_id = str(agent.get("id", "0"))
    level = int(rule.get("level", 0))

    rule_group = get_rule_group(rule_id)

    meta = {
        "rule_id": rule_id,
        "rule_group": rule_group,
        "agent_id": agent_id,
        "agent_name": agent.get("name"),
        "level": level,
        "ts": time.time(),
    }

    # Verificar si el grupo de reglas está deshabilitado por toggle en el dashboard
    overrides = load_overrides()
    if rule_group != "default" and overrides.get(f"rule_group:{rule_group}") is False:
        meta["decision"] = f"muted_rule_group:{rule_group}"
        return ("", meta)

    if deduper.is_duplicate(rule_id, agent_id):
        meta["decision"] = "duplicate"
        return ("", meta)
    deduper.mark(rule_id, agent_id)

    msg = templates.render(rule_id, alert)
    if msg:
        meta["decision"] = "template"
        return (msg, meta)

    if level < settings.relay_min_level_unknown:
        meta["decision"] = "below_threshold"
        return ("", meta)

    meta["decision"] = "default"
    return (templates.render_default(alert), meta)

