import time

from . import templates
from ..config import load_overrides, settings
from .dedup import deduper


def get_rule_groups(rule: dict, rule_id: str) -> list[str]:
    """Mapea un rule_id y sus metadatos a grupos de reglas configurables en el dashboard."""
    groups = []

    # Cumplimiento y Normativas (Wazuh tags)
    if "pci_dss" in rule:
        groups.append("pci_dss")
    if "gdpr" in rule:
        groups.append("gdpr")
    if "hipaa" in rule:
        groups.append("hipaa")
    if "nist_800_53" in rule:
        groups.append("nist_800_53")
    if "tsc" in rule:
        groups.append("tsc")
    if "mitre" in rule:
        groups.append("mitre")

    if not rule_id:
        return groups or ["default"]
    
    # Autenticación / Logins (5710 SSH fallido, 5712 múltiple, 5715 su, 5401 sudo, 57100-57106 logins)
    if rule_id in ("5710", "5712", "5715", "5401") or (rule_id.isdigit() and 57100 <= int(rule_id) <= 57106):
        groups.append("authentication_success")
    
    # Integridad de archivos (Syscheck / FIM: 550 nuevo, 553 modificado, 554 eliminado)
    if rule_id in ("550", "553", "554"):
        groups.append("fim")
    
    # Archivos SUID / SGID
    if rule_id == "520":
        groups.append("suid")
    
    # Detección de Vulnerabilidades (CVEs: 57107-57110)
    if rule_id.isdigit() and 57107 <= int(rule_id) <= 57110:
        groups.append("vulnerability_detector")
    
    # Amenazas de Red y Descargas (2902, 2903)
    if rule_id in ("2902", "2903"):
        groups.append("network_threats")
        groups.append("threat_hunting")
    
    # Eventos de Salud WAHA
    if rule_id == "999001":
        groups.append("waha_health")
    
    # Active Response
    if rule_id.isdigit() and 60000 <= int(rule_id) <= 60500:
        groups.append("active_response")
    
    # SCA, Rootcheck, Syscollector
    if rule_id.startswith("501") or rule_id.startswith("502"):
        groups.append("sca")
    if rule_id.startswith("510"):
        groups.append("rootcheck")
    if rule_id.startswith("505"):
        groups.append("syscollector")
        groups.append("it_hygiene")
    
    return groups or ["default"]


async def format_alert(alert: dict) -> tuple[str, dict]:
    rule = alert.get("rule", {}) or {}
    agent = alert.get("agent", {}) or {}
    rule_id = str(rule.get("id", "0"))
    agent_id = str(agent.get("id", "0"))
    level = int(rule.get("level", 0))

    rule_groups = get_rule_groups(rule, rule_id)

    meta = {
        "rule_id": rule_id,
        "rule_groups": rule_groups,
        "agent_id": agent_id,
        "agent_name": agent.get("name"),
        "level": level,
        "ts": time.time(),
    }

    # Verificar si el grupo de reglas está deshabilitado por toggle en el dashboard
    overrides = load_overrides()
    for rg in rule_groups:
        if rg != "default" and overrides.get(f"rule_group:{rg}") is False:
            meta["decision"] = f"muted_rule_group:{rg}"
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

