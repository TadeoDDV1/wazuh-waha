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
    
    # Autenticación / Logins
    if (
        rule_id in ("5710", "5712", "5715", "5401", "57120", "57123", "57124", "57131", "57132")
        or (rule_id.isdigit() and 57100 <= int(rule_id) <= 57106)
    ):
        groups.append("authentication_success")
    
    # Integridad de archivos (Syscheck / FIM: 550 nuevo, 553 modificado, 554 eliminado, 57125, 57129)
    if rule_id in ("550", "553", "554", "57125", "57129"):
        groups.append("fim")
    
    # Archivos SUID / SGID
    if rule_id == "520":
        groups.append("suid")
    
    # Detección de Vulnerabilidades (CVEs: 57107-57110)
    if rule_id.isdigit() and 57107 <= int(rule_id) <= 57110:
        groups.append("vulnerability_detector")
    
    # Amenazas de Red, Escaneos y Probes
    if rule_id in ("2902", "2903", "57128", "57133", "57134", "57135", "57139"):
        groups.append("network_threats")
        groups.append("threat_hunting")

    # Reverse Shells y Comandos Sospechosos
    if rule_id in ("57121", "57122", "57138", "57140"):
        groups.append("threat_hunting")
    
    # Eventos de Salud WAHA y Sistema
    if rule_id in ("999001", "57126", "57127", "57130"):
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


def _append_remediation(msg: str, enriched: dict | None) -> str:
    """Añade una sección breve de acciones al mensaje de notificación."""
    if not msg or not enriched:
        return msg
    enrichment = enriched.get("enrichment") or {}
    steps = enrichment.get("remediation") or []
    if not steps:
        return msg
    lines = ["", "🧭 *¿Qué hacer?*"]
    for idx, step in enumerate(steps[:2], start=1):
        action = str(step.get("action") or "").strip()
        if action:
            lines.append(f"{idx}. {action}")
    return msg + "\n".join(lines)


async def format_alert(alert: dict, enriched: dict | None = None) -> tuple[str, dict]:
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

    # Verificar si la regla individual está silenciada
    if overrides.get(f"muted_rule:{rule_id}") is True:
        meta["decision"] = f"muted_rule:{rule_id}"
        return ("", meta)

    src_ip = templates.extract_clean_ip(alert)
    user = templates.extract_clean_user(alert)

    # Silenciar logins rutinarios del host de monitoreo local (192.168.122.1 o localhost)
    if rule_id in ("57100", "57101", "5501", "5502") and src_ip in ("192.168.122.1", "127.0.0.1", "127.0.0.1 (Local)", "🏠 Local / Consola"):
        if user in ("tadeou7", "wazuh", "soc", "No especificado"):
            meta["decision"] = "internal_telemetry_login"
            return ("", meta)

    # Se genera primero el mensaje: si la regla no produce notificación
    # (por umbral, etc.) no debe consumir una reserva de deduplicación.
    msg = templates.render(rule_id, alert)
    if msg:
        meta["decision"] = "template"
    elif level < settings.relay_min_level_unknown:
        meta["decision"] = "below_threshold"
        return ("", meta)
    else:
        meta["decision"] = "default"
        msg = templates.render_default(alert)

    if enriched:
        enrichment = enriched.get("enrichment") or {}
        translations = enrichment.get("translations") or {}
        risk = enrichment.get("risk") or {}
        meta["enrichment"] = {
            "summary_es": translations.get("summary_es"),
            "description_es": translations.get("description_es"),
            "plain_severity": risk.get("plain_severity"),
            "degraded": bool(enrichment.get("degraded")),
        }
        msg = _append_remediation(msg, enriched)

    # Reserva atómica: evita que dos workers envíen la misma alerta a la vez.
    # alerts.py libera la reserva si el envío falla por completo.
    if not deduper.claim(rule_id, agent_id, key_extra=src_ip):
        meta["decision"] = "duplicate"
        return ("", meta)
    meta["dedup_claimed"] = True
    meta["dedup_key"] = {"rule_id": rule_id, "agent_id": agent_id, "key_extra": src_ip}

    return (msg, meta)

