"""
Orquesta el flujo: dedup -> template -> default.
Ollama/IA queda DESACTIVADO por ahora (ver ollama_client.py y docs/ollama.md).
Devuelve (mensaje_final, metadata).
"""
import time

from . import templates
from .config import settings
from .dedup import deduper


async def format_alert(alert: dict) -> tuple[str, dict]:
    rule = alert.get("rule", {}) or {}
    agent = alert.get("agent", {}) or {}
    rule_id = str(rule.get("id", "0"))
    agent_id = str(agent.get("id", "0"))
    level = int(rule.get("level", 0))

    meta = {
        "rule_id": rule_id,
        "agent_id": agent_id,
        "agent_name": agent.get("name"),
        "level": level,
        "ts": time.time(),
    }

    # 1) Dedupe
    if deduper.is_duplicate(rule_id, agent_id):
        meta["decision"] = "duplicate"
        return ("", meta)
    deduper.mark(rule_id, agent_id)

    # 2) Plantilla especifica por rule_id (rapido, sin IA)
    msg = templates.render(rule_id, alert)
    if msg:
        meta["decision"] = "template"
        return (msg, meta)

    # 3) Sin template y level bajo el minimo → descartar
    if level < settings.relay_min_level_unknown:
        meta["decision"] = "below_threshold"
        return ("", meta)

    # 4) Plantilla generica (sin IA, sin red)
    meta["decision"] = "default"
    return (templates.render_default(alert), meta)
