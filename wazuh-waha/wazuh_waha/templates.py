
"""
Plantillas de mensaje preprogramadas por rule_id de Wazuh.
Si el rule_id matchea, se usa esta plantilla (cero IA, cero latencia).
Si no matchea, cae a IA o a _default.
"""
from typing import Callable

TemplateFn = Callable[[dict], str]


def _agent(alert: dict) -> str:
    a = alert.get("agent", {}) or {}
    return a.get("name", a.get("id", "unknown"))


def _field(alert: dict, *path: str, default: str = "?") -> str:
    """Busca recursivamente en data/agent/full_log."""
    candidates = [alert.get("data", {}) or {}, alert.get("agent", {}) or {}]
    for root in candidates:
        cur = root
        for k in path:
            if not isinstance(cur, dict):
                cur = None
                break
            cur = cur.get(k)
        if cur is not None:
            return str(cur)
    # fallback a full_log
    log = alert.get("full_log", "") or ""
    return log[:80] + ("..." if len(log) > 80 else "")


# Mapa: rule_id -> funcion que arma el mensaje
TEMPLATES: dict[str, TemplateFn] = {
    # --- SSH / auth ---
    "5710": lambda a: (
        f"🔐 *SSH fallido*\n"
        f"Agente: `{_agent(a)}`\n"
        f"Origen: `{_field(a, 'srcip')}`\n"
        f"Usuario: `{_field(a, 'dstuser', default='?')}`"
    ),
    "5712": lambda a: (
        f"🔐 *Multiples SSH fallidos*\n"
        f"Agente: `{_agent(a)}`\n"
        f"Origen: `{_field(a, 'srcip')}`"
    ),
    "5715": lambda a: (
        f"🔐 *su fallido*\n"
        f"Agente: `{_agent(a)}`\n"
        f"Usuario: `{_field(a, 'dstuser', default='?')}`"
    ),
    "5401": lambda a: (
        f"🔐 *sudo fallido*\n"
        f"Agente: `{_agent(a)}`"
    ),

    # --- FIM (File Integrity Monitoring) ---
    "550": lambda a: (
        f"📁 *Archivo nuevo*\n"
        f"Agente: `{_agent(a)}`\n"
        f"Path: `{_field(a, 'path', default=_field(a, 'file', default='?'))}`"
    ),
    "553": lambda a: (
        f"✏️ *Archivo modificado*\n"
        f"Agente: `{_agent(a)}`\n"
        f"Path: `{_field(a, 'path', default=_field(a, 'file', default='?'))}`"
    ),
    "554": lambda a: (
        f"🗑️ *Archivo eliminado*\n"
        f"Agente: `{_agent(a)}`\n"
        f"Path: `{_field(a, 'path', default=_field(a, 'file', default='?'))}`"
    ),

    # --- Permisos / SUID ---
    "520": lambda a: (
        f"⚠️ *Binario SUID*\n"
        f"Agente: `{_agent(a)}`\n"
        f"Path: `{_field(a, 'path', default='?')}`"
    ),

    # --- Web / Descargas ---
    "2902": lambda a: (
        f"🌐 *Descarga web*\n"
        f"Agente: `{_agent(a)}`\n"
        f"URL: `{_field(a, 'url')}`"
    ),
    "2903": lambda a: (
        f"🌐 *Descarga sospechosa*\n"
        f"Agente: `{_agent(a)}`\n"
        f"URL: `{_field(a, 'url')}`"
    ),

    # --- Login exitoso (reglas custom 57100-57106) ---
    "57100": lambda a: (
        f"✅ *Login SSH exitoso*\n"
        f"Agente: `{_agent(a)}`\n"
        f"Usuario: `{_field(a, 'dstuser', default='?')}`\n"
        f"Origen: `{_field(a, 'srcip', default='local')}`\n"
        f"Hora: `{a.get('timestamp', '?')}`"
    ),
    "57101": lambda a: (
        f"🔑 *Login SSH con clave publica*\n"
        f"Agente: `{_agent(a)}`\n"
        f"Usuario: `{_field(a, 'dstuser', default='?')}`\n"
        f"Origen: `{_field(a, 'srcip', default='local')}`\n"
        f"Hora: `{a.get('timestamp', '?')}`"
    ),
    "57102": lambda a: (
        f"🚨 *ROOT LOGIN por SSH* (CRITICO)\n"
        f"Agente: `{_agent(a)}`\n"
        f"Origen: `{_field(a, 'srcip', default='local')}`\n"
        f"Hora: `{a.get('timestamp', '?')}`\n"
        f"⚠️ Verificar si este acceso era esperado"
    ),
    "57103": lambda a: (
        f"🔄 *Cambio de usuario (su) exitoso*\n"
        f"Agente: `{_agent(a)}`\n"
        f"Usuario destino: `{_field(a, 'dstuser', default='?')}`\n"
        f"Hora: `{a.get('timestamp', '?')}`"
    ),
    "57104": lambda a: (
        f"🔑 *Comando sudo ejecutado*\n"
        f"Agente: `{_agent(a)}`\n"
        f"Usuario: `{_field(a, 'dstuser', default='?')}`\n"
        f"Comando: `{_field(a, 'command', default='?')[:120]}`\n"
        f"Hora: `{a.get('timestamp', '?')}`"
    ),
    "57105": lambda a: (
        f"🖥️ *Login local (TTY/consola)*\n"
        f"Agente: `{_agent(a)}`\n"
        f"Usuario: `{_field(a, 'dstuser', default='?')}`\n"
        f"TTY: `{_field(a, 'tty', default='?')}`\n"
        f"Hora: `{a.get('timestamp', '?')}`"
    ),
    "57106": lambda a: (
        f"👋 *Logout / sesion cerrada*\n"
        f"Agente: `{_agent(a)}`\n"
        f"Usuario: `{_field(a, 'dstuser', default='?')}`\n"
        f"Hora: `{a.get('timestamp', '?')}`"
    ),
}


def render(rule_id: str, alert: dict) -> str | None:
    """Devuelve mensaje formateado o None si no hay plantilla para esta regla."""
    fn = TEMPLATES.get(str(rule_id))
    if fn is None:
        return None
    try:
        return fn(alert)
    except Exception:
        return None


def render_default(alert: dict) -> str:
    """Plantilla generica para alertas sin rule_id templatado (sin IA)."""
    return (
        f"🚨 *Alerta Wazuh*\n"
        f"Regla: `{alert.get('rule', {}).get('id', '?')} - "
        f"{alert.get('rule', {}).get('description', '?')}`\n"
        f"Nivel: `{alert.get('rule', {}).get('level', '?')}`\n"
        f"Agente: `{_agent(alert)}`\n"
        f"Hora: `{alert.get('timestamp', '?')}`"
    )
