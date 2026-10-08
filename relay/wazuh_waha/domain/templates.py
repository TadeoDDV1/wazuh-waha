from typing import Callable

TemplateFn = Callable[[dict], str]


def _agent(alert: dict) -> str:
    a = alert.get("agent", {}) or {}
    return a.get("name", a.get("id", "unknown"))


def _field(alert: dict, *path: str, default: str = "?") -> str:
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
    log = alert.get("full_log", "") or ""
    return log[:80] + ("..." if len(log) > 80 else "")


def _vuln(alert: dict, *path: str, default: str = "?") -> str:
    vuln = alert.get("data", {}).get("vulnerability") or {}
    cur = vuln
    for k in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k, default)
    return str(cur) if cur is not None else default


def _cvss(alert: dict, version: str = "cvss3", default: str = "?") -> str:
    return _vuln(alert, "cvss", version, "base_score", default=default)


TEMPLATES: dict[str, TemplateFn] = {
    # --- Seguridad existente ---
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
    "520": lambda a: (
        f"⚠️ *Binario SUID*\n"
        f"Agente: `{_agent(a)}`\n"
        f"Path: `{_field(a, 'path', default='?')}`"
    ),
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
    # --- Login exitoso (custom) ---
    "57100": lambda a: (
        f"✅ *Login SSH exitoso*\n"
        f"Agente: `{_agent(a)}`\n"
        f"Usuario: `{_field(a, 'dstuser', default='?')}`\n"
        f"Origen: `{_field(a, 'srcip', default='local')}:{_field(a, 'srcport', default='?')}`\n"
        f"Proceso: `{_field(a, 'program_name', default='sshd')}`\n"
        f"Ubicacion: `{a.get('location', '?')}`\n"
        f"Log: `{a.get('full_log', '')[:160]}`\n"
        f"Hora: `{a.get('timestamp', '?')}`"
    ),
    "57101": lambda a: (
        f"🔑 *Login SSH con clave publica*\n"
        f"Agente: `{_agent(a)}`\n"
        f"Usuario: `{_field(a, 'dstuser', default='?')}`\n"
        f"Origen: `{_field(a, 'srcip', default='local')}:{_field(a, 'srcport', default='?')}`\n"
        f"Proceso: `{_field(a, 'program_name', default='sshd')}`\n"
        f"Ubicacion: `{a.get('location', '?')}`\n"
        f"Log: `{a.get('full_log', '')[:160]}`\n"
        f"Hora: `{a.get('timestamp', '?')}`"
    ),
    "57102": lambda a: (
        f"🚨 *ROOT LOGIN por SSH* (CRITICO)\n"
        f"Agente: `{_agent(a)}`\n"
        f"Origen: `{_field(a, 'srcip', default='local')}:{_field(a, 'srcport', default='?')}`\n"
        f"Proceso: `{_field(a, 'program_name', default='sshd')}`\n"
        f"Ubicacion: `{a.get('location', '?')}`\n"
        f"Log: `{a.get('full_log', '')[:160]}`\n"
        f"Hora: `{a.get('timestamp', '?')}`\n"
        f"⚠️ Verificar si este acceso era esperado"
    ),
    "57103": lambda a: (
        f"🔄 *Cambio de usuario (su) exitoso*\n"
        f"Agente: `{_agent(a)}`\n"
        f"Usuario origen: `{_field(a, 'srcuser', default='?')}`\n"
        f"Usuario destino: `{_field(a, 'dstuser', default='?')}`\n"
        f"Proceso: `{_field(a, 'program_name', default='su')}`\n"
        f"Log: `{a.get('full_log', '')[:160]}`\n"
        f"Hora: `{a.get('timestamp', '?')}`"
    ),
    "57104": lambda a: (
        f"🔑 *Comando sudo ejecutado*\n"
        f"Agente: `{_agent(a)}`\n"
        f"Usuario: `{_field(a, 'dstuser', default='?')}`\n"
        f"Comando: `{_field(a, 'command', default='?')[:120]}`\n"
        f"Directorio: `{_field(a, 'pwd', default='?')}`\n"
        f"TTY: `{_field(a, 'tty', default='?')}`\n"
        f"Proceso: `{_field(a, 'program_name', default='sudo')}`\n"
        f"Hora: `{a.get('timestamp', '?')}`"
    ),
    "57105": lambda a: (
        f"🖥️ *Login local (TTY/consola)*\n"
        f"Agente: `{_agent(a)}`\n"
        f"Usuario: `{_field(a, 'dstuser', default='?')}`\n"
        f"TTY: `{_field(a, 'tty', default='?')}`\n"
        f"Proceso: `{_field(a, 'program_name', default='?')}`\n"
        f"Ubicacion: `{a.get('location', '?')}`\n"
        f"Log: `{a.get('full_log', '')[:160]}`\n"
        f"Hora: `{a.get('timestamp', '?')}`"
    ),
    "57106": lambda a: (
        f"👋 *Logout / sesion cerrada*\n"
        f"Agente: `{_agent(a)}`\n"
        f"Usuario: `{_field(a, 'dstuser', default='?')}`\n"
        f"Proceso: `{_field(a, 'program_name', default='?')}`\n"
        f"Duracion: `{_field(a, 'session_time', default='?')}`\n"
        f"Log: `{a.get('full_log', '')[:160]}`\n"
        f"Hora: `{a.get('timestamp', '?')}`"
    ),
    # --- Vulnerability Detector ---
    "23505": lambda a: (
        f"🛡️ *Vulnerabilidad ALTA*\n"
        f"CVE: `{_vuln(a, 'cve')}`\n"
        f"Paquete: `{_vuln(a, 'package', 'name')} {_vuln(a, 'package', 'version')}`\n"
        f"Agente: `{_agent(a)}`\n"
        f"CVSS: `{_cvss(a, 'cvss3')} / {_cvss(a, 'cvss2')}`\n"
        f"Publicado: `{_vuln(a, 'published', default='?')[:10]}`"
    ),
    "23506": lambda a: (
        f"🚨 *Vulnerabilidad CRITICA*\n"
        f"CVE: `{_vuln(a, 'cve')}`\n"
        f"Paquete: `{_vuln(a, 'package', 'name')} {_vuln(a, 'package', 'version')}`\n"
        f"Agente: `{_agent(a)}`\n"
        f"CVSS: `{_cvss(a, 'cvss3')} / {_cvss(a, 'cvss2')}`\n"
        f"Severidad: `{_vuln(a, 'severity')}`\n"
        f"Publicado: `{_vuln(a, 'published', default='?')[:10]}`"
    ),
    "57107": lambda a: (
        f"🟡 *Vulnerabilidad MEDIA*\n"
        f"CVE: `{_vuln(a, 'cve')}`\n"
        f"Paquete: `{_vuln(a, 'package', 'name')} {_vuln(a, 'package', 'version')}`\n"
        f"Agente: `{_agent(a)}`\n"
        f"CVSS: `{_cvss(a, 'cvss3')} / {_cvss(a, 'cvss2')}`"
    ),
    "57108": lambda a: (
        f"🟢 *Vulnerabilidad BAJA*\n"
        f"CVE: `{_vuln(a, 'cve')}`\n"
        f"Paquete: `{_vuln(a, 'package', 'name')} {_vuln(a, 'package', 'version')}`\n"
        f"Agente: `{_agent(a)}`\n"
        f"CVSS: `{_cvss(a, 'cvss3')} / {_cvss(a, 'cvss2')}`"
    ),
    "57109": lambda a: (
        f"✅ *Vulnerabilidad RESUELTA*\n"
        f"CVE: `{_vuln(a, 'cve')}`\n"
        f"Paquete: `{_vuln(a, 'package', 'name')} {_vuln(a, 'package', 'version')}`\n"
        f"Agente: `{_agent(a)}`\n"
        f"Severidad: `{_vuln(a, 'severity')}`\n"
        f"CVSS: `{_cvss(a, 'cvss3')} / {_cvss(a, 'cvss2')}`"
    ),
    "57110": lambda a: (
        f"🧹 *Vulnerabilidades limpiadas*\n"
        f"Agente: `{_agent(a)}`\n"
        f"Se limpiaron todas las vulnerabilidades del inventario"
    ),
}


_COMMON_TRANSLATIONS = [
    ("sshd: Authentication failed", "Fallo de autenticación por SSH"),
    ("sshd: Insecure connection attempt", "Intento de conexión SSH insegura"),
    ("sshd: Attempt to login using a non-existent user", "Intento de login SSH con usuario inexistente"),
    ("Multiple failed logins from the same source", "Múltiples logins fallidos desde la misma IP"),
    ("Integrity checksum changed", "Integridad de archivo alterada (FIM)"),
    ("File added to the system", "Nuevo archivo añadido al sistema (FIM)"),
    ("File deleted", "Archivo eliminado del sistema (FIM)"),
    ("Host-based anomaly detection event", "Anomalía detectada en el host (Rootcheck)"),
    ("Maximum number of failed login attempts exceeded", "Límite máximo de logins fallidos superado"),
    ("System user successfully logged in", "Inicio de sesión de usuario del sistema exitoso"),
    ("PAM: User login failed", "PAM: Error de inicio de sesión"),
    ("PAM: Login session opened", "PAM: Sesión abierta en el sistema"),
    ("PAM: Login session closed", "PAM: Sesión cerrada en el sistema"),
    ("Sudo command executed", "Comando ejecutado mediante sudo"),
    ("Service was started", "Servicio del sistema iniciado"),
    ("Service was stopped", "Servicio del sistema detenido"),
    ("High severity vulnerability", "Vulnerabilidad de seguridad de nivel ALTO"),
    ("Critical severity vulnerability", "Vulnerabilidad de seguridad de nivel CRÍTICO"),
    ("Medium severity vulnerability", "Vulnerabilidad de seguridad de nivel MEDIO"),
    ("Low severity vulnerability", "Vulnerabilidad de seguridad de nivel BAJO"),
    ("Vulnerability detected", "Vulnerabilidad detectada en el equipo"),
    ("Package database changed", "Base de datos de paquetes del sistema modificada"),
    ("Active response", "Respuesta Activa ejecutada"),
    ("WAHA session", "Evento de salud de la sesión WhatsApp (WAHA)"),
    ("wazuh-agent", "Evento de estado del Agente Wazuh"),
    ("wazuh-waha", "Evento de estado del Relay Wazuh-WAHA"),
]


def _translate_description_es(desc: str) -> str:
    if not desc:
        return "Alerta de seguridad sin descripción"
    for eng, esp in _COMMON_TRANSLATIONS:
        if eng.lower() in desc.lower():
            return esp
    return desc


def _format_level_es(level: int | str) -> str:
    try:
        lvl = int(level)
    except Exception:
        lvl = 0
    if lvl >= 12:
        return f"[L{lvl}] 🔴 CRÍTICO"
    elif lvl >= 8:
        return f"[L{lvl}] 🟠 ALTO"
    elif lvl >= 4:
        return f"[L{lvl}] 🟡 MEDIO"
    return f"[L{lvl}] 🟢 BAJO"


def render(rule_id: str, alert: dict) -> str | None:
    fn = TEMPLATES.get(str(rule_id))
    if fn is None:
        return None
    try:
        return fn(alert)
    except Exception:
        return None


def render_default(alert: dict) -> str:
    rule = alert.get("rule", {}) or {}
    rule_id = rule.get("id", "?")
    raw_desc = rule.get("description", "?")
    desc_es = _translate_description_es(raw_desc)
    level = rule.get("level", 0)
    level_es = _format_level_es(level)
    agent = _agent(alert)
    timestamp = alert.get("timestamp", "?")
    src_ip = _field(alert, "srcip", default="")
    user = _field(alert, "dstuser", default="")

    lines = [
        "🚨 *ALERTA DE SEGURIDAD WAZUH*",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"📊 *Nivel:* {level_es}",
        f"🛡️ *Regla:* `#{rule_id}` - *{desc_es}*",
        f"🖥️ *Equipo / Agente:* `{agent}`",
    ]
    if src_ip and src_ip != "?":
        lines.append(f"🌐 *IP Origen:* `{src_ip}`")
    if user and user != "?":
        lines.append(f"👤 *Usuario:* `{user}`")
    lines.append(f"⏰ *Hora:* `{timestamp}`")
    return "\n".join(lines)

