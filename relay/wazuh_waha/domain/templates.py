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
    # --- Nuevas reglas de seguridad avanzadas (57120 - 57130) ---
    "57120": lambda a: (
        f"🚨 *Ataque de fuerza bruta SSH persistente* (CRÍTICO)\n"
        f"Agente: `{_agent(a)}`\n"
        f"Origen: `{_field(a, 'srcip')}`\n"
        f"Detección: `Más de 10 intentos fallidos de login en 2 minutos`\n"
        f"Hora: `{a.get('timestamp', '?')}`\n"
        f"⚠️ Se recomienda bloqueo preventivo de IP."
    ),
    "57121": lambda a: (
        f"🚨 *Ejecución remota sospechosa por tubería* (CRÍTICO)\n"
        f"Agente: `{_agent(a)}`\n"
        f"Usuario: `{_field(a, 'dstuser', default='?')}`\n"
        f"Comando detectado: `{_field(a, 'command', default=_field(a, 'full_log', default='?'))[:140]}`\n"
        f"Hora: `{a.get('timestamp', '?')}`\n"
        f"⚠️ Posible ejecución de script externo o payload en memoria."
    ),
    "57122": lambda a: (
        f"⚠️ *Ejecución de binario/script en carpeta temporal*\n"
        f"Agente: `{_agent(a)}`\n"
        f"Usuario: `{_field(a, 'dstuser', default='?')}`\n"
        f"Comando: `{_field(a, 'command', default='?')[:120]}`\n"
        f"Directorio: `{_field(a, 'pwd', default='?')}`\n"
        f"Hora: `{a.get('timestamp', '?')}`"
    ),
    "57123": lambda a: (
        f"⛔ *Violación de seguridad: Usuario no autorizado en sudoers*\n"
        f"Agente: `{_agent(a)}`\n"
        f"Usuario infractor: `{_field(a, 'srcuser', default=_field(a, 'dstuser', default='?'))}`\n"
        f"Log: `{translate_full_log_es(a.get('full_log', ''))[:160]}`\n"
        f"Hora: `{a.get('timestamp', '?')}`"
    ),
    "57124": lambda a: (
        f"🚨 *Intentos reiterados de login como ROOT por SSH*\n"
        f"Agente: `{_agent(a)}`\n"
        f"Origen: `{_field(a, 'srcip')}`\n"
        f"Log: `{translate_full_log_es(a.get('full_log', ''))[:160]}`\n"
        f"Hora: `{a.get('timestamp', '?')}`"
    ),
    "57125": lambda a: (
        f"🚨 *Modificación de archivo crítico del sistema (/etc/shadow, passwd, sudoers)* (CRÍTICO)\n"
        f"Agente: `{_agent(a)}`\n"
        f"Archivo: `{_field(a, 'path', default=_field(a, 'file', default='?'))}`\n"
        f"Log FIM: `{translate_full_log_es(a.get('full_log', ''))[:160]}`\n"
        f"Hora: `{a.get('timestamp', '?')}`\n"
        f"⚠️ Verificación urgente de integridad requerida."
    ),
    "57126": lambda a: (
        f"🛑 *Detención de servicio crítico del sistema (Wazuh / SSH / Firewall)*\n"
        f"Agente: `{_agent(a)}`\n"
        f"Detalle: `{translate_full_log_es(a.get('full_log', ''))[:160]}`\n"
        f"Hora: `{a.get('timestamp', '?')}`"
    ),
    "57127": lambda a: (
        f"🔥 *Kernel OOM Killer activado (Memoria RAM agotada)*\n"
        f"Agente: `{_agent(a)}`\n"
        f"Detalle: `{translate_full_log_es(a.get('full_log', ''))[:160]}`\n"
        f"Hora: `{a.get('timestamp', '?')}`"
    ),
    "57128": lambda a: (
        f"🛡️ *Escaneo de puertos detectado / bloqueado por Firewall*\n"
        f"Agente: `{_agent(a)}`\n"
        f"Origen: `{_field(a, 'srcip')}`\n"
        f"Log: `{a.get('full_log', '')[:160]}`\n"
        f"Hora: `{a.get('timestamp', '?')}`"
    ),
    "57129": lambda a: (
        f"🔑 *Modificación en authorized_keys (Llaves SSH de acceso)*\n"
        f"Agente: `{_agent(a)}`\n"
        f"Archivo: `{_field(a, 'path', default=_field(a, 'file', default='?'))}`\n"
        f"Hora: `{a.get('timestamp', '?')}`\n"
        f"⚠️ Verificar si se añadieron llaves públicas no autorizadas."
    ),
    "57130": lambda a: (
        f"🐳 *Contenedor Docker detenido o en fallo de ejecución*\n"
        f"Agente: `{_agent(a)}`\n"
        f"Log: `{translate_full_log_es(a.get('full_log', ''))[:160]}`\n"
        f"Hora: `{a.get('timestamp', '?')}`"
    ),
}


_COMMON_TRANSLATIONS = [
    # SSH & Autenticación
    ("sshd: Authentication failed", "Fallo de autenticación por SSH"),
    ("sshd: Insecure connection attempt", "Intento de conexión SSH insegura"),
    ("sshd: Attempt to login using a non-existent user", "Intento de login SSH con usuario inexistente"),
    ("Multiple failed logins from the same source", "Múltiples logins fallidos desde la misma IP (Fuerza bruta)"),
    ("Maximum number of failed login attempts exceeded", "Límite máximo de logins fallidos superado"),
    ("System user successfully logged in", "Inicio de sesión de usuario del sistema exitoso"),
    ("SSH login exitoso con clave publica", "Login SSH exitoso con clave pública"),
    ("SSH login exitoso como root (CRITICO)", "Login SSH exitoso como root (CRÍTICO)"),
    ("SSH login exitoso", "Login SSH exitoso"),
    ("Accepted password", "Contraseña SSH aceptada con éxito"),
    ("Accepted publickey", "Login SSH aceptado con clave pública"),
    ("Failed password", "Contraseña incorrecta"),
    ("Invalid user", "Usuario inexistente o inválido"),
    ("Connection closed by", "Conexión cerrada por"),
    ("Disconnected from", "Desconectado de"),

    # FIM (Integridad de archivos)
    ("Integrity checksum changed", "Integridad de archivo alterada (FIM)"),
    ("File added to the system", "Nuevo archivo añadido al sistema (FIM)"),
    ("File deleted from the system", "Archivo eliminado del sistema (FIM)"),
    ("File deleted", "Archivo eliminado del sistema (FIM)"),
    ("File modified", "Archivo modificado en el sistema (FIM)"),
    ("Size changed", "Tamaño de archivo modificado"),
    ("Permissions changed", "Permisos de archivo alterados"),
    ("Ownership changed", "Propietario de archivo alterado"),

    # PAM / Sudo / Sesiones
    ("PAM: User login failed", "PAM: Error de inicio de sesión"),
    ("PAM: Login session opened", "PAM: Sesión abierta en el sistema"),
    ("PAM: Login session closed", "PAM: Sesión cerrada en el sistema"),
    ("Sudo command executed", "Comando ejecutado mediante sudo"),
    ("User not in sudoers", "Usuario no autorizado en sudoers"),
    ("Cambio de usuario (su) exitoso", "Cambio de usuario (su) exitoso"),
    ("Comando sudo ejecutado con exito", "Comando sudo ejecutado con éxito"),
    ("Login local (TTY/consola) exitoso", "Login local (TTY/consola) exitoso"),
    ("Logout / sesion cerrada", "Logout / sesión cerrada"),

    # Servicios y Kernel
    ("Service was started", "Servicio del sistema iniciado"),
    ("Service was stopped", "Servicio del sistema detenido"),
    ("Out of memory: Killed process", "Memoria RAM agotada (OOM Killer activado)"),
    ("invoked oom-killer", "OOM-Killer activado por el Kernel"),
    ("Host-based anomaly detection event", "Anomalía detectada en el host (Rootcheck)"),
    ("Trojaned version of file detected", "Versión troyanizada de archivo detectada"),
    ("Rootkit detected", "Rootkit detectado en el sistema"),

    # Vulnerability Detector
    ("High severity vulnerability", "Vulnerabilidad de seguridad de nivel ALTO"),
    ("Critical severity vulnerability", "Vulnerabilidad de seguridad de nivel CRÍTICO"),
    ("Medium severity vulnerability", "Vulnerabilidad de seguridad de nivel MEDIO"),
    ("Low severity vulnerability", "Vulnerabilidad de seguridad de nivel BAJO"),
    ("Vulnerability detected", "Vulnerabilidad detectada en el equipo"),
    ("Vulnerabilidad MEDIA detectada", "Vulnerabilidad MEDIA detectada"),
    ("Vulnerabilidad BAJA detectada", "Vulnerabilidad BAJA detectada"),
    ("Vulnerabilidad resuelta", "Vulnerabilidad resuelta"),
    ("Vulnerabilidades limpiadas", "Vulnerabilidades limpiadas"),
    ("Package database changed", "Base de datos de paquetes del sistema modificada"),

    # Red y Firewall
    ("UFW BLOCK", "Bloqueo por cortafuegos UFW"),
    ("iptables denied", "Conexión rechazada por IPTables"),
    ("connection refused", "Conexión rechazada"),

    # Infraestructura y Health
    ("Active response", "Respuesta Activa ejecutada"),
    ("WAHA session", "Evento de salud de la sesión WhatsApp (WAHA)"),
    ("wazuh-agent", "Evento de estado del Agente Wazuh"),
    ("wazuh-waha", "Evento de estado del Relay Wazuh-WAHA"),
]


def translate_full_log_es(log_text: str) -> str:
    """Traduce patrones comunes en los logs de auditoría de Wazuh y Linux a español legible."""
    if not log_text:
        return ""

    import re
    res = log_text
    patterns = [
        # PAM
        (r"pam_unix\(([^:]+):session\): session opened for user (\w+) by \(uid=(\d+)\)", r"PAM (\1): sesión abierta para el usuario \2 por (uid=\3)"),
        (r"pam_unix\(([^:]+):session\): session opened for user (\w+)", r"PAM (\1): sesión iniciada para el usuario \2"),
        (r"pam_unix\(([^:]+):session\): session closed for user (\w+)", r"PAM (\1): sesión cerrada para el usuario \2"),
        # SSH
        (r"Accepted password for (\w+) from ([\d\.]+) port (\d+) ssh2", r"Contraseña aceptada para \1 desde \2 puerto \3 (SSH2)"),
        (r"Accepted publickey for (\w+) from ([\d\.]+) port (\d+) ssh2", r"Clave pública aceptada para \1 desde \2 puerto \3 (SSH2)"),
        (r"Failed password for invalid user (\w+) from ([\d\.]+) port (\d+) ssh2", r"Contraseña incorrecta para usuario inexistente \1 desde \2 (SSH)"),
        (r"Failed password for (\w+) from ([\d\.]+) port (\d+) ssh2", r"Contraseña incorrecta para \1 desde \2 (SSH)"),
        (r"Invalid user (\w+) from ([\d\.]+)", r"Usuario inválido \1 desde \2"),
        (r"Received disconnect from ([\d\.]+)", r"Desconexión recibida desde \1"),
        (r"Disconnected from user (\w+) ([\d\.]+)", r"Desconectado del usuario \1 (\2)"),
        (r"Connection closed by ([\d\.]+)", r"Conexión cerrada por \1"),
        # Sudo
        (r"COMMAND=(.*)", r"COMANDO=\1"),
        (r"USER=root", r"USUARIO=root"),
        (r"PWD=([^\s;]+)", r"DIR=\1"),
        # FIM
        (r"Integrity checksum changed for: '([^']+)'", r"Integridad modificada para: '\1'"),
        (r"File added to the system: '([^']+)'", r"Archivo nuevo en el sistema: '\1'"),
        (r"File deleted from the system: '([^']+)'", r"Archivo eliminado del sistema: '\1'"),
        (r"Mode: realtime", r"Modo: tiempo real"),
        (r"Changed attributes: (.*)", r"Atributos modificados: \1"),
        (r"Size changed from (\d+) to (\d+)", r"Tamaño cambió de \1 a \2 bytes"),
        # Kernel / Servicios
        (r"Out of memory: Killed process (\d+) \(([^)]+)\)", r"Memoria RAM agotada: Proceso terminado \1 (\2)"),
        (r"invoked oom-killer: (.*)", r"OOM-Killer activado por Kernel: \1"),
        (r"Stopped (.*)\.", r"Servicio detenido: \1."),
        (r"Started (.*)\.", r"Servicio iniciado: \1."),
    ]

    for p, repl in patterns:
        res = re.sub(p, repl, res, flags=re.IGNORECASE)

    return res


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
    raw_log = alert.get("full_log", "") or ""
    log_es = translate_full_log_es(raw_log)

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
    if log_es:
        lines.append(f"📝 *Detalle:* `{log_es[:140]}`")
    lines.append(f"⏰ *Hora:* `{timestamp}`")
    return "\n".join(lines)

