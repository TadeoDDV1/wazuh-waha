import time
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


def render_soc_alert(
    alert: dict,
    title: str,
    fields: list[tuple[str, str]],
    recommendation: str = "",
    evidence: str = "",
) -> str:
    """Construye una tarjeta forense SOC con diseño estructurado, nivel de severidad y atajos rápidos."""
    rule = alert.get("rule", {}) or {}
    rule_id = str(rule.get("id", "0"))
    level = int(rule.get("level", 0))
    agent_obj = alert.get("agent", {}) or {}
    agent_name = agent_obj.get("name") or agent_obj.get("id") or "Servidor Local"
    agent_id = str(agent_obj.get("id", "000"))
    timestamp = alert.get("timestamp") or time.strftime("%Y-%m-%d %H:%M:%S")

    if level >= 15:
        level_badge = f"🚨 *[CRÍTICO • L{level}]*"
    elif level >= 12:
        level_badge = f"🟠 *[ALTO • L{level}]*"
    elif level >= 8:
        level_badge = f"🟡 *[MEDIO • L{level}]*"
    else:
        level_badge = f"🔵 *[INFO • L{level}]*"

    agent_suffix = f" _(ID: {agent_id})_" if agent_id and agent_id != "000" else ""
    lines = [
        level_badge,
        "━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"🛡️ *Regla #{rule_id}:* *{title}*",
        f"💻 *Equipo / Agente:* `{agent_name}`{agent_suffix}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━",
    ]

    for label, val in fields:
        if val and val != "?" and val != "None":
            lines.append(f"{label} `{val}`")

    if evidence and evidence != "?":
        cleaned_ev = translate_full_log_es(evidence)
        lines.append(f"📝 *Evidencia:* `{cleaned_ev[:150]}`")

    lines.append(f"⏰ *Hora:* `{timestamp}`")
    lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━")

    if recommendation:
        lines.append(f"💡 *Acción SOC:* {recommendation}\n")

    lines.append("⚡ *Acciones rápidas:*")
    lines.append(f"• Ficha forense: `/agente {agent_id}`")
    lines.append(f"• Reporte PDF: `/reporte {agent_id}`")
    lines.append(f"• Silenciar regla: `/silenciar {rule_id}`")

    return "\n".join(lines)


TEMPLATES: dict[str, TemplateFn] = {
    # --- Seguridad existente ---
    "5710": lambda a: render_soc_alert(
        a,
        title="SSH fallido (Autenticación rechazada)",
        fields=[
            ("🌐 Origen:", _field(a, "srcip")),
            ("👤 Usuario:", _field(a, "dstuser", default="?")),
            ("⚙️ Proceso:", _field(a, "program_name", default="sshd")),
        ],
        recommendation="Validar si la IP es conocida; bloquear temporalmente si los intentos continúan.",
        evidence=a.get("full_log", ""),
    ),
    "5712": lambda a: render_soc_alert(
        a,
        title="Múltiples fallos SSH (Posible ataque de fuerza bruta)",
        fields=[
            ("🌐 Origen:", _field(a, "srcip")),
            ("👤 Usuario:", _field(a, "dstuser", default="?")),
        ],
        recommendation="Aislar IP en firewall o revisar reglas de Fail2ban en el host.",
        evidence=a.get("full_log", ""),
    ),
    "5715": lambda a: render_soc_alert(
        a,
        title="Elevación su fallida (Contraseña errónea)",
        fields=[
            ("👤 Usuario origen:", _field(a, "srcuser", default="?")),
            ("👤 Usuario destino:", _field(a, "dstuser", default="?")),
            ("⚙️ Proceso:", _field(a, "program_name", default="su")),
        ],
        recommendation="Investigar usuario que ejecutó su; posible intento no autorizado de cambio a root.",
        evidence=a.get("full_log", ""),
    ),
    "5401": lambda a: render_soc_alert(
        a,
        title="Ejecución de sudo fallida (Contraseña incorrecta)",
        fields=[
            ("👤 Usuario:", _field(a, "dstuser", default=_field(a, "srcuser", default="?"))),
            ("⚙️ Proceso:", "sudo"),
        ],
        recommendation="Verificar si el usuario tiene privilegios sudo autorizados.",
        evidence=a.get("full_log", ""),
    ),
    "550": lambda a: render_soc_alert(
        a,
        title="FIM - Archivo nuevo agregado en ruta supervisada",
        fields=[
            ("📁 Archivo:", _field(a, "path", default=_field(a, "file", default="?"))),
        ],
        recommendation="Confirmar si el archivo nuevo corresponde a un despliegue o software programado.",
        evidence=a.get("full_log", ""),
    ),
    "553": lambda a: render_soc_alert(
        a,
        title="FIM - Archivo modificado en ruta supervisada",
        fields=[
            ("📁 Archivo:", _field(a, "path", default=_field(a, "file", default="?"))),
        ],
        recommendation="Verificar si la alteración fue realizada por un proceso administrativo autorizado.",
        evidence=a.get("full_log", ""),
    ),
    "554": lambda a: render_soc_alert(
        a,
        title="FIM - Archivo eliminado del sistema",
        fields=[
            ("📁 Archivo:", _field(a, "path", default=_field(a, "file", default="?"))),
        ],
        recommendation="Confirmar que la eliminación no afecte la integridad del sistema o registros.",
        evidence=a.get("full_log", ""),
    ),
    "520": lambda a: render_soc_alert(
        a,
        title="Binario SUID detectado en el sistema",
        fields=[
            ("📁 Archivo:", _field(a, "path", default="?")),
        ],
        recommendation="Los binarios SUID corren con privilegios de root. Verificar si fue creado intencionalmente.",
        evidence=a.get("full_log", ""),
    ),
    "2902": lambda a: render_soc_alert(
        a,
        title="Descarga web registrada desde el endpoint",
        fields=[
            ("🌐 URL:", _field(a, "url")),
        ],
        recommendation="Verificar reputación de la URL y si la descarga fue autorizada por el usuario.",
    ),
    "2903": lambda a: render_soc_alert(
        a,
        title="Descarga web sospechosa detectada",
        fields=[
            ("🌐 URL:", _field(a, "url")),
        ],
        recommendation="Posible descarga de payload malicioso. Analizar URL en VirusTotal o aislar endpoint.",
    ),
    # --- Login exitoso (custom) ---
    "57100": lambda a: render_soc_alert(
        a,
        title="Login SSH exitoso por contraseña",
        fields=[
            ("👤 Usuario:", _field(a, "dstuser", default="?")),
            ("🌐 Origen:", f"{_field(a, 'srcip', default='local')}:{_field(a, 'srcport', default='?')}"),
            ("⚙️ Proceso:", _field(a, "program_name", default="sshd")),
            ("📍 Ubicación:", a.get("location", "?")),
        ],
        recommendation="Confirmar si este acceso interactivo por contraseña era esperado.",
        evidence=a.get("full_log", ""),
    ),
    "57101": lambda a: render_soc_alert(
        a,
        title="Login SSH exitoso con clave pública",
        fields=[
            ("👤 Usuario:", _field(a, "dstuser", default="?")),
            ("🌐 Origen:", f"{_field(a, 'srcip', default='local')}:{_field(a, 'srcport', default='?')}"),
            ("⚙️ Proceso:", _field(a, "program_name", default="sshd")),
        ],
        recommendation="Acceso verificado mediante llave criptográfica autorizada.",
        evidence=a.get("full_log", ""),
    ),
    "57102": lambda a: render_soc_alert(
        a,
        title="ROOT LOGIN directo por SSH (CRÍTICO)",
        fields=[
            ("👤 Usuario:", "root"),
            ("🌐 Origen:", f"{_field(a, 'srcip', default='local')}:{_field(a, 'srcport', default='?')}"),
            ("⚙️ Proceso:", _field(a, "program_name", default="sshd")),
        ],
        recommendation="Acceso directo de superusuario. Se recomienda deshabilitar PermitRootLogin en sshd_config.",
        evidence=a.get("full_log", ""),
    ),
    "57103": lambda a: render_soc_alert(
        a,
        title="Cambio de usuario (su) exitoso",
        fields=[
            ("👤 Usuario origen:", _field(a, "srcuser", default="?")),
            ("👤 Usuario destino:", _field(a, "dstuser", default="?")),
            ("⚙️ Proceso:", _field(a, "program_name", default="su")),
        ],
        recommendation="Transición de privilegios registrada en el host.",
        evidence=a.get("full_log", ""),
    ),
    "57104": lambda a: render_soc_alert(
        a,
        title="Comando sudo ejecutado con privilegios",
        fields=[
            ("👤 Usuario:", _field(a, "dstuser", default="?")),
            ("⚙️ Comando:", _field(a, "command", default="?")[:120]),
            ("📂 Directorio:", _field(a, "pwd", default="?")),
            ("🖥️ TTY:", _field(a, "tty", default="?")),
        ],
        recommendation="Auditar si el comando ejecutado bajo sudo corresponde al mantenimiento habitual.",
        evidence=a.get("full_log", ""),
    ),
    "57105": lambda a: render_soc_alert(
        a,
        title="Login local interactivo (TTY / Consola)",
        fields=[
            ("👤 Usuario:", _field(a, "dstuser", default="?")),
            ("🖥️ TTY:", _field(a, "tty", default="?")),
            ("⚙️ Proceso:", _field(a, "program_name", default="?")),
        ],
        recommendation="Acceso físico o por consola virtual en el servidor.",
        evidence=a.get("full_log", ""),
    ),
    "57106": lambda a: render_soc_alert(
        a,
        title="Sesión cerrada / Logout del sistema",
        fields=[
            ("👤 Usuario:", _field(a, "dstuser", default="?")),
            ("⏱️ Duración:", _field(a, "session_time", default="?")),
            ("⚙️ Proceso:", _field(a, "program_name", default="?")),
        ],
        recommendation="Cierre normal de sesión de usuario.",
        evidence=a.get("full_log", ""),
    ),
    # --- Vulnerability Detector ---
    "23505": lambda a: render_soc_alert(
        a,
        title="Vulnerabilidad de seguridad de nivel ALTO (CVE)",
        fields=[
            ("🛡️ CVE:", _vuln(a, "cve")),
            ("📦 Paquete:", f"{_vuln(a, 'package', 'name')} {_vuln(a, 'package', 'version')}"),
            ("📊 CVSS v3:", _cvss(a, "cvss3")),
            ("📅 Publicado:", _vuln(a, "published", default="?")[:10]),
        ],
        recommendation="Planificar actualización del paquete vulnerable mediante el gestor del SO.",
    ),
    "23506": lambda a: render_soc_alert(
        a,
        title="Vulnerabilidad de seguridad de nivel CRÍTICO (CVE)",
        fields=[
            ("🚨 CVE:", _vuln(a, "cve")),
            ("📦 Paquete:", f"{_vuln(a, 'package', 'name')} {_vuln(a, 'package', 'version')}"),
            ("📊 CVSS v3:", _cvss(a, "cvss3")),
            ("🔥 Severidad:", _vuln(a, "severity")),
        ],
        recommendation="Actualización urgente requerida; evaluar exposición del servicio a redes públicas.",
    ),
    "57107": lambda a: render_soc_alert(
        a,
        title="Vulnerabilidad de seguridad de nivel MEDIO (CVE)",
        fields=[
            ("🟡 CVE:", _vuln(a, "cve")),
            ("📦 Paquete:", f"{_vuln(a, 'package', 'name')} {_vuln(a, 'package', 'version')}"),
            ("📊 CVSS v3:", _cvss(a, "cvss3")),
        ],
        recommendation="Incluir en el siguiente ciclo ordinario de parches de seguridad.",
    ),
    "57108": lambda a: render_soc_alert(
        a,
        title="Vulnerabilidad de seguridad de nivel BAJO (CVE)",
        fields=[
            ("🟢 CVE:", _vuln(a, "cve")),
            ("📦 Paquete:", f"{_vuln(a, 'package', 'name')} {_vuln(a, 'package', 'version')}"),
            ("📊 CVSS v3:", _cvss(a, "cvss3")),
        ],
        recommendation="Monitorear avisos del fabricante del sistema operativo.",
    ),
    "57109": lambda a: render_soc_alert(
        a,
        title="Vulnerabilidad corregida / Resuelta",
        fields=[
            ("✅ CVE:", _vuln(a, "cve")),
            ("📦 Paquete:", f"{_vuln(a, 'package', 'name')} {_vuln(a, 'package', 'version')}"),
        ],
        recommendation="El parche de seguridad fue aplicado y la debilidad quedó mitigada.",
    ),
    "57110": lambda a: render_soc_alert(
        a,
        title="Inventario de vulnerabilidades depurado",
        fields=[],
        recommendation="Base de datos de vulnerabilidades del agente sincronizada con éxito.",
    ),
    # --- Nuevas reglas de seguridad avanzadas (57120 - 57130) ---
    "57120": lambda a: render_soc_alert(
        a,
        title="Ataque de fuerza bruta SSH persistente (CRÍTICO)",
        fields=[
            ("🌐 Origen:", _field(a, "srcip")),
            ("🔍 Detección:", "Más de 10 intentos fallidos de login en 2 minutos"),
        ],
        recommendation="Bloqueo preventivo de IP inmediato en Firewall perimetral o iptables.",
        evidence=a.get("full_log", ""),
    ),
    "57121": lambda a: render_soc_alert(
        a,
        title="Ejecución remota sospechosa por tubería (CRÍTICO)",
        fields=[
            ("👤 Usuario:", _field(a, "dstuser", default="?")),
            ("⚙️ Comando:", _field(a, "command", default=_field(a, "full_log", default="?"))[:140]),
        ],
        recommendation="Posible ejecución en memoria (curl | bash). Aislar proceso y host preventivamente.",
        evidence=a.get("full_log", ""),
    ),
    "57122": lambda a: render_soc_alert(
        a,
        title="Ejecución de binario/script en carpeta temporal (/tmp)",
        fields=[
            ("👤 Usuario:", _field(a, "dstuser", default="?")),
            ("⚙️ Comando:", _field(a, "command", default="?")[:120]),
            ("📂 Directorio:", _field(a, "pwd", default="?")),
        ],
        recommendation="Revisar origen del binario en /tmp; rutas temporales no deben alojar ejecutables.",
        evidence=a.get("full_log", ""),
    ),
    "57123": lambda a: render_soc_alert(
        a,
        title="Violación de seguridad: Usuario no autorizado en sudoers",
        fields=[
            ("👤 Usuario infractor:", _field(a, "srcuser", default=_field(a, "dstuser", default="?"))),
        ],
        recommendation="Intento de ejecución con privilegios sin autorización en /etc/sudoers.",
        evidence=a.get("full_log", ""),
    ),
    "57124": lambda a: render_soc_alert(
        a,
        title="Intentos reiterados de login como ROOT por SSH",
        fields=[
            ("🌐 Origen:", _field(a, "srcip")),
        ],
        recommendation="Tráfico dirigido contra la cuenta root. Verificar si la IP debe bloquearse.",
        evidence=a.get("full_log", ""),
    ),
    "57125": lambda a: render_soc_alert(
        a,
        title="Modificación de archivo crítico (/etc/shadow, passwd, sudoers) (CRÍTICO)",
        fields=[
            ("📁 Archivo:", _field(a, "path", default=_field(a, "file", default="?"))),
        ],
        recommendation="Alerta de máxima prioridad FIM. Validar inmediatamente si se añadieron usuarios o claves.",
        evidence=a.get("full_log", ""),
    ),
    "57126": lambda a: render_soc_alert(
        a,
        title="Detención de servicio crítico del sistema (Wazuh / SSH / Firewall)",
        fields=[],
        recommendation="Servicio esencial detenido. Confirmar si se trata de mantenimiento o sabotaje.",
        evidence=a.get("full_log", ""),
    ),
    "57127": lambda a: render_soc_alert(
        a,
        title="Kernel OOM Killer activado (Memoria RAM agotada)",
        fields=[],
        recommendation="El kernel eliminó procesos por saturación de RAM. Revisar consumo con /procesos.",
        evidence=a.get("full_log", ""),
    ),
    "57128": lambda a: render_soc_alert(
        a,
        title="Escaneo de puertos detectado / bloqueado por Firewall",
        fields=[
            ("🌐 Origen:", _field(a, "srcip")),
        ],
        recommendation="Paquetes hacia puertos cerrados bloqueados por cortafuegos.",
        evidence=a.get("full_log", ""),
    ),
    "57129": lambda a: render_soc_alert(
        a,
        title="Modificación en authorized_keys (Llaves SSH de acceso)",
        fields=[
            ("📁 Archivo:", _field(a, "path", default=_field(a, "file", default="?"))),
        ],
        recommendation="Revisar llaves públicas añadidas a ~/.ssh/authorized_keys para descartar persistencia.",
        evidence=a.get("full_log", ""),
    ),
    "57130": lambda a: render_soc_alert(
        a,
        title="Contenedor Docker detenido o en fallo de ejecución",
        fields=[],
        recommendation="Comprobar estado de los contenedores con /servicios.",
        evidence=a.get("full_log", ""),
    ),
    "57131": lambda a: render_soc_alert(
        a,
        title="Intento fallido de autenticación por SSH",
        fields=[
            ("👤 Usuario intentado:", _field(a, "dstuser", default=_field(a, "srcuser", default="?"))),
            ("🌐 Origen:", f"{_field(a, 'srcip')}:{_field(a, 'srcport', default='?')}"),
        ],
        recommendation="Acceso SSH rechazado. Monitorear si proviene de IP desconocida.",
        evidence=a.get("full_log", ""),
    ),
    "57132": lambda a: render_soc_alert(
        a,
        title="Intento de acceso SSH con usuario no existente",
        fields=[
            ("👤 Usuario no válido:", _field(a, "srcuser", default=_field(a, "dstuser", default="?"))),
            ("🌐 Origen:", f"{_field(a, 'srcip')}:{_field(a, 'srcport', default='?')}"),
        ],
        recommendation="Patrón clásico de diccionario / escaneo automatizado contra nombres comunes.",
        evidence=a.get("full_log", ""),
    ),
    "57133": lambda a: render_soc_alert(
        a,
        title="Escaneo o sondeo de red en puerto SSH (Probe scan)",
        fields=[
            ("🌐 Origen:", f"{_field(a, 'srcip')}:{_field(a, 'srcport', default='?')}"),
            ("🔍 Detección:", "Conexión sin intercambio válido de protocolo SSH"),
        ],
        recommendation="Sondeo de conectividad previo a intrusión. Monitorear dirección IP.",
        evidence=a.get("full_log", ""),
    ),
    "57134": lambda a: render_soc_alert(
        a,
        title="Múltiples conexiones cerradas en SSH (Barrido de puertos)",
        fields=[
            ("🌐 Origen:", _field(a, "srcip")),
            ("🔍 Detección:", "Ráfaga de desconexiones preauth en puerto 22"),
        ],
        recommendation="Barrido rápido de puertos detectado por el sensor.",
        evidence=a.get("full_log", ""),
    ),
    "57135": lambda a: render_soc_alert(
        a,
        title="Escaneo masivo de puertos detectado por Firewall (CRÍTICO)",
        fields=[
            ("🌐 Origen sospechoso:", _field(a, "srcip")),
            ("🔍 Detección:", "Múltiples paquetes a puertos cerrados en < 30s"),
        ],
        recommendation="Escaneo agresivo de reconocimiento. Bloquear IP en el router o cortafuegos perimetral.",
        evidence=a.get("full_log", ""),
    ),
    "57136": lambda a: render_soc_alert(
        a,
        title="Usuario o grupo del sistema eliminado",
        fields=[],
        recommendation="Confirmar si la baja de la cuenta fue autorizada por el equipo de TI.",
        evidence=a.get("full_log", ""),
    ),
    "57137": lambda a: render_soc_alert(
        a,
        title="Modificación en tareas programadas Crontab",
        fields=[],
        recommendation="Verificar persistencia; inspeccionar nuevas tareas en /etc/cron* o crontab -l.",
        evidence=a.get("full_log", ""),
    ),
    "57138": lambda a: render_soc_alert(
        a,
        title="Intento crítico de Reverse Shell o Tubería de red (CRÍTICO)",
        fields=[
            ("👤 Usuario:", _field(a, "dstuser", default="?")),
            ("⚙️ Comando sospechoso:", _field(a, "command", default=_field(a, "full_log", default="?"))[:140]),
        ],
        recommendation="Detección de shell reversa. Aislar el host de la red inmediatamente e iniciar forense.",
        evidence=a.get("full_log", ""),
    ),
    "57139": lambda a: render_soc_alert(
        a,
        title="Herramienta de escaneo o captura ejecutada en el servidor",
        fields=[
            ("👤 Usuario:", _field(a, "dstuser", default="?")),
            ("⚙️ Herramienta detectada:", _field(a, "command", default="?")[:120]),
        ],
        recommendation="Uso de tcpdump/nmap/wireshark en el host. Confirmar autorización de diagnóstico.",
        evidence=a.get("full_log", ""),
    ),
    "57140": lambda a: render_soc_alert(
        a,
        title="Intento de borrado de logs o desactivación de cortafuegos (CRÍTICO)",
        fields=[
            ("👤 Usuario:", _field(a, "dstuser", default="?")),
            ("⚙️ Acción detectada:", _field(a, "command", default=_field(a, "full_log", default="?"))[:140]),
        ],
        recommendation="Intento activo de evasión de defensas (MITRE T1070). Bloquear usuario y aislar host.",
        evidence=a.get("full_log", ""),
    ),
    "57150": lambda a: render_soc_alert(
        a,
        title="Wazuh Agent conectado al ecosistema",
        fields=[
            ("🌐 IP Enlace:", _field(a, "srcip", default="any")),
            ("🐧 Plataforma:", _field(a, "os", "name", default="Linux")),
            ("⚙️ Estado:", "🟢 Activo y Sincronizado"),
        ],
        recommendation="Endpoint conectado. Se ejecutó el análisis de integridad y postura CIS Benchmark.",
        evidence=a.get("full_log", ""),
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
    rule_id = str(rule.get("id", "?"))
    raw_desc = rule.get("description", "?")
    desc_es = _translate_description_es(raw_desc)
    level = rule.get("level", 0)
    level_es = _format_level_es(level)
    agent = _agent(alert)
    agent_id = str((alert.get("agent") or {}).get("id", "000"))
    timestamp = alert.get("timestamp", "?")
    src_ip = _field(alert, "srcip", default="")
    user = _field(alert, "dstuser", default="")
    raw_log = alert.get("full_log", "") or ""
    log_es = translate_full_log_es(raw_log)

    agent_suffix = f" _(ID: {agent_id})_" if agent_id and agent_id != "000" else ""
    lines = [
        "🚨 *ALERTA DE SEGURIDAD WAZUH*",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"📊 *Nivel:* {level_es}",
        f"🛡️ *Regla:* `#{rule_id}` - *{desc_es}*",
        f"🖥️ *Equipo / Agente:* `{agent}`{agent_suffix}",
    ]
    if src_ip and src_ip != "?":
        lines.append(f"🌐 *IP Origen:* `{src_ip}`")
    if user and user != "?":
        lines.append(f"👤 *Usuario:* `{user}`")
    if log_es:
        lines.append(f"📝 *Detalle:* `{log_es[:140]}`")
    lines.append(f"⏰ *Hora:* `{timestamp}`")
    lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━")
    lines.append("⚡ *Acciones rápidas:*")
    lines.append(f"• Ficha forense: `/agente {agent_id}`")
    lines.append(f"• Reporte PDF: `/reporte {agent_id}`")
    lines.append(f"• Silenciar regla: `/silenciar {rule_id}`")
    return "\n".join(lines)

