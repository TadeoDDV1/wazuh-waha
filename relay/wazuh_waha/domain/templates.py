import html as _html
import re
import time
from typing import Callable

TemplateFn = Callable[[dict], str]

_IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_FROM_IP_REGEX = re.compile(
    r"(?:from|SRC=|client|rhost=)\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3}|[a-fA-F0-9:]+)",
    re.IGNORECASE,
)
_PORT_REGEX = re.compile(r"(?:port|SPT=|DPT=)\s*(\d+)", re.IGNORECASE)
_USER_REGEX = re.compile(
    r"(?:for(?:\s+invalid\s+user)?|user=|user\s+)\s*([a-zA-Z0-9_\-\.]+)",
    re.IGNORECASE,
)
_PROC_REGEX = re.compile(r"\b([a-zA-Z0-9_\-\.]{2,32})(?:\[\d+\])?:\s")


def _agent(alert: dict) -> str:
    a = alert.get("agent", {}) or {}
    return a.get("name", a.get("id", "unknown"))


def extract_clean_ip(alert: dict) -> str:
    """Extrae la IP de origen legítima sin arrastrar logs crudos ni texto de depuración."""
    data = alert.get("data", {}) or {}
    pre = alert.get("predecoder", {}) or {}
    port_data = data.get("port", {}) if isinstance(data.get("port"), dict) else {}
    netinfo = data.get("netinfo", {}) if isinstance(data.get("netinfo"), dict) else {}
    candidates = [
        data.get("srcip"),
        data.get("src_ip"),
        alert.get("srcip"),
        pre.get("srcip"),
        port_data.get("remote_ip"),
        netinfo.get("remote_ip"),
        data.get("remote_ip"),
        data.get("client_ip"),
        port_data.get("local_ip"),
        data.get("local_ip"),
    ]
    for c in candidates:
        if c and isinstance(c, str):
            c_clean = c.strip().replace("::ffff:", "")
            if c_clean and c_clean not in ("-", "(none)", "unknown", "?", "127.0.0.1", "::1", "0.0.0.0"):
                return c_clean
            elif c_clean in ("127.0.0.1", "::1"):
                return "127.0.0.1 (Local)"

    # Buscar en full_log con regex acotado
    log = (alert.get("full_log", "") or "")[:1024]
    if log:
        m = _FROM_IP_REGEX.search(log)
        if m:
            ip_cand = m.group(1).replace("::ffff:", "").strip()
            if ip_cand and ip_cand not in ("127.0.0.1", "::1", "0.0.0.0"):
                return ip_cand
        ips = _IPV4_REGEX.findall(log)
        for ip in ips:
            if not ip.startswith("127.") and ip not in ("0.0.0.0", "255.255.255.255"):
                try:
                    parts = [int(p) for p in ip.split(".")]
                    if all(0 <= p <= 255 for p in parts):
                        return ip
                except ValueError:
                    pass

    # Eventos locales reconocidos
    rule = alert.get("rule", {}) or {}
    rule_id = str(rule.get("id", "0"))
    loc = alert.get("location", "")
    if rule_id in ("57103", "57104", "57105", "57106", "5401", "5402", "5407") or "pam" in loc or "sudo" in loc:
        return "🏠 Local / Consola"

    return "No identificada (Interno)"


def extract_clean_port(alert: dict) -> str:
    """Extrae el puerto de red limpio."""
    data = alert.get("data", {}) or {}
    port_data = data.get("port", {}) if isinstance(data.get("port"), dict) else {}
    candidates = [
        data.get("srcport"),
        data.get("src_port"),
        alert.get("srcport"),
        port_data.get("remote_port"),
        port_data.get("local_port"),
        data.get("remote_port"),
        data.get("local_port"),
    ]
    for c in candidates:
        if c and str(c).strip() not in ("0", "-1", "?", "-", "None"):
            return str(c).strip()
    log = (alert.get("full_log", "") or "")[:1024]
    if log:
        m = _PORT_REGEX.search(log)
        if m:
            return m.group(1)
    return ""


def extract_clean_user(alert: dict) -> str:
    """Extrae el usuario asociado al evento de forma limpia."""
    data = alert.get("data", {}) or {}
    pre = alert.get("predecoder", {}) or {}
    candidates = [
        data.get("dstuser"),
        data.get("srcuser"),
        pre.get("dstuser"),
        pre.get("srcuser"),
        data.get("user"),
        alert.get("dstuser"),
        alert.get("srcuser"),
    ]
    for c in candidates:
        if c and str(c).strip() and str(c) not in ("?", "None", "-", "(none)"):
            return str(c).strip()
    log = (alert.get("full_log", "") or "")[:1024]
    if log:
        m = _USER_REGEX.search(log)
        if m:
            u = m.group(1).strip()
            if u not in ("from", "port", "ssh2", "invalid"):
                return u
    return "No especificado"


def extract_clean_process(alert: dict) -> str:
    """Extrae el proceso o servicio de ejecución."""
    data = alert.get("data", {}) or {}
    pre = alert.get("predecoder", {}) or {}
    port_data = data.get("port", {}) if isinstance(data.get("port"), dict) else {}
    proc_data = data.get("process", {}) if isinstance(data.get("process"), dict) else {}
    candidates = [
        data.get("program_name"),
        pre.get("program_name"),
        proc_data.get("name"),
        proc_data.get("cmd"),
        data.get("process") if isinstance(data.get("process"), str) else None,
        port_data.get("process"),
    ]
    for c in candidates:
        if c and isinstance(c, str) and c.strip() and c.strip() not in ("?", "None", "-", "(none)"):
            val = c.strip()
            # Si es un path completo, tomar el binario final
            if "/" in val and not val.startswith("-"):
                val = val.split("/")[-1]
            return val
    first_line = (alert.get("full_log", "") or "").split("\n", 1)[0][:250]
    if first_line:
        m = _PROC_REGEX.search(first_line)
        if m:
            return m.group(1)
    loc = alert.get("location", "")
    if loc and "/" in loc:
        return loc.split("/")[-1]
    return "sistema"


def _field(alert: dict, *path: str, default: str = "?") -> str:
    # Si se pide srcip específicamente, usar extractor limpio para nunca emitir código crudo
    if len(path) == 1 and path[0] in ("srcip", "src_ip"):
        ip = extract_clean_ip(alert)
        return ip if ip and not ip.startswith("No identificada") else default

    if len(path) == 1 and path[0] in ("dstuser", "srcuser", "user"):
        u = extract_clean_user(alert)
        return u if u and u != "No especificado" else default

    if len(path) == 1 and path[0] in ("program_name", "process"):
        p = extract_clean_process(alert)
        return p if p and p != "sistema" else default

    candidates = [alert.get("data", {}) or {}, alert.get("agent", {}) or {}]
    for root in candidates:
        cur = root
        for k in path:
            if not isinstance(cur, dict):
                cur = None
                break
            cur = cur.get(k)
        if cur is not None and str(cur).strip():
            return str(cur).strip()

    return default


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
    explanation: str = "",
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
        level_badge = f"🔴 *[CRÍTICO • L{level}]*"
    elif level >= 8:
        level_badge = f"🟠 *[ALTO • L{level}]*"
    elif level >= 4:
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
        if val and val != "?" and val != "None" and val != "No especificado" and not val.startswith("No identificada"):
            lines.append(f"{label} `{val}`")

    if explanation:
        lines.append(f"🔍 *Diagnóstico:* {explanation}")

    if evidence and evidence != "?" and evidence != "None":
        cleaned_ev = translate_full_log_es(evidence)
        if len(cleaned_ev) > 160:
            cleaned_ev = cleaned_ev[:157] + "..."
        lines.append(f"📝 *Evidencia:* `{cleaned_ev}`")

    lines.append(f"⏰ *Hora:* `{timestamp}`")
    lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━")

    if recommendation:
        lines.append(f"💡 *Acción SOC:* {recommendation}\n")

    lines.append("⚡ *Acciones rápidas:*")
    lines.append(f"• Ficha forense: `/agente {agent_id}`")
    lines.append(f"• Reporte PDF: `/reporte {agent_id}`")
    lines.append(f"• Silenciar regla: `/silenciar {rule_id}`")

    return "\n".join(lines)


def render_soc_alert_html(alert: dict, title: str = "", recommendation: str = "") -> str:
    """Genera plantilla de correo electrónico HTML con diseño ejecutivo SOC profesional."""
    rule = alert.get("rule", {}) or {}
    rule_id = str(rule.get("id", "0"))
    level = int(rule.get("level", 0))
    agent_obj = alert.get("agent", {}) or {}
    agent_name = agent_obj.get("name") or agent_obj.get("id") or "Servidor Local"
    agent_id = str(agent_obj.get("id", "000"))
    timestamp = alert.get("timestamp") or time.strftime("%Y-%m-%d %H:%M:%S")

    desc_raw = title or rule.get("description", "Evento de seguridad")
    desc_es = _translate_description_es(desc_raw)

    if level >= 12:
        badge_bg = "#dc2626"
        badge_text = f"CRÍTICO (Nivel {level})"
    elif level >= 8:
        badge_bg = "#ea580c"
        badge_text = f"ALTO (Nivel {level})"
    elif level >= 4:
        badge_bg = "#d97706"
        badge_text = f"MEDIO (Nivel {level})"
    else:
        badge_bg = "#0284c7"
        badge_text = f"INFO (Nivel {level})"

    src_ip = extract_clean_ip(alert)
    user = extract_clean_user(alert)
    proc = extract_clean_process(alert)
    raw_log = alert.get("full_log", "") or ""
    log_es = translate_full_log_es(raw_log)

    rec = recommendation
    if not rec:
        if level >= 12:
            rec = "Evento de criticidad máxima. Aislar endpoint preventivamente y auditar credenciales/procesos."
        elif level >= 8:
            rec = "Verificar origen del evento y contrastar con la bitácora de administración autorizada."
        else:
            rec = "Evento registrado para auditoría y correlación continua del SOC."

    # Escapar todo valor dinámico: proviene de logs/alertas y puede contener
    # HTML/JS (XSS en el cliente de correo o robo de datos vía <img>).
    def esc(value: object) -> str:
        return _html.escape(str(value), quote=True)

    desc_es_h = esc(desc_es)
    badge_text_h = esc(badge_text)
    rule_id_h = esc(rule_id)
    agent_name_h = esc(agent_name)
    agent_id_h = esc(agent_id)
    src_ip_h = esc(src_ip)
    user_h = esc(user)
    proc_h = esc(proc)
    timestamp_h = esc(timestamp)
    rec_h = esc(rec)
    log_es_h = esc(log_es[:200])

    html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0f172a; color: #f8fafc; margin: 0; padding: 20px; }}
    .container {{ max-width: 650px; margin: 0 auto; background: #1e293b; border-radius: 12px; overflow: hidden; border: 1px solid #334155; }}
    .header {{ background: #0f172a; padding: 20px; border-bottom: 2px solid {badge_bg}; }}
    .badge {{ display: inline-block; padding: 4px 12px; border-radius: 9999px; font-size: 12px; font-weight: bold; color: #ffffff; background-color: {badge_bg}; }}
    .title {{ margin: 10px 0 0 0; font-size: 18px; color: #f8fafc; }}
    .content {{ padding: 20px; }}
    .table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
    .table td {{ padding: 8px 12px; border-bottom: 1px solid #334155; font-size: 14px; }}
    .table td.label {{ color: #94a3b8; width: 35%; font-weight: 500; }}
    .table td.value {{ color: #f1f5f9; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }}
    .action-box {{ background: #0f172a; border-left: 4px solid #3b82f6; padding: 14px 16px; border-radius: 4px; margin-bottom: 20px; }}
    .action-title {{ font-size: 13px; font-weight: bold; color: #38bdf8; text-transform: uppercase; margin-bottom: 4px; }}
    .action-text {{ font-size: 14px; color: #e2e8f0; margin: 0; }}
    .footer {{ background: #0f172a; padding: 14px 20px; font-size: 12px; color: #64748b; text-align: center; border-top: 1px solid #334155; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <span class="badge">{badge_text_h}</span>
      <h2 class="title">🛡️ Regla #{rule_id_h}: {desc_es_h}</h2>
    </div>
    <div class="content">
      <table class="table">
        <tr><td class="label">💻 Endpoint / Agente:</td><td class="value">{agent_name_h} (ID: {agent_id_h})</td></tr>
        <tr><td class="label">🌐 Origen / IP:</td><td class="value">{src_ip_h}</td></tr>
        <tr><td class="label">👤 Usuario:</td><td class="value">{user_h}</td></tr>
        <tr><td class="label">⚙️ Proceso / Servicio:</td><td class="value">{proc_h}</td></tr>
        <tr><td class="label">⏰ Marca de Tiempo:</td><td class="value">{timestamp_h}</td></tr>
      </table>
      <div class="action-box">
        <div class="action-title">💡 Acción SOC Recomendada:</div>
        <p class="action-text">{rec_h}</p>
      </div>
      {f'<div style="font-size: 12px; color: #94a3b8; background: #0b1120; padding: 10px; border-radius: 6px; font-family: monospace;"><b>Evidencia:</b> {log_es_h}</div>' if log_es else ''}
    </div>
    <div class="footer">
      Wazuh-WAHA SOC Suite · Notificación Automatizada Multi-Canal
    </div>
  </div>
</body>
</html>"""
    return html


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

    # Amenazas de Red, Reconocimiento y Firewall
    ("UFW BLOCK", "Bloqueo por cortafuegos UFW"),
    ("iptables denied", "Conexión rechazada por IPTables"),
    ("connection refused", "Conexión rechazada"),
    ("Port scan detected", "Escaneo de puertos detectado por el sensor"),
    ("Nmap scan", "Escaneo de red mediante Nmap detectado"),
    ("SYN flood attack", "Ataque de denegación de servicio (SYN Flood)"),
    ("Broadcast ping", "Sondeo de red broadcast (Ping ICMP)"),
    ("Promiscuous mode", "Interfaz de red en modo promiscuo (Capturador/Sniffer)"),
    ("Host-based anomaly detection event (rootcheck)", "Anomalía en el sistema detectada por Rootcheck"),

    # Ataques Web y Servicios HTTP
    ("SQL injection attempt", "Intento de inyección SQL (SQLi) detectado"),
    ("Cross-site scripting", "Intento de ataque XSS (Cross-Site Scripting)"),
    ("Directory traversal attempt", "Intento de salto de directorio (Path Traversal)"),
    ("Shellshock attack", "Intento de explotación Shellshock"),
    ("Apache: Attempt to access forbidden directory", "Intento de acceso a directorio prohibido en servidor Web"),
    ("Nginx: 403 Forbidden", "Petición web bloqueada (403 Forbidden)"),
    ("Web server 500 error code", "Error interno 500 en servidor Web"),

    # Amenazas avanzadas y Persistencia
    ("Reverse shell", "Intento de Reverse Shell interactiva detectado"),
    ("Suspicious process execution", "Ejecución de proceso sospechoso detectada"),
    ("Execution from temporary directory", "Ejecución de binario en directorio temporal (/tmp)"),
    ("Crontab altered", "Modificación en tareas programadas Crontab"),
    ("SSH key added", "Nueva llave SSH añadida a authorized_keys"),
    ("Password changed", "Contraseña de usuario modificada en el sistema"),
    ("User account created", "Nueva cuenta de usuario creada en el sistema"),
    ("User account deleted", "Cuenta de usuario eliminada del sistema"),

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

    # Infraestructura y Health
    ("Active response", "Respuesta Activa ejecutada"),
    ("WAHA session", "Evento de salud de la sesión WhatsApp (WAHA)"),
    ("wazuh-agent", "Evento de estado del Agente Wazuh"),
    ("wazuh-waha", "Evento de estado del Relay Wazuh-WAHA"),
    ("syscollector", "Telemetría de red y sistema (Syscollector)"),
    ("dbsync_ports", "Conexión de red activa registrada"),
    ("dbsync_packages", "Inventario de software actualizado"),
    ("dbsync_processes", "Inventario de procesos en ejecución"),
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
    src_ip = extract_clean_ip(alert)
    src_port = extract_clean_port(alert)
    user = extract_clean_user(alert)
    proc = extract_clean_process(alert)
    raw_log = alert.get("full_log", "") or ""
    log_es = translate_full_log_es(raw_log)

    agent_suffix = f" _(ID: {agent_id})_" if agent_id and agent_id != "000" else ""
    lines = [
        "🚨 *ALERTA DE SEGURIDAD WAZUH*",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"📊 *Nivel:* {level_es}",
        f"🛡️ *Regla:* `#{rule_id}` - *{desc_es}*",
        f"💻 *Equipo / Agente:* `{agent}`{agent_suffix}",
    ]
    if src_ip and not src_ip.startswith("No identificada"):
        port_suffix = f":{src_port}" if src_port else ""
        lines.append(f"🌐 *IP Origen:* `{src_ip}{port_suffix}`")
    if user and user != "No especificado":
        lines.append(f"👤 *Usuario:* `{user}`")
    if proc and proc != "sistema":
        lines.append(f"⚙️ *Proceso:* `{proc}`")
    if log_es and log_es != desc_es:
        lines.append(f"📝 *Detalle:* `{log_es[:140]}`")
    lines.append(f"⏰ *Hora:* `{timestamp}`")
    lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━")

    try:
        lvl_int = int(level)
    except Exception:
        lvl_int = 0
    if lvl_int >= 12:
        rec = "Evento de criticidad máxima. Aislar endpoint preventivamente y auditar credenciales/procesos."
    elif lvl_int >= 8:
        rec = "Verificar origen del evento y contrastar con la bitácora de administración autorizada."
    else:
        rec = "Evento registrado para auditoría y correlación continua del SOC."
    lines.append(f"💡 *Acción SOC:* {rec}\n")

    lines.append("⚡ *Acciones rápidas:*")
    lines.append(f"• Ficha forense: `/agente {agent_id}`")
    lines.append(f"• Reporte PDF: `/reporte {agent_id}`")
    lines.append(f"• Silenciar regla: `/silenciar {rule_id}`")
    return "\n".join(lines)

