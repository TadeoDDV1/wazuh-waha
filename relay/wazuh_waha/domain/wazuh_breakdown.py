"""
wazuh_breakdown.py — Desglose comprensivo, modular y didáctico de Wazuh para el SOC.

Transforma los hallazgos crudos de los módulos de Wazuh (SCA, FIM, Rootcheck,
Syscollector, Vulnerabilidades y Detecciones SIEM) en un informe estructurado
módulo por módulo y apartado por apartado en español claro, explicando:
  - Regla o control que se rompe / incumple
  - Nivel de severidad técnica y operativa
  - ¿Qué ocurrió? (Explicación para humanos)
  - ¿Cuál es el riesgo real para el endpoint o la red?
  - ¿Cómo se remedia de forma inmediata? (Comandos y pasos concretos)
"""

from __future__ import annotations

from typing import Any

from .cis_translator import localize_cis_check


# Catálogo especializado de explicaciones didácticas de Reglas Wazuh (SIEM)
_RULE_SOC_EXPLANATIONS: dict[str, dict[str, str]] = {
    # SSH y Acceso Remoto
    "57100": {
        "title": "Fallo de autenticación por SSH (Contraseña incorrecta o usuario inválido)",
        "risk": "Indica un intento de inicio de sesión no autorizado o un ataque de fuerza bruta intentando adivinar credenciales.",
        "remediation": "Deshabilitar login por contraseña en /etc/ssh/sshd_config, exigir claves SSH y bloquear IPs atacantes con Fail2ban.",
        "category": "Autenticación / Acceso Remoto",
    },
    "57101": {
        "title": "Inicio de sesión SSH exitoso mediante clave pública",
        "risk": "Acceso interactivo concedido al sistema. Si ocurre fuera de horario o desde una IP desconocida, puede indicar una llave SSH comprometida.",
        "remediation": "Auditar la procedencia de la IP y verificar que la llave pública en ~/.ssh/authorized_keys pertenezca a un operador autorizado.",
        "category": "Autenticación / Acceso Remoto",
    },
    "57102": {
        "title": "Inicio de sesión SSH exitoso mediante contraseña",
        "risk": "El inicio de sesión interactivo por contraseña es vulnerable a sniffing e ingeniería social.",
        "remediation": "Configurar 'PasswordAuthentication no' en sshd_config y migrar al uso exclusivo de llaves SSH protegidas.",
        "category": "Autenticación / Acceso Remoto",
    },
    "57103": {
        "title": "Contraseña incorrecta al intentar ejecutar comando sudo",
        "risk": "Un usuario local intentó elevar privilegios con una clave errónea. Puede ser un error humano o un intruso intentando adivinar la clave de root.",
        "remediation": "Verificar la identidad del usuario y revisar los intentos fallidos acumulados en /var/log/auth.log.",
        "category": "Privilegios y Sudo",
    },
    "57104": {
        "title": "Comando administrativo ejecutado con éxito mediante sudo",
        "risk": "Se aplicó una modificación o lectura privilegiada en el sistema como root. Requiere trazabilidad de auditoría.",
        "remediation": "Validar que la orden ejecutada corresponda a una tarea de mantenimiento programada y que el usuario esté en la lista de operadores autorizados.",
        "category": "Privilegios y Sudo",
    },
    "57106": {
        "title": "Intento de ejecución de sudo por usuario NO registrado en sudoers",
        "risk": "ALERTA SEVERA: Un usuario sin privilegios intentó obtener control de superusuario. Es un claro síntoma de usuario curioso o intruso.",
        "remediation": "Suspender temporalmente la cuenta del usuario e investigar la consola o proceso desde el que se emitió el comando.",
        "category": "Privilegios y Sudo",
    },
    "57110": {
        "title": "Cierre de sesión interactiva (Logout / Sesión SSH cerrada)",
        "risk": "Evento de trazabilidad normal de finalización de sesión de trabajo.",
        "remediation": "No requiere remediación. Se registra con fines de control de tiempos de actividad.",
        "category": "Autenticación / Acceso Remoto",
    },
    "57111": {
        "title": "Ataque continuo de fuerza bruta SSH detectado",
        "risk": "Múltiples intentos fallidos de autenticación en una ventana corta de tiempo. Riesgo de denegación de servicio o brecha si las claves son débiles.",
        "remediation": "La IP de origen debe aislarse en el firewall (ufw deny from <IP>) o activarse la Respuesta Activa de Wazuh (firewall-drop).",
        "category": "Amenaza de Red / Fuerza Bruta",
    },

    # FIM (Monitoreo de Integridad de Archivos - Syscheck)
    "550": {
        "title": "Archivo del sistema modificado (Integridad FIM alterada)",
        "risk": "Los atributos, tamaño, permisos o suma hash criptográfica (MD5/SHA256) del archivo cambiaron. Si no fue por actualización legítima, indica manipulación maliciosa o inserción de backdoor.",
        "remediation": "Revisar el diff del archivo, validar contra el paquete del SO ('dpkg -V' o 'pacman -Qk') y restaurar desde respaldo si fue alterado por un intruso.",
        "category": "Integridad de Archivos (FIM)",
    },
    "554": {
        "title": "Nuevo archivo añadido en directorio supervisado (FIM)",
        "risk": "Se creó un archivo en rutas críticas del sistema (/bin, /etc, /usr/bin). Común en la instalación de herramientas de ataque, webshells o scripts de persistencia.",
        "remediation": "Inspeccionar el propietario, permisos y contenido del archivo recién creado. Eliminar o poner en cuarentena si no fue autorizado.",
        "category": "Integridad de Archivos (FIM)",
    },
    "553": {
        "title": "Archivo eliminado en directorio crítico del sistema (FIM)",
        "risk": "Borrado de binarios o logs de auditoría para entorpecer la investigación forense (técnica de evasión de defensas).",
        "remediation": "Investigar qué proceso ejecutó la orden de borrado y reinstalar el paquete o archivo faltante.",
        "category": "Integridad de Archivos (FIM)",
    },

    # Rootcheck (Malware y Anomalías de Kernel)
    "510": {
        "title": "Anomalía en el host detectada por Rootcheck (Malware / Inconsistencia)",
        "risk": "Discrepancia detectada entre las llamadas al sistema del kernel y el sistema de archivos (puertos ocultos, procesos fantasma o firmas de rootkit).",
        "remediation": "Ejecutar análisis complementario de rootkits con rkhunter o chkrootkit. Si persiste, aislar el endpoint de la red para análisis forense.",
        "category": "Detección Antimalware (Rootcheck)",
    },

    # Vulnerability Detector
    "80710": {
        "title": "Vulnerabilidad conocida (CVE) detectada en paquete instalado",
        "risk": "Existe un fallo de seguridad documentado públicamente en el software del equipo que permite ejecución remota de código, escalada local o DoS.",
        "remediation": "Actualizar el paquete afectado a la versión corregida mediante el gestor de paquetes oficial (apt, pacman, yum).",
        "category": "Gestión de Vulnerabilidades (CVE)",
    },

    # PAM y Autenticación de Consola
    "5401": {
        "title": "Cambio de usuario interactivo mediante comando 'su' exitoso",
        "risk": "Un usuario cambió su identidad hacia otra cuenta en consola local. Requiere validar si fue hacia la cuenta de root.",
        "remediation": "Revisar que la elevación esté justificada y restringir el uso de 'su' únicamente a miembros del grupo wheel o sudo.",
        "category": "Gestión de Identidades",
    },
    "5402": {
        "title": "Fallo al intentar cambiar de usuario con comando 'su'",
        "risk": "Contraseña incorrecta introducida para cambiar de cuenta. Posible intento no autorizado de suplantación local.",
        "remediation": "Identificar el usuario que emitió la orden y revisar si hay patrones repetitivos de intento de acceso.",
        "category": "Gestión de Identidades",
    },
}


def explain_wazuh_rule(rule_id: str, level: int | str, description: str, groups: list[str] | None = None) -> dict[str, str]:
    """Genera la ficha explicativa didáctica en español para cualquier regla de Wazuh."""
    rid = str(rule_id).strip()
    try:
        lvl = int(level)
    except Exception:
        lvl = 0

    if lvl >= 12:
        sev_label = "🚨 CRÍTICO"
        sev_badge = "🔴"
    elif lvl >= 8:
        sev_label = "⚠️ ALTO"
        sev_badge = "🟠"
    elif lvl >= 4:
        sev_label = "⚡ MEDIO"
        sev_badge = "🟡"
    else:
        sev_label = "ℹ️ INFORMATIVO"
        sev_badge = "🟢"

    known = _RULE_SOC_EXPLANATIONS.get(rid)
    if known:
        return {
            "rule_id": rid,
            "level": str(lvl),
            "severity_label": sev_label,
            "severity_badge": sev_badge,
            "title": known["title"],
            "risk": known["risk"],
            "remediation": known["remediation"],
            "category": known["category"],
        }

    # Heurística dinámica basada en descripción y grupos
    desc_clean = description or f"Regla Wazuh #{rid}"
    groups_list = groups or []
    groups_str = " · ".join(groups_list) if groups_list else "Seguridad del Sistema"

    # Generar deducción comprensible
    desc_lower = desc_clean.lower()
    if "sudo" in desc_lower:
        cat = "Privilegios / Sudo"
        risk = "Acción administrativa con privilegios de superusuario ejecutada en el host."
        remed = "Verificar que la orden esté autorizada en el manual de procedimientos."
    elif "ssh" in desc_lower or "authentication" in desc_lower or "login" in desc_lower:
        cat = "Autenticación y Accesos"
        risk = "Intento o establecimiento de enlace de credenciales en el sistema."
        remed = "Auditar IP de origen y asegurar que no haya intentos de fuerza bruta."
    elif "fim" in desc_lower or "syscheck" in desc_lower or "file" in desc_lower:
        cat = "Integridad de Archivos (FIM)"
        risk = "Alteración en atributos, permisos o contenido de un archivo del sistema."
        remed = "Verificar si fue producto de una actualización legítima o modificación manual."
    elif "vulnerab" in desc_lower or "cve" in desc_lower:
        cat = "Vulnerabilidades (CVE)"
        risk = "Software con vulnerabilidad de seguridad conocida expuesto a explotación."
        remed = "Aplicar el último parche de seguridad o actualizar el paquete correspondiente."
    elif "firewall" in desc_lower or "iptables" in desc_lower or "ufw" in desc_lower or "drop" in desc_lower:
        cat = "Defensa de Red / Firewall"
        risk = "Paquetes no deseados, escaneo o conexiones denegadas por el cortafuegos."
        remed = "Revisar si la IP intentó conexiones a múltiples puertos cerrados."
    else:
        cat = groups_str
        risk = f"Evento correlacionado por el motor de reglas de Wazuh con severidad {lvl}/15."
        remed = "Revisar los detalles forenses del evento en el registro de alertas."

    return {
        "rule_id": rid,
        "level": str(lvl),
        "severity_label": sev_label,
        "severity_badge": sev_badge,
        "title": desc_clean,
        "risk": risk,
        "remediation": remed,
        "category": cat,
    }


def explain_network_port_risk(port: int | str, protocol: str = "tcp", process: str = "") -> dict[str, str]:
    """Evalúa la superficie de ataque y el riesgo operativo de un puerto en escucha."""
    p = str(port).strip()
    proto = str(protocol).upper()
    proc = str(process).strip() or "Servicio del sistema"

    high_risk_ports = {
        "21": ("FTP (Sin cifrar)", "⚠️ ALTO", "Transmite credenciales en texto plano. Usar SFTP en su lugar."),
        "22": ("SSH (Shell Seguro)", "⚡ MEDIO", "Expuesto a ataques constantes de fuerza bruta. Restringir a red interna o VPN."),
        "23": ("Telnet (Inseguro)", "🚨 CRÍTICO", "Protocolo obsoleto y vulnerable a sniffing. Debe deshabilitarse inmediatamente."),
        "25": ("SMTP (Correo)", "⚡ MEDIO", "Posible uso como Open Relay si la configuración es incorrecta."),
        "53": ("DNS", "ℹ️ BAJO", "Servicio de resolución de nombres. Requiere protección contra amplificación."),
        "80": ("HTTP (Sin cifrar)", "⚡ MEDIO", "Tráfico web en texto plano. Redirigir a HTTPS (Puerto 443)."),
        "443": ("HTTPS (Web Seguro)", "ℹ️ BAJO", "Canal web cifrado estándar. Mantener certificados TLS al día."),
        "3306": ("MySQL / MariaDB", "⚠️ ALTO", "Base de datos expuesta en red. No debe exponerse a interfaces públicas."),
        "3389": ("RDP (Escritorio Remoto)", "🚨 CRÍTICO", "Blanco primario de ataques de ransomware. Aislar tras VPN con MFA."),
        "5432": ("PostgreSQL", "⚠️ ALTO", "Base de datos expuesta. Debe escuchar solo en localhost (127.0.0.1)."),
        "8001": ("SOC Dashboard (Wazuh-WAHA)", "ℹ️ SOC", "Panel de visualización y comando del SOC."),
        "8765": ("Relay Wazuh-WAHA", "ℹ️ SOC", "API y motor de alertas del ecosistema."),
        "55000": ("Wazuh Manager API", "ℹ️ SOC", "Canal de administración REST del clúster Wazuh."),
        "1514": ("Wazuh Remoted (Agentes)", "ℹ️ SOC", "Túnel seguro cifrado AES para recepción de eventos de agentes."),
        "1515": ("Wazuh Authd (Registro)", "ℹ️ SOC", "Servicio de enrolamiento y generación de claves de agentes."),
    }

    if p in high_risk_ports:
        name, sev, advice = high_risk_ports[p]
    else:
        name = f"Puerto {p}/{proto} ({proc})"
        sev = "⚡ MEDIO" if int(p) < 1024 else "ℹ️ NORMAL"
        advice = "Verificar si este servicio requiere acceso desde toda la red o si puede filtrarse."

    return {
        "port": p,
        "protocol": proto,
        "service_name": name,
        "severity": sev,
        "process": proc,
        "advice": advice,
    }


def explain_user_account_risk(user: dict[str, Any]) -> dict[str, str]:
    """Evalúa el nivel de privilegio y el riesgo asociado a una cuenta de usuario."""
    uname = str(user.get("user_name", "-"))
    uid = str(user.get("uid", "-"))
    gid = str(user.get("gid", "-"))
    shell = str(user.get("shell") or "-")
    home = str(user.get("home") or "-")

    is_root = uid == "0" or uname == "root"
    is_interactive = any(s in shell for s in ("bash", "sh", "zsh", "fish")) and not any(n in shell for n in ("nologin", "false"))

    if is_root:
        if uname != "root":
            status = "🚨 PUERTA TRASERA / SUPERUSUARIO CLONADO"
            risk = "Cuenta con UID 0 que no es 'root'. Indicador muy grave de compromiso del sistema."
            advice = "Eliminar de inmediato la cuenta y auditar /etc/passwd."
        else:
            status = "🔴 SUPERUSUARIO LEGÍTIMO (ROOT)"
            risk = "Control absoluto del sistema. Debe protegerse contra acceso remoto directo."
            advice = "Deshabilitar PermitRootLogin en SSH y requerir sudo con trazabilidad."
    elif is_interactive:
        status = "🔵 USUARIO CON CONSOLA INTERACTIVA"
        risk = "Cuenta capaz de iniciar sesión y ejecutar órdenes en la shell del sistema operativo."
        advice = "Asegurar que utilice contraseña robusta o llave SSH y que tenga MFA."
    else:
        status = "⚪ CUENTA DE SERVICIO / DAEMON"
        risk = "Cuenta restringida para ejecución de procesos en segundo plano sin shell interactiva."
        advice = "Mantener shell como /usr/sbin/nologin o /bin/false."

    return {
        "username": uname,
        "uid": uid,
        "gid": gid,
        "shell": shell,
        "home": home,
        "status_label": status,
        "risk_explanation": risk,
        "security_advice": advice,
    }


def build_wazuh_module_breakdown(profile: dict[str, Any]) -> dict[str, Any]:
    """
    Construye el desglose modular exhaustivo y pedagógico de la postura de seguridad
    de un agente Wazuh para transporte al Reporte PDF, Dashboard y Canales de Notificación.
    """
    aid = str(profile.get("agent_id", "?"))
    aname = profile.get("name") or profile.get("agent_name") or f"agente-{aid}"
    ip = profile.get("ip") or "127.0.0.1"
    os_info = profile.get("os", {}) or {}

    modules: dict[str, Any] = {}

    # ─────────────────────────────────────────────────────────────────────────
    # MÓDULO 1: Seguridad de Configuración y Hardening (CIS Benchmark - SCA)
    # ─────────────────────────────────────────────────────────────────────────
    sca = profile.get("sca", {}) or {}
    failed_checks = sca.get("failed_checks", []) or []
    sca_score = float(sca.get("score", 0.0))

    sca_breakdown = []
    for check in failed_checks:
        localized = localize_cis_check(check)
        cid = str(check.get("id") or check.get("check_id") or "SCA")
        sca_breakdown.append({
            "check_id": cid,
            "title": localized["title"],
            "severity": "⚠️ ALTO" if "shadow" in localized["title"].lower() or "root" in localized["title"].lower() else "⚡ MEDIO",
            "rule_broken": f"Control CIS #{cid}: {check.get('title', 'Violación de estándar de configuración')}",
            "risk_explanation": localized["rationale"],
            "remediation_command": localized["remediation"],
        })

    modules["sca"] = {
        "module_name": "Seguridad de Configuración (CIS Benchmark - SCA)",
        "module_code": "WAZUH_MOD_SCA",
        "description": "Audita la postura de fortificación del SO frente a estándares internacionales.",
        "score": sca_score,
        "passed_count": sca.get("pass", 0),
        "failed_count": sca.get("fail", 0),
        "total_checks": sca.get("total_checks", 0),
        "policy_name": sca.get("name", "CIS Benchmark"),
        "policy_id": sca.get("policy_id", "cis"),
        "broken_rules": sca_breakdown,
    }

    # ─────────────────────────────────────────────────────────────────────────
    # MÓDULO 2: Monitoreo de Integridad de Archivos (FIM / Syscheck)
    # ─────────────────────────────────────────────────────────────────────────
    fim = profile.get("fim", {}) or {}
    fim_files = fim.get("recent_files", []) or []
    fim_total = fim.get("total_monitored", len(fim_files))

    fim_items = []
    for f in fim_files[:20]:
        f_path = str(f.get("file", "-"))
        fim_items.append({
            "file_path": f_path,
            "rule_code": "Regla Wazuh #550 / #554 (Integridad FIM)",
            "severity": "⚡ MEDIO (Nivel 7)",
            "size_bytes": f.get("size", 0),
            "permissions": f.get("perm", "-"),
            "owner": f.get("uname", "-"),
            "date": f.get("date", "-"),
            "checksum_md5": f.get("md5", "-"),
            "explanation": "El archivo es supervisado por Syscheck para alertar ante cualquier sustitución, inyección o cambio no autorizado.",
        })

    modules["fim"] = {
        "module_name": "Monitoreo de Integridad de Archivos (FIM / Syscheck)",
        "module_code": "WAZUH_MOD_FIM",
        "description": "Rastrea modificaciones, alteraciones de permisos y firmas hash en archivos críticos.",
        "monitored_files_count": fim_total,
        "recent_monitored_items": fim_items,
        "status_summary": f"{fim_total:,} archivos supervisados activamente" if fim_total else "Supervisión activa",
    }

    # ─────────────────────────────────────────────────────────────────────────
    # MÓDULO 3: Detección de Malware y Rootkits (Rootcheck)
    # ─────────────────────────────────────────────────────────────────────────
    rootcheck = profile.get("rootcheck", {}) or {}
    root_items = rootcheck.get("items", []) or []
    root_total = rootcheck.get("total_items", len(root_items))

    root_breakdown = []
    for r in root_items[:15]:
        root_breakdown.append({
            "event": r.get("event", "Anomalía de comportamiento"),
            "file": r.get("file", "-"),
            "rule_code": "Regla Wazuh #510 (Rootcheck Anomaly)",
            "severity": "🚨 CRÍTICO (Nivel 7-10)",
            "risk_explanation": "Posible presencia de llamadas interceptadas, archivos ocultos o troyanos en memoria del sistema.",
            "remediation": "Inspeccionar el proceso causante y verificar la integridad de las librerías compartidas del sistema.",
        })

    modules["rootcheck"] = {
        "module_name": "Detección de Malware, Rootkits y Anomalías (Rootcheck)",
        "module_code": "WAZUH_MOD_ROOTCHECK",
        "description": "Detecta rootkits en kernel y espacio de usuario, puertas traseras y llamadas ocultas.",
        "total_anomalies": root_total,
        "items": root_breakdown,
        "status_summary": "✅ Sin rootkits ni anomalías detectadas" if root_total == 0 else f"⚠️ {root_total} anomalías detectadas",
    }

    # ─────────────────────────────────────────────────────────────────────────
    # MÓDULO 4: Alertas SIEM y Detecciones Correlacionadas
    # ─────────────────────────────────────────────────────────────────────────
    detections = profile.get("recent_detections", []) or []
    detections_breakdown = []

    for d in detections[:25]:
        rid = str(d.get("rule_id") or d.get("id") or "0")
        lvl = d.get("level", 0)
        desc = str(d.get("description", ""))
        grps = d.get("groups", [])
        explained = explain_wazuh_rule(rid, lvl, desc, grps)
        detections_breakdown.append({
            "rule_id": rid,
            "level": str(lvl),
            "severity_badge": explained["severity_badge"],
            "severity_label": explained["severity_label"],
            "rule_broken": f"Regla #{rid}: {explained['title']}",
            "category": explained["category"],
            "what_happened": desc,
            "risk_explanation": explained["risk"],
            "remediation_advice": explained["remediation"],
            "timestamp": d.get("timestamp", "-"),
        })

    modules["siem_alerts"] = {
        "module_name": "Alertas SIEM y Eventos Correlacionados",
        "module_code": "WAZUH_MOD_SIEM",
        "description": "Incidentes e indicadores de compromiso correlacionados por el motor de reglas de Wazuh.",
        "total_events": len(detections),
        "high_severity_count": sum(1 for d in detections if int(d.get("level") or 0) >= 8),
        "critical_count": sum(1 for d in detections if int(d.get("level") or 0) >= 12),
        "broken_rules": detections_breakdown,
    }

    # ─────────────────────────────────────────────────────────────────────────
    # MÓDULO 5: Superficie de Red y Sockets en Escucha (Syscollector)
    # ─────────────────────────────────────────────────────────────────────────
    ports_data = profile.get("ports", {}) or {}
    ports_items = ports_data.get("items", []) or []
    ports_breakdown = []

    for p in ports_items[:25]:
        p_num = p.get("local_port") or p.get("port") or 0
        proto = p.get("protocol") or "tcp"
        proc = p.get("process") or "-"
        evaluated = explain_network_port_risk(p_num, proto, proc)
        ports_breakdown.append({
            "port": str(p_num),
            "protocol": proto.upper(),
            "local_ip": p.get("local_ip", "0.0.0.0"),
            "process": proc,
            "pid": p.get("pid", 0),
            "state": p.get("state", "listening"),
            "service_evaluated": evaluated["service_name"],
            "severity": evaluated["severity"],
            "risk_and_advice": evaluated["advice"],
        })

    modules["network_surface"] = {
        "module_name": "Superficie de Red y Puertos en Escucha (Syscollector)",
        "module_code": "WAZUH_MOD_NET_SURFACE",
        "description": "Inventario de sockets y servicios locales expuestos hacia la red local o Internet.",
        "total_ports_count": ports_data.get("total_count", len(ports_items)),
        "ports_breakdown": ports_breakdown,
    }

    # ─────────────────────────────────────────────────────────────────────────
    # MÓDULO 6: Cuentas de Usuario y Privilegios del Sistema (Syscollector)
    # ─────────────────────────────────────────────────────────────────────────
    users_data = profile.get("users", {}) or {}
    sample_users = users_data.get("sample_users", []) or []
    users_breakdown = []

    for u in sample_users[:25]:
        evaluated_u = explain_user_account_risk(u)
        users_breakdown.append({
            "username": evaluated_u["username"],
            "uid": evaluated_u["uid"],
            "gid": evaluated_u["gid"],
            "shell": evaluated_u["shell"],
            "home": evaluated_u["home"],
            "status_label": evaluated_u["status_label"],
            "risk_explanation": evaluated_u["risk_explanation"],
            "security_advice": evaluated_u["security_advice"],
        })

    modules["users_access"] = {
        "module_name": "Cuentas de Usuario y Privilegios Locales (Syscollector)",
        "module_code": "WAZUH_MOD_USERS",
        "description": "Auditoría de cuentas del sistema operativo, UID 0, privilegios y shells activos.",
        "total_users_count": users_data.get("total_users", len(sample_users)),
        "users_breakdown": users_breakdown,
    }

    # ─────────────────────────────────────────────────────────────────────────
    # MÓDULO 7: Servicios y Daemons del Sistema (Syscollector)
    # ─────────────────────────────────────────────────────────────────────────
    services_data = profile.get("services", {}) or {}
    sample_services = services_data.get("sample_services", []) or []

    modules["system_services"] = {
        "module_name": "Servicios y Daemons del Sistema (Syscollector)",
        "module_code": "WAZUH_MOD_SERVICES",
        "description": "Supervisión de procesos daemon y persistencias activas en el sistema.",
        "total_services_count": services_data.get("total_services", len(sample_services)),
        "sample_services": sample_services[:30],
    }

    # ─────────────────────────────────────────────────────────────────────────
    # MÓDULO 8: Inventario de Software y SBOM (Syscollector)
    # ─────────────────────────────────────────────────────────────────────────
    software_data = profile.get("software", {}) or {}
    sample_packages = software_data.get("sample_packages", []) or []

    modules["software_inventory"] = {
        "module_name": "Inventario de Software Instalado (SBOM)",
        "module_code": "WAZUH_MOD_SOFTWARE",
        "description": "Catálogo de paquetes y aplicaciones desplegadas en el endpoint.",
        "total_packages_count": software_data.get("total_packages", len(sample_packages)),
        "sample_packages": sample_packages[:30],
    }

    return {
        "agent_id": aid,
        "agent_name": aname,
        "ip": ip,
        "os_summary": f"{os_info.get('name', 'Linux')} {os_info.get('version', '')} ({os_info.get('architecture', 'x86_64')})",
        "modules_count": len(modules),
        "modules": modules,
    }


def format_wazuh_breakdown_notification(breakdown: dict[str, Any], trigger_reason: str = "conexión") -> str:
    """
    Renderiza el desglose completo módulo por módulo en español con formato enriquecido
    para entrega inmediata en los canales de notificación (Telegram / WhatsApp).
    """
    aid = breakdown.get("agent_id", "?")
    aname = breakdown.get("agent_name", "agente")
    ip = breakdown.get("ip", "127.0.0.1")
    os_str = breakdown.get("os_summary", "Linux")
    mods = breakdown.get("modules", {})

    lines = [
        "🛡️ *[DESGLOSE DE SEGURIDAD WAZUH • MÓDULO POR MÓDULO]*",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"🖥️ *Endpoint:* `{aname}` _(ID: {aid})_",
        f"🌐 *Dirección IP:* `{ip}`",
        f"🐧 *Plataforma:* `{os_str}`",
        f"🔔 *Evento:* `Auditoría exhaustiva por {trigger_reason}`",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━",
        "📋 *DESGLOSE DE APARTADOS TÉCNICOS & REGLAS INFRINGIDAS:*",
        "",
    ]

    # 1. SCA CIS
    sca = mods.get("sca", {})
    sca_score = sca.get("score", 0.0)
    failed_checks = sca.get("broken_rules", [])
    lines.append("1️⃣ *Módulo Hardening & CIS Benchmark (SCA):*")
    lines.append(f"   • Cumplimiento: `{sca_score:.1f}%` ({sca.get('passed_count', 0)} aprobadas | {sca.get('failed_count', 0)} falladas)")
    if failed_checks:
        lines.append("   ⚠️ *Reglas/Controles CIS Incumplidos:*")
        for idx, chk in enumerate(failed_checks[:3], 1):
            lines.append(f"   {idx}. *{chk['title']}* ({chk['severity']})")
            lines.append(f"      💡 _Riesgo:_ {chk['risk_explanation']}")
            lines.append(f"      🛠️ _Solución:_ `{chk['remediation_command']}`")
    else:
        lines.append("   ✅ _Sin reglas CIS reprobadas en este análisis._")
    lines.append("")

    # 2. FIM
    fim = mods.get("fim", {})
    lines.append("2️⃣ *Módulo Integridad de Archivos (FIM / Syscheck):*")
    lines.append(f"   • Base de Integridad: `{fim.get('status_summary', 'Activa')}`")
    lines.append("   • Reglas Wazuh: `Regla #550 (Modificado), #554 (Creado), #553 (Borrado)`")
    lines.append("   • Propósito: Detectar reemplazo de binarios o inyección de backdoors.")
    lines.append("")

    # 3. Rootcheck
    root = mods.get("rootcheck", {})
    lines.append("3️⃣ *Módulo Antimalware y Anomalías (Rootcheck):*")
    lines.append(f"   • Diagnóstico: `{root.get('status_summary', 'Normal')}`")
    lines.append("   • Regla Wazuh: `Regla #510 (Host Anomaly Detection - Nivel 7)`")
    lines.append("")

    # 4. Alertas SIEM
    siem = mods.get("siem_alerts", {})
    alerts_list = siem.get("broken_rules", [])
    lines.append("4️⃣ *Módulo Detecciones SIEM & Incidentes Correlacionados:*")
    lines.append(f"   • Total Alertas: `{siem.get('total_events', 0)} eventos` (🚨 `{siem.get('high_severity_count', 0)} críticas/altas`)")
    if alerts_list:
        lines.append("   ⚠️ *Desglose de Reglas de Seguridad Roto/Detectadas:*")
        for idx, a in enumerate(alerts_list[:3], 1):
            lines.append(f"   {idx}. *{a['rule_broken']}* [{a['severity_badge']} L{a['level']}]")
            lines.append(f"      💡 _Riesgo:_ {a['risk_explanation']}")
            lines.append(f"      🛠️ _Acción:_ {a['remediation_advice']}")
    else:
        lines.append("   ✅ _Sin alertas de intrusión recientes._")
    lines.append("")

    # 5. Red y Puertos
    net = mods.get("network_surface", {})
    ports_breakdown = net.get("ports_breakdown", [])
    lines.append("5️⃣ *Módulo Superficie de Red y Puertos en Escucha (Syscollector):*")
    lines.append(f"   • Sockets en Escucha: `{net.get('total_ports_count', 0)} puertos abiertos`")
    sample_ports = [f"{p['port']}/{p['protocol']} ({p['process']})" for p in ports_breakdown[:4]]
    if sample_ports:
        lines.append(f"   • Servicios expuestos: `{' · '.join(sample_ports)}`")
    lines.append("")

    # 6. Cuentas de Usuario
    users = mods.get("users_access", {})
    lines.append("6️⃣ *Módulo Cuentas de Usuario y Privilegios (Syscollector):*")
    lines.append(f"   • Total Cuentas Auditadas: `{users.get('total_users_count', 0)} cuentas`")
    lines.append("   • Regla de Acceso: Restringir UID 0 exclusivamente al superusuario root.")
    lines.append("")

    # 7. Servicios
    services = mods.get("system_services", {})
    lines.append("7️⃣ *Módulo Servicios y Daemons del Sistema:*")
    lines.append(f"   • Daemons Supervisados: `{services.get('total_services_count', 0)} servicios en monitoreo continuo`")
    lines.append("")

    # 8. Software SBOM
    sw = mods.get("software_inventory", {})
    lines.append("8️⃣ *Módulo Inventario de Software (SBOM):*")
    lines.append(f"   • Paquetes en Catálogo: `{sw.get('total_packages_count', 0):,} aplicaciones registradas`")

    lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━")
    lines.append("📄 *Reporte Forense Detallado:*")
    lines.append(f"• Descargar PDF con los 13 apartados explicados: `/reporte {aid}`")
    lines.append(f"• Ver desglose CIS completo: `/sca {aid}`")
    lines.append(f"• Inspeccionar puertos: `/puertos_agente {aid}`")

    return "\n".join(lines)
