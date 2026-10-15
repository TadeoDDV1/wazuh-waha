"""
cis_translator.py — Motor de traducción, localización y adaptación técnica
al español de chequeos de seguridad CIS Benchmark (SCA) y recomendaciones de hardening.
"""

from __future__ import annotations

import re
from typing import Any

# Diccionario especializado de mapeo para los chequeos CIS más frecuentes en Linux
_CIS_CATALOG_ES: dict[str, dict[str, str]] = {
    # Módulos de kernel y sistemas de archivos
    "Ensure unused filesystems kernel modules are not available.": {
        "title": "Deshabilitar módulos de kernel para sistemas de archivos en desuso",
        "rationale": "Los módulos de kernel no requeridos aumentan la superficie de ataque y permiten a atacantes cargar código malicioso o vulnerar el sistema.",
        "remediation": "Descargar módulos no usados (modprobe -r) y bloquearlos en /etc/modprobe.d/blacklist.conf",
    },
    "Ensure /tmp is a separate partition.": {
        "title": "Configurar /tmp como una partición o volumen independiente",
        "rationale": "Aislar /tmp evita que el desbordamiento de archivos temporales colapse el sistema raíz (/) y permite aplicar políticas de montaje seguras.",
        "remediation": "Habilitar la unidad de montaje systemd: 'systemctl unmask tmp.mount && systemctl enable --now tmp.mount'",
    },
    "Ensure nodev option set on /tmp partition.": {
        "title": "Configurar la opción de montaje 'nodev' en la partición /tmp",
        "rationale": "Impide la creación o uso de dispositivos especiales de bloques o caracteres en /tmp, bloqueando vectores de escalada de privilegios.",
        "remediation": "Editar /etc/fstab y agregar 'nodev' a las opciones de montaje de /tmp",
    },
    "Ensure nosuid option set on /tmp partition.": {
        "title": "Configurar la opción de montaje 'nosuid' en la partición /tmp",
        "rationale": "Bloquea la ejecución de binarios con elevación de privilegios (SUID/SGID) en /tmp, impidiendo escaladas locales de atacantes.",
        "remediation": "Editar /etc/fstab y agregar 'nosuid' a las opciones de montaje de /tmp",
    },
    "Ensure noexec option set on /tmp partition.": {
        "title": "Configurar la opción de montaje 'noexec' en la partición /tmp",
        "rationale": "Impide la ejecución directa de binarios o scripts descargados en /tmp, mitigando la ejecución de payloads o malware temporal.",
        "remediation": "Editar /etc/fstab y agregar 'noexec' a las opciones de montaje de /tmp",
    },
    "Ensure /var is a separate partition.": {
        "title": "Configurar /var como partición independiente",
        "rationale": "Evita que el crecimiento acelerado de logs, colas de correo o bases de datos sature el sistema de archivos principal.",
        "remediation": "Asignar un volumen dedicado para /var en /etc/fstab",
    },
    "Ensure /var/tmp is a separate partition.": {
        "title": "Configurar /var/tmp como partición independiente",
        "rationale": "Aísla archivos temporales de larga duración para aplicar políticas restrictivas (nosuid, nodev, noexec).",
        "remediation": "Configurar /var/tmp en /etc/fstab con opciones: nosuid,nodev,noexec",
    },
    "Ensure /var/log is a separate partition.": {
        "title": "Configurar /var/log en partición independiente",
        "rationale": "Garantiza la disponibilidad del sistema si ocurre una sobrecarga o ataque de denegación de servicio por llenado masivo de logs.",
        "remediation": "Asignar partición dedicada a /var/log en /etc/fstab",
    },
    "Ensure /var/log/audit is a separate partition.": {
        "title": "Configurar /var/log/audit en partición independiente",
        "rationale": "Protege los registros forenses de auditoría para que no se pierdan o sobrescriban ante saturación de otros logs.",
        "remediation": "Configurar partición dedicada para el demonio auditd en /var/log/audit",
    },
    "Ensure /home is a separate partition.": {
        "title": "Configurar /home en partición independiente",
        "rationale": "Aísla el almacenamiento de los usuarios del sistema operativo, permitiendo cuotas y opciones restrictivas (nodev).",
        "remediation": "Montar /home en partición separada con opción nodev en /etc/fstab",
    },

    # Permisos de archivos críticos
    "Ensure permissions on /etc/shadow are configured": {
        "title": "Proteger permisos y propietario del archivo /etc/shadow",
        "rationale": "El archivo /etc/shadow contiene los hashes criptográficos de contraseñas. Si es legible por terceros, expone las claves a descifrado offline.",
        "remediation": "chmod 0000 /etc/shadow && chown root:root /etc/shadow",
    },
    "Ensure permissions on /etc/gshadow are configured": {
        "title": "Proteger permisos del archivo /etc/gshadow",
        "rationale": "Contiene los hashes de contraseñas de grupos y credenciales sensibles que deben restringirse al superusuario.",
        "remediation": "chmod 0000 /etc/gshadow && chown root:root /etc/gshadow",
    },
    "Ensure permissions on /etc/passwd are configured": {
        "title": "Proteger permisos de escritura en /etc/passwd",
        "rationale": "Si un atacante puede escribir en /etc/passwd, puede crear cuentas privilegiadas no autorizadas con UID 0 (root).",
        "remediation": "chmod 0644 /etc/passwd && chown root:root /etc/passwd",
    },
    "Ensure permissions on /etc/group are configured": {
        "title": "Proteger permisos de escritura en /etc/group",
        "rationale": "Evita la modificación no autorizada de membresías en grupos críticos como sudo o adm.",
        "remediation": "chmod 0644 /etc/group && chown root:root /etc/group",
    },
    "Ensure permissions on /etc/shadow- are configured": {
        "title": "Proteger copia de respaldo /etc/shadow-",
        "rationale": "El archivo de respaldo de shadow también almacena hashes de contraseñas y debe estar totalmente restringido.",
        "remediation": "chmod 0000 /etc/shadow- && chown root:root /etc/shadow-",
    },
    "Ensure permissions on /etc/gshadow- are configured": {
        "title": "Proteger copia de respaldo /etc/gshadow-",
        "rationale": "El archivo de respaldo de gshadow contiene hashes de grupos y no debe ser legible por usuarios normales.",
        "remediation": "chmod 0000 /etc/gshadow- && chown root:root /etc/gshadow-",
    },

    # SSH y Acceso Remoto
    "Ensure SSH PermitRootLogin is disabled": {
        "title": "Deshabilitar el inicio de sesión directo de root por SSH",
        "rationale": "Permitir el login directo de root expone al host a ataques constantes de fuerza bruta y elimina la auditoría de quién ingresó al sistema.",
        "remediation": "echo 'PermitRootLogin no' >> /etc/ssh/sshd_config && systemctl restart ssh",
    },
    "Ensure SSH PasswordAuthentication is disabled": {
        "title": "Deshabilitar la autenticación por contraseña en SSH (usar llaves)",
        "rationale": "El uso de contraseñas en SSH es vulnerable a ataques de fuerza bruta, phishing y reutilización de credenciales.",
        "remediation": "Configurar 'PasswordAuthentication no' en /etc/ssh/sshd_config y reiniciar ssh",
    },
    "Ensure SSH MaxAuthTries is set to 4 or less": {
        "title": "Limitar reintentos de autenticación SSH a 4 o menos",
        "rationale": "Reduce la velocidad y éxito de herramientas de ataque de diccionario y fuerza bruta en el puerto SSH.",
        "remediation": "Configurar 'MaxAuthTries 4' en /etc/ssh/sshd_config",
    },
    "Ensure SSH Protocol is set to 2": {
        "title": "Garantizar el uso exclusivo del protocolo SSH v2",
        "rationale": "El protocolo SSH v1 contiene vulnerabilidades criptográficas conocidas de diseño que permiten intercepción de tráfico.",
        "remediation": "Configurar 'Protocol 2' en /etc/ssh/sshd_config",
    },
    "Ensure SSH X11 forwarding is disabled": {
        "title": "Deshabilitar reenvío de X11 en SSH",
        "rationale": "El reenvío X11 permite que un atacante en el servidor local espíe eventos de teclado o ventanas del cliente SSH.",
        "remediation": "Configurar 'X11Forwarding no' en /etc/ssh/sshd_config",
    },

    # Auditoría, Logging y Servicios
    "Ensure auditd is installed": {
        "title": "Instalar el framework de auditoría de seguridad (auditd)",
        "rationale": "Sin auditd, el kernel no registra llamadas al sistema privilegiadas ni eventos críticos de integridad.",
        "remediation": "Instalar auditd: 'apt-get install -y auditd' o 'yum install audit'",
    },
    "Ensure auditd service is enabled": {
        "title": "Habilitar e iniciar el servicio auditd",
        "rationale": "Garantiza que la auditoría del sistema opere continuamente desde el arranque de la máquina.",
        "remediation": "systemctl enable --now auditd",
    },
    "Ensure auditd service is active": {
        "title": "Verificar que el servicio auditd esté en ejecución activa",
        "rationale": "Registra accesos no autorizados a archivos del sistema y llamadas privilegiadas a nivel de kernel.",
        "remediation": "systemctl restart auditd",
    },
    "Ensure firewall is active": {
        "title": "Asegurar que el cortafuegos del host (UFW / iptables) esté activo",
        "rationale": "Un host sin cortafuegos expone todos sus puertos de escucha directamente a la red sin filtrado perimetral.",
        "remediation": "Activar el cortafuegos: 'ufw enable' o configurar reglas con iptables/nftables",
    },
    "Ensure ufw is installed": {
        "title": "Instalar cortafuegos UFW",
        "rationale": "Proporciona una capa de defensa en profundidad para controlar el tráfico entrante y saliente del endpoint.",
        "remediation": "apt-get install -y ufw && ufw enable",
    },
    "Ensure AppArmor is installed": {
        "title": "Instalar y habilitar el módulo de seguridad AppArmor",
        "rationale": "AppArmor restringe las capacidades de los programas para que no puedan acceder a archivos o recursos fuera de su perfil.",
        "remediation": "apt-get install -y apparmor apparmor-utils && systemctl enable --now apparmor",
    },

    # Políticas de contraseñas y cuentas
    "Ensure password expiration is 365 days or less": {
        "title": "Establecer caducidad máxima de contraseñas (≤ 365 días)",
        "rationale": "La rotación periódica reduce el tiempo de vida útil de contraseñas comprometidas o filtradas.",
        "remediation": "Configurar 'PASS_MAX_DAYS 365' en /etc/login.defs",
    },
    "Ensure password minimum days is 1 or more": {
        "title": "Establecer tiempo mínimo entre cambios de contraseña (≥ 1 día)",
        "rationale": "Impide que los usuarios roten contraseñas repetidamente para volver a usar su clave favorita anterior.",
        "remediation": "Configurar 'PASS_MIN_DAYS 1' en /etc/login.defs",
    },
    "Ensure password expiration warning days is 7 or more": {
        "title": "Configurar aviso previo de caducidad de contraseña (≥ 7 días)",
        "rationale": "Avisa al usuario con antelación para que cambie su clave antes del bloqueo operativo de su cuenta.",
        "remediation": "Configurar 'PASS_WARN_AGE 7' en /etc/login.defs",
    },
    "Ensure default user umask is 027 or more restrictive": {
        "title": "Configurar umask predeterminado a 027 o más restrictivo",
        "rationale": "Garantiza que los archivos creados por los usuarios no tengan permisos de lectura o ejecución para otros usuarios.",
        "remediation": "Configurar 'UMASK 027' en /etc/login.defs y /etc/profile",
    },
    "Ensure core dumps are restricted": {
        "title": "Restringir la generación de volcados de memoria (Core Dumps)",
        "rationale": "Los volcados de memoria pueden exponer contraseñas, tokens y claves privadas en texto plano almacenadas en RAM.",
        "remediation": "echo '* hard core 0' >> /etc/security/limits.conf && sysctl -w fs.suid_dumpable=0",
    },
    "Ensure address space layout randomization (ASLR) is enabled": {
        "title": "Habilitar aleatorización de direcciones de memoria (ASLR)",
        "rationale": "ASLR dificulta enormemente la ejecución de ataques basados en Buffer Overflow y explotación de memoria.",
        "remediation": "sysctl -w kernel.randomize_va_space=2",
    },
}


def _translate_title_heuristic(title: str) -> str:
    """Traduce heurísticamente títulos comunes de normas CIS Benchmark."""
    t = title.strip()
    # Coincidencia directa
    for k, v in _CIS_CATALOG_ES.items():
        if k.lower() in t.lower() or t.lower() in k.lower():
            return v["title"]

    patterns = [
        (r"^Ensure\s+(.*?)\s+is not available\.?$", r"Deshabilitar disponibilidad de \1"),
        (r"^Ensure\s+(.*?)\s+is not installed\.?$", r"Desinstalar software no requerido: \1"),
        (r"^Ensure\s+(.*?)\s+is installed\.?$", r"Instalar y verificar servicio: \1"),
        (r"^Ensure\s+(.*?)\s+is disabled\.?$", r"Deshabilitar servicio o protocolo: \1"),
        (r"^Ensure\s+(.*?)\s+is enabled\.?$", r"Habilitar y proteger: \1"),
        (r"^Ensure\s+(.*?)\s+is active\.?$", r"Asegurar ejecución activa de: \1"),
        (r"^Ensure permissions on\s+(.*?)\s+are configured\.?$", r"Configurar permisos seguros en \1"),
        (r"^Ensure permissions on\s+(.*?)\s+are\s+(.*?)\.?$", r"Asegurar permisos \2 en \1"),
        (r"^Ensure\s+(.*?)\s+is a separate partition\.?$", r"Configurar \1 como partición independiente"),
        (r"^Ensure\s+(.*?)\s+is set to\s+(.*?)\.?$", r"Configurar parámetro \1 en \2"),
        (r"^Ensure\s+(.*?)\s+is configured\.?$", r"Asegurar configuración adecuada de \1"),
        (r"^Ensure\s+(.*?)\s+are configured\.?$", r"Asegurar configuración adecuada de \1"),
        (r"^Ensure\s+(.*?)\s+is restricted\.?$", r"Restringir acceso y uso de \1"),
        (r"^Disable\s+(.*?)\.?$", r"Deshabilitar \1"),
        (r"^Enable\s+(.*?)\.?$", r"Habilitar \1"),
    ]

    for p, repl in patterns:
        if re.search(p, t, flags=re.IGNORECASE):
            res = re.sub(p, repl, t, flags=re.IGNORECASE)
            return res.rstrip(".")

    return t


def _translate_rationale_heuristic(rationale: str) -> str:
    """Traduce y resume el riesgo/motivo de seguridad en español."""
    r = rationale.strip()
    if not r:
        return "Reducir la superficie de ataque y fortalecer la postura de seguridad del endpoint."

    # Mapeo exacto
    for k, v in _CIS_CATALOG_ES.items():
        if k.lower() in r.lower():
            return v["rationale"]

    # Reemplazo de conceptos técnicos en inglés
    replacements = [
        ("While loadable filesystem kernel modules are a convenient method of modifying the running kernel, this can be abused by attackers",
         "Los módulos de kernel cargables que no se usan aumentan la superficie de ataque ante intrusos."),
        ("Making /tmp its own file system allows an administrator to set additional mount options",
         "Aislar /tmp en su propia partición permite aplicar opciones de montaje restrictivas contra malware."),
        ("Since the /tmp filesystem is not intended to support devices",
         "Impide que atacantes creen nodos de dispositivos especiales para saltarse los controles del sistema."),
        ("Since the /tmp filesystem is only intended for temporary file storage, set this option to ensure that users cannot create setuid",
         "Evita que se ejecuten o depositen binarios con permisos elevados (SUID/SGID) en carpetas temporales."),
        ("The /etc/shadow file contains user password hashes",
         "El archivo contiene los hashes de contraseñas y debe restringirse para evitar ataques de fuerza bruta offline."),
        ("Permitting root login over SSH increases the surface of brute-force attacks",
         "Permitir el login de root por SSH expone al sistema a ataques de fuerza bruta y elimina la trazabilidad."),
        ("attackers", "atacantes"),
        ("privilege escalation", "escalada de privilegios"),
        ("unauthorized access", "acceso no autorizado"),
        ("denial of service", "denegación de servicio"),
        ("brute force", "fuerza bruta"),
        ("reduce attack surface", "reducir la superficie de ataque"),
        ("compromised", "comprometido"),
        ("vulnerabilities", "vulnerabilidades"),
        ("malicious software", "software malicioso"),
        ("buffer overflow", "desbordamiento de búfer"),
    ]

    res = r
    for eng, esp in replacements:
        res = re.sub(re.escape(eng), esp, res, flags=re.IGNORECASE)

    # Limpiar longitud estética para Telegram/WhatsApp
    if len(res) > 140:
        res = res[:137] + "..."
    return res


def _translate_remediation_heuristic(remediation: str) -> str:
    """Limpia la sintaxis cruda de remediación de Wazuh y la presenta en español conciso."""
    rem = remediation.strip()
    if not rem:
        return "Aplicar configuración recomendada por el fabricante o directriz CIS."

    # Mapeo exacto
    for k, v in _CIS_CATALOG_ES.items():
        if k.lower() in rem.lower():
            return v["remediation"]

    # Limpiar prefijos de sintaxis CIS como "- IF - the module is available in the running kernel: - Unload the filesystem..."
    if "- IF - the module is available" in rem:
        return "Descargar módulo del kernel en ejecución (modprobe -r) y añadirlo a /etc/modprobe.d/blacklist.conf"
    if "systemctl unmask tmp.mount" in rem:
        return "systemctl unmask tmp.mount && systemctl enable --now tmp.mount"
    if "- IF - a separate partition exists for /tmp" in rem:
        # Extraer opciones sugeridas
        m_opts = re.search(r"add\s+([a-zA-Z0-9,]+)\s+to the fourth field", rem)
        opts = m_opts.group(1) if m_opts else "nodev,nosuid,noexec"
        return f"Editar /etc/fstab y añadir '{opts}' a la partición /tmp"

    # Reemplazos genéricos
    rem = re.sub(r"^Run the following command to configure (.*?):?\s*", r"Ejecutar: \1 -> ", rem, flags=re.IGNORECASE)
    rem = re.sub(r"^Edit the (.*?) file and set (.*?):?\s*", r"Editar \1 y configurar \2 -> ", rem, flags=re.IGNORECASE)

    if len(rem) > 180:
        rem = rem[:177] + "..."
    return rem


def localize_cis_check(check: dict[str, Any]) -> dict[str, str]:
    """Recibe un control CIS en inglés y retorna una versión completamente localizada y adaptada al español."""
    raw_title = check.get("title", "") or ""
    raw_rationale = check.get("rationale", "") or ""
    raw_remediation = check.get("remediation", "") or ""

    # 1. Verificar si coincide con el catálogo maestro
    catalog_entry = None
    for k, entry in _CIS_CATALOG_ES.items():
        if k.lower() == raw_title.lower() or k.lower() in raw_title.lower():
            catalog_entry = entry
            break

    if catalog_entry:
        return {
            "title": catalog_entry["title"],
            "rationale": catalog_entry["rationale"],
            "remediation": catalog_entry["remediation"],
        }

    # 2. Traducción heurística
    return {
        "title": _translate_title_heuristic(raw_title),
        "rationale": _translate_rationale_heuristic(raw_rationale),
        "remediation": _translate_remediation_heuristic(raw_remediation),
    }
