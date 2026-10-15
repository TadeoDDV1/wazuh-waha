# wazuh-waha — SOC Operations & Notification Suite

Ecosistema unificado de monitoreo, telemetría y respuesta ante incidentes para **Wazuh SIEM**, con entrega de alertas multicanal (**WhatsApp**, **Telegram**, **Email**), bot interactivo de administración SOC, auditoría automática de endpoints con recomendaciones de hardening CIS Benchmark y generador de **reportes forenses oficiales en PDF**.

```
Wazuh Manager (Alertas de seguridad & Conexiones de Agente)
  ├── Regla SIEM activada (level >= 8) o conexión de agente (regla 57150 / watcher)
  └── Integración whatsapp_alert.py
       └── POST http://<relay-host>:8765/alerts
            ├── Deduplicación concurrente con fcntl.flock
            ├── Enriquecimiento contextual y traducción técnica al español
            ├── Auditoría de conexión y recomendaciones de hardening CIS Benchmark
            ├── Despacho a WhatsApp (WAHA) + Telegram + Email SMTP
            ├── Journaling de tráfico y telemetría SSE en vivo
            └── Generación de Reportes Forenses PDF SOC v2.0 por Agente
```

---

## 🌟 Capacidades Principales

- 📱 **Alertas Multicanal en Español**: Despacho instantáneo a WhatsApp (WAHA), Telegram Bot y Email corporativo con plantillas formateadas y clasificación de severidad (Crítico, Alto, Medio, Bajo).
- 🔍 **Auditoría Automática de Conexión & Hardening CIS**: Al conectarse o reconectarse un endpoint, Wazuh dispara escaneos de integridad (Syscheck/FIM) y genera una tarjeta de auditoría con barra de progreso, controles CIS Benchmark fallados, análisis de riesgo y **comandos directos de remediación** en español.
- 🤖 **Bot Administrativo de Telegram (39 Comandos)**: Control total del SOC desde el chat móvil (`/comandos`, `/reporte`, `/agentes`, `/sca`, `/analizar_agente`, `/red`, `/sitios`, `/servicios`, `/silenciar`, `/reiniciar`).
- 📄 **Reportes Forenses PDF SOC v2.0**: Expedientes forenses completos con 10 apartados técnicos explicados (Hardware, Sistema Operativo, Interfaces de Red, Destinos Web, Procesos Activos, Inventario SBOM, Seguridad CIS SCA, Integridad FIM y Detecciones SIEM).
- 📊 **Dashboard Web en Tiempo Real**: Panel de control React 18 + Vite con stream de eventos SSE, métricas en vivo y configuración dinámica.
- 🛡️ **Seguridad BFF & RBAC**: Autenticación estricta mediante API keys, cookies seguras HTTP-only y rate limiting preventivo.

---

## 🚀 Despliegue e Instalación

### 1. Requisitos Previos
- Servidor Linux (Ubuntu, Debian, CentOS o Arch Linux).
- Python 3.11+ con soporte para `venv`.
- Docker y Docker Compose (para contenedor WAHA y Dashboard).
- Instancia activa de Wazuh Manager (v4.x).

### 2. Configuración del Relay
```bash
# 1. Clonar repositorio
git clone https://github.com/TadeoDDV1/wazuh-waha.git && cd wazuh-waha

# 2. Configurar variables de entorno
cp .env.example .env
# Generar claves de seguridad
openssl rand -hex 24

# 3. Instalar entorno e iniciar servicios del Relay
bash scripts/install-wazuh-waha.sh

# 4. Iniciar contenedores WAHA y Dashboard
docker compose up -d
```

### 3. Configuración en la VM del Wazuh Manager
1. Copiar las reglas locales a la máquina del Wazuh Manager:
   ```bash
   sudo cp manager-side/rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml
   sudo chown root:wazuh /var/ossec/etc/rules/local_rules.xml
   sudo chmod 0640 /var/ossec/etc/rules/local_rules.xml
   ```
2. Instalar el script de integración `whatsapp_alert.py`:
   ```bash
   sudo cp manager-side/integrations/custom/whatsapp_alert.py /var/ossec/integrations/custom/whatsapp_alert.py
   sudo chown root:wazuh /var/ossec/integrations/custom/whatsapp_alert.py
   sudo chmod 0750 /var/ossec/integrations/custom/whatsapp_alert.py
   ```
3. Insertar el bloque de integración en `/var/ossec/etc/ossec.conf`:
   ```xml
   <integration>
     <name>custom-whatsapp</name>
     <hook_url>http://127.0.0.1:8765/alerts</hook_url>
     <api_key>TU_RELAY_API_KEY</api_key>
     <alert_format>json</alert_format>
   </integration>
   ```
4. Reiniciar Wazuh Manager:
   ```bash
   sudo systemctl restart wazuh-manager.service
   ```

---

## 🤖 Catálogo de Comandos del Bot de Telegram

El bot incluye un catálogo categorizado que puedes consultar escribiendo `/comandos` o explorando por área funcional:

| Categoría | Comando de Acceso | Funcionalidades Clave |
|---|---|---|
| **👥 Agentes y Endpoints** | `/comandos agentes` | `/agentes`, `/agente <id>`, `/analizar_agente <id>`, `/sca <id>`, `/fim <id>`, `/procesos <id>`, `/paquetes <id>`, `/puertos_agente <id>`, `/sitios_agente <id>`, `/reiniciar_agente <id>`, `/agregar_agente`, `/eliminar_agente`, `/comando_agente <so>` |
| **📄 Reportes Ejecutivos** | `/comandos reportes` | `/reporte <agent_id>` (Genera y envía el informe PDF oficial SOC v2.0) |
| **🌐 Red y Telemetría** | `/comandos red` | `/red` (sockets activos y puertos), `/sitios` (auditoría web externa), `/escanear_red` (sondeo inmediato) |
| **🚨 Alertas y Reglas** | `/comandos alertas` | `/alertas [n]`, `/buscar_alerta <termino>`, `/silenciar <rule_id>`, `/reactivar <rule_id>`, `/reglas_silenciadas`, `/limpiar_cache`, `/reglas` |
| **📱 Pasarela WhatsApp** | `/comandos waha` | `/waha_status`, `/waha_restart`, `/waha_qr` (código QR interactivo en el chat), `/enviar_wa <numero> <msg>` |
| **⚙️ Configuración SOC** | `/comandos config` | `/config`, `/set_nivel <8-15>`, `/set_canal <whatsapp\|telegram\|email> <on\|off>`, `/set_phone`, `/set_email`, `/set_dedup`, `/set_wazuh_ip`, `/sync_comandos` |
| **🖥️ Servidor y Host** | `/comandos sistema` | `/status` (CPU, RAM, Disco, Uptime), `/servicios` (salud de Wazuh, Relay, WAHA, Dashboard), `/reiniciar <servicio>`, `/logs [n]`, `/audit [n]`, `/ip`, `/kpis`, `/ping` |

---

## 📄 Informes Forenses PDF SOC v2.0

Cada reporte oficial generado incluye un encabezado institucional, foliado dinámico (`Página X de Y`), tarjetas ejecutivas KPI y 10 apartados de auditoría:

1. **Identificación y Registro**: Hostname, ID, IP de enlace, versión de agente y último keep-alive.
2. **Capacidad y Hardware**: CPU, núcleos, MHz, memoria RAM detallada y número de serie de placa.
3. **Sistema Operativo**: Distribución, release, kernel exacto y arquitectura.
4. **Interfaces de Red**: Adaptadores físicos/virtuales, IPv4, MAC, MTU y volumen RX/TX.
5. **Destinos de Red & Sockets**: Conexiones activas en tiempo real, puertos, procesos y categorización.
6. **Procesos en Ejecución**: Binarios activos, PIDs, usuarios ejecutores y estado.
7. **Software Instalado (SBOM)**: Inventario de paquetes, versiones y proveedores homologados.
8. **Seguridad CIS Benchmark (SCA)**: Score porcentual, controles fallados y remediaciones directas.
9. **Integridad de Archivos (FIM)**: Archivos modificados o añadidos, tamaño, permisos y hashes MD5.
10. **Detecciones SIEM**: Historial de alertas correlacionadas por severidad (L1 a L15).

---

## 🛠️ Comandos de Operación y Diagnóstico

```bash
# Estado y salud de los servicios
systemctl status wazuh-waha
curl http://localhost:8765/health

# Verificación de contenedores
docker ps --filter "name=wazuh-waha"

# Diagnóstico integral del sistema
bash scripts/diagnose.sh

# Logs en vivo del Relay
journalctl -u wazuh-waha -f

# Ejecución de pruebas unitarias
PYTHONPATH=. relay/.venv/bin/pytest tests/ -v
```

---

## 📂 Estructura del Proyecto

```
wazuh-waha/
├── README.md                     # Documentación maestra y guía de arquitectura
├── GEMINI.md                     # Reglas de operación del asistente
├── docker-compose.yml            # Orquestación de contenedores WAHA y Dashboard
├── dashboard/                    # Panel Web React 18 + Vite + TypeScript
├── relay/                        # Núcleo del servicio FastAPI + Uvicorn
│   ├── pyproject.toml            # Dependencias y configuración de empaquetado
│   ├── systemd/                  # Archivos de servicio systemd y watchdog
│   └── wazuh_waha/               # Módulos Python (API, Notifiers, Telemetría, SCA)
├── manager-side/                 # Reglas SIEM, snippets y scripts para Wazuh Manager
├── scripts/                      # Scripts de despliegue, recuperación y diagnóstico
└── tests/                        # Suite automatizada de pruebas unitarias
```
