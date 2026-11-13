# wazuh-waha — SOC Operations & Notification Suite

<div align="center">

![Wazuh-WAHA Banner](dashboard/src/assets/hero.png)

[![Release](https://img.shields.io/badge/Release-v2.0.0--SOC-blue.svg)](https://github.com/TadeoDDV1/wazuh-waha/releases)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB.svg?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18.3+-61DAFB.svg?logo=react&logoColor=black)](https://react.dev)
[![Wazuh SIEM](https://img.shields.io/badge/Wazuh-4.8%2B%20%2F%204.9%2B-00599C.svg?logo=wazuh&logoColor=white)](https://wazuh.com)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED.svg?logo=docker&logoColor=white)](https://www.docker.com)
[![License](https://img.shields.io/badge/License-Proprietary%20%2F%20LARCAD-red.svg)](#licencia)

**Plataforma Unificada de Operaciones de Seguridad Defensiva, Telemetría en Tiempo Real, Alertas Multicanal y Expedientes Forenses Automatizados para Wazuh SIEM/XDR.**

[Despliegue Rápido](#-despliegue-e-instalación) •
[Arquitectura](#-arquitectura-y-flujo-de-datos) •
[Capacidades](#-capacidades-principales) •
[Reportes Forenses PDF](#-informes-forenses-pdf-soc-v20-13-secciones) •
[Bot de Telegram](#-catálogo-del-bot-de-telegram-39-comandos) •
[API REST](#-referencia-de-la-api-rest) •
[Variables de Entorno](#-matriz-de-configuración-env) •
[Doc. Técnica (.docx)](docs/DOCUMENTACION_TECNICA_WAZUH_WAHA.docx) •
[Manual de Usuario (.docx)](docs/MANUAL_DE_USUARIO_WAZUH_WAHA.docx)

</div>

---

## 📖 Visión General

**wazuh-waha** es una suite de ingeniería de seguridad defensiva de grado industrial que elimina la brecha operativa entre la detección de incidentes en el motor **Wazuh SIEM/XDR** y la acción de respuesta inmediata del equipo de analistas del SOC.

Actúa como una capa intermedia inteligente de automatización, orquestación, telemetría continua y auditoría forense que:
1. **Despacha alertas multicanal enriquecidas** a **WhatsApp** (WAHA), **Telegram** y **Correo Electrónico (SMTP/HTML)**, traduciendo firmas crudas a lenguaje técnico en español con categorización de riesgo, ubicación geográfica e indicadores de compromiso (IoCs).
2. **Audita automáticamente cualquier endpoint al conectarse o reconectarse**, disparando evaluaciones de cumplimiento **CIS Benchmark (SCA)** y chequeos de integridad de archivos (**FIM/Syscheck**), prescribiendo comandos directos de mitigación (*Hardening Playbooks*).
3. **Genera Expedientes Forenses Oficiales en PDF (v2.0)** estructurados en **13 apartados forenses** con **gráficas vectoriales nativas** de cumplimiento y distribución de alertas.
4. **Proporciona un Dashboard Web React 19 + Vite de alto rendimiento**, optimizado con *code-splitting* (`React.lazy`), badge de estado reactivo `🟢 SSE Live`, terminales de tráfico persistentes sobre SSH multiplexado (`ControlMaster`) y consola interactiva WebSockets (`xterm.js`).
5. **Ofrece un Bot Móvil de Telegram con 39 comandos administrativos** que permiten controlar el SOC, los agentes y el servidor desde cualquier teléfono móvil autorizado.

---

## 🏛️ Arquitectura y Flujo de Datos

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                 WAZUH SIEM / MANAGER                                   │
│                                                                                        │
│   [ Endpoints / Agentes ] ────(1514/TCP)────► [ ossec-analysisd / syscheck / SCA ]      │
│                                                          │                             │
│                                                  (Regla >= Nivel 8                     │
│                                                   o Regla 57150)                       │
│                                                          ▼                             │
│                                               [ ossec-integratord ]                    │
│                                                          │                             │
│                                            whatsapp_alert.py (Integración)             │
└──────────────────────────────────────────────────────────┬─────────────────────────────┘
                                                           │ POST /alerts (JSON)
                                                           ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              RELAY CORE (FastAPI / Uvicorn)                            │
│                                                                                        │
│  ├── 🛡️ Autenticación: Verificación de RELAY_API_KEY / Rate-Limit por IP / Trusted XFF  │
│  ├── 🔒 Concurrencia: Bloqueo seguro fcntl.flock & Deduplicación TTL en disco          │
│  ├── 🌐 Localización: cis_translator.py & wazuh_breakdown.py (Explicación y Mitigación)│
│  ├── 🕵️ Agente Watcher: Disparo proactivo de FIM/SCA ante eventos de conexión (57150)   │
│  ├── 📊 Gráficas Vectoriales: Motor ReportLab Drawing (Donut CIS & Bar Severity)       │
│  ├── 📜 Journaling: traffic.jsonl, auditoría de mutaciones (audit.jsonl) y backups     │
│  └── 📡 Stream SSE & SSH ControlMaster: Telemetría de tráfico en vivo (tail -F)        │
└──────────────┬────────────────────────┬─────────────────────────┬──────────────────────┘
               │                        │                         │
               ▼                        ▼                         ▼
      ┌─────────────────┐      ┌─────────────────┐       ┌─────────────────┐
      │ WhatsApp (WAHA) │      │  Telegram Bot   │       │   Email SMTP    │
      │   (Chromium     │      │   (39 Comandos  │       │  (Plantillas    │
      │   WebJS/REST)   │      │   Interactivos) │       │   HTML SOC)     │
      └─────────────────┘      └─────────────────┘       └─────────────────┘
               │                        │                         │
               └────────────────────────┼─────────────────────────┘
                                        ▼
                   ┌──────────────────────────────────────────┐
                   │        DASHBOARD WEB SOC (React 19)      │
                   │                                          │
                   │  ├── 🟢 SSE Live Traffic Terminal        │
                   │  ├── 🌐 Network & Sockets Terminal (ss)  │
                   │  ├── 📊 Panel Gráfico Interactivo (SVG)  │
                   │  ├── 📄 Visor & Descarga de Reportes PDF │
                   │  ├── 💻 Consola Web Interactiva (PTY/WS) │
                   │  └── ⚙️ Control Seguro de Módulos Wazuh │
                   └──────────────────────────────────────────┘
```

---

## 🌟 Capacidades Principales

### 1. 📱 Alertas de Seguridad Multicanal en Español
- **WhatsApp**: Envío estructurado con emojis forenses, resumen de amenaza, IP de origen, usuario, proceso ejecutor y recomendaciones directas al teléfono del administrador.
- **Telegram Bot**: Despacho instantáneo en Markdown enriquecido con botones de acción rápida y envío directo de reportes PDF adjuntos.
- **Email Corporativo**: Notificaciones con diseño profesional HTML/CSS adaptado para SOCs, compatible con servidores SMTP (Gmail, Exchange, Postfix) y Hyvor Relay.
- **Deduplicación Concurrente Segura**: Evita tormentas de alertas repetitivas utilizando bloqueos de archivos en disco (`fcntl.flock(LOCK_EX)`).
- **Tolerancia a Fallos y Reintentos**: Política de retroceso exponencial (*exponential backoff*) y auto-recuperación transparente ante caídas transitorias de los contenedores.

### 2. 🔍 Auditoría Automática de Conexión y Hardening CIS
- Al registrarse o reconectarse un agente (evento Wazuh `57150`), el motor `agent_analyzer.py` dispara una auditoría inmediata:
  1. Ejecuta escaneos forzados de integridad de archivos (**FIM/Syscheck**).
  2. Consulta la evaluación de seguridad **CIS Benchmark (SCA)**.
  3. Mapea la superficie de ataque (puertos en escucha, sockets de red y software SBOM).
  4. Genera una tarjeta de auditoría forense con porcentaje de cumplimiento, lista de directivas falladas y **comandos exactos de remediación** en terminal.

### 3. 📄 Expedientes Forenses Oficiales PDF SOC v2.0 (13 Secciones)
- Informes forenses ejecutivos y técnicos generados en milisegundos mediante **ReportLab**.
- Portada institucional, número de folio oficial dinámico (`SOC-REP-<id>-v2`), marcas de tiempo ISO, sellos de confidencialidad y pie de página con paginación (`Página X de Y`).
- **Gráficas Vectoriales Nativas**:
  - **Donut Radial de Cumplimiento CIS SCA**: Porcentaje central en negrita, anillo verde/rojo proporcional y desglose de controles aprobados vs fallados.
  - **Barra Apilada de Severidad de Alertas SIEM**: Distribución segmentada de incidentes (Crítico L12+, Alto L8-11, Medio L5-7, Bajo L1-4).
- Desglose forense exhaustivo de 13 apartados técnicos (Hardware, SO, Interfaces, Sockets, Procesos, Paquetes SBOM, Usuarios, Servicios, CIS SCA, FIM, Alertas y Dictamen Ejecutivo).

### 4. 📊 Dashboard Web SOC de Alto Rendimiento (React 19 + Vite)
- **Optimización Extrema de Bundle (Reducción del 71%)**: Arquitectura de carga diferida (`React.lazy` + `Suspense`) que divide los módulos secundarios en chunks independientes (`vendor-react`, `vendor-core`, `vendor-libs`), reduciendo el bundle inicial a **167 kB**.
- **Badge Reactivo de Telemetría**: Indicador visual `🟢 SSE Live` / `🟡 Reconectando` en la barra de navegación que informa en tiempo real la salud de los streams `/traffic/stream` y `/snapshot/stream`.
- **Pestaña Gráfica Forense Interactiva**: Gráficos circulares SVG animados, barras de severidad y medidores de recursos en tiempo real antes de descargar el PDF.
- **Terminal de Tráfico Persistente**: Captura de eventos mediante multiplexación SSH (`ControlMaster` + `ControlPersist`) ejecutando `tail -n 100 -F` en `archives.json` / `alerts.json`, eliminando el consumo excesivo de CPU y logins PAM repetitivos.
- **Consola Web Interactiva (xterm.js)**: Emulador de terminal PTY sobre WebSockets para diagnosticar el Relay o conectar por SSH al Manager bajo estrictos controles RBAC.

### 5. 🤖 Consola Móvil por Telegram (39 Comandos)
- Control total del SOC desde dispositivos móviles con autenticación estricta por `TELEGRAM_CHAT_ID`.
- Permite solicitar reportes forenses en PDF (`/reporte <id>`), auditar agentes (`/analizar_agente <id>`), silenciar alertas ruidosas (`/silenciar <regla>`), verificar puertos (`/red`), consultar dominios (`/sitios`) y reiniciar contenedores (`/reiniciar relay`).

---

## 📄 Informes Forenses PDF SOC v2.0 (13 Secciones)

Cada reporte oficial generado por el motor de reportes incluye una portada institucional, Foliado Único (`SOC-REP-<id>-v2`), tarjetas KPI ejecutivas, dos paneles de gráficas vectoriales y **13 apartados forenses detallados**:

| N.º | Sección Forense | Módulo Fuente de Wazuh | Objetivo Técnico & Implicación Operativa del SOC |
|---|---|---|---|
| **§01** | **Identificación y Registro del Agente** | Wazuh API Core | Verifica identidad del endpoint, hostname, IP de enlace, versión del agente y sincronización continua de keep-alive. |
| **§02** | **Capacidad y Consumo de Hardware** | `syscollector_hardware` | Audita CPU, núcleos, MHz, memoria RAM total/utilizada/libre y número de serie criptográfico de placa base. |
| **§03** | **Sistema Operativo y Plataforma** | `syscollector_os` | Identifica distribución, versión exacta del kernel, arquitectura y release para gestión de ciclo de vida (EOL) y riesgos LPE. |
| **§04** | **Interfaces de Red y Tráfico Acumulado** | `syscollector_netiface` | Mapea adaptadores Ethernet, Wi-Fi y Loopback con direcciones IPv4/IPv6, máscaras, MACs, MTU y bytes RX/TX. |
| **§05** | **Superficie de Red: Sockets y Destinos** | `syscollector_ports` / `net` | Inventario de puertos a la escucha (LISTEN) en TCP/UDP, PIDs asociados y auditoría de dominios externos comunicados. |
| **§06** | **Procesos en Ejecución** | `syscollector_processes` | Lista binarios activos, argumentos, identificadores PID, usuarios ejecutores y consumo de memoria. |
| **§07** | **Software Instalado y Paquetería (SBOM)** | `syscollector_packages` | Inventario de paquetes y aplicaciones para correlación continua contra la base de datos nacional de CVEs. |
| **§08** | **Auditoría de Cuentas y Privilegios** | `syscollector_users` | Audita cuentas locales, identificadores UID/GID, shells asignadas y pertenencia a grupos privilegiados (`sudo`, `wheel`). |
| **§09** | **Servicios y Daemons del Sistema** | `syscollector_services` | Supervisa servicios del sistema (systemd/init), estado de ejecución (running/stopped) y tipo de inicio. |
| **§10** | **Seguridad de Configuración (SCA — CIS)** | `wazuh_sca` | Evaluación de hardening contra directivas CIS Benchmark. Incluye **Gráfica Donut Vectorial** y comandos de remediación paso a paso. |
| **§11** | **Integridad FIM & Antimalware (Rootcheck)** | `wazuh_syscheck` / `rootcheck` | Rastrear alteraciones en archivos críticos (/etc, binarios), sumas hash MD5/SHA256, permisos y firmas rootcheck activas. |
| **§12** | **Detecciones y Alertas SIEM Recientes** | `wazuh_alerts` | Registro de incidentes correlacionados con **Gráfica de Barra Apilada de Severidad** (Crítico L12+, Alto L8-11, Medio L5-7, Bajo L1-4). |
| **§13** | **Dictamen Ejecutivo y Recomendaciones SOC** | Motor Forense SOC Suite | Matriz de nivel de riesgo global (**BAJO**, **MEDIO**, **ALTO**, **CRÍTICO**) con playbook técnico de acciones preventivas inmediatas. |

---

## 🤖 Catálogo del Bot de Telegram (39 Comandos)

El Bot de Telegram cuenta con un catálogo estructurado accesible escribiendo `/comandos` en el chat:

### 👥 1. Agentes y Endpoints (`/comandos agentes`)
* `/agentes` — Lista todos los agentes registrados, su ID, IP, sistema operativo y estado.
* `/agente <id>` — Muestra la ficha forense condensada del agente (hardware, uptime, seguridad).
* `/analizar_agente <id>` — Dispara una auditoría forzada FIM y SCA con recomendaciones inmediatas.
* `/sca <id>` — Consulta el reporte de cumplimiento de seguridad CIS Benchmark y directivas falladas.
* `/fim <id>` — Lista los últimos archivos alterados, añadidos o eliminados detectados por Syscheck.
* `/procesos <id>` — Muestra los procesos en ejecución y sus PIDs en el agente.
* `/paquetes <id>` — Consulta el inventario SBOM de software y bibliotecas instaladas.
* `/puertos_agente <id>` — Lista los puertos TCP/UDP abiertos y en escucha en el host.
* `/sitios_agente <id>` — Identifica los dominios externos y destinos IP a los que se conecta el host.
* `/reiniciar_agente <id>` — Envía la orden remota al Wazuh Manager para reiniciar el demonio del agente.
* `/agregar_agente <nombre> <ip>` — Inscribe un nuevo agente en el SIEM y devuelve su clave de registro.
* `/eliminar_agente <id>` — Da de baja y elimina definitivamente a un agente del inventario.
* `/comando_agente <so>` — Genera el comando de instalación en una línea para Ubuntu, Debian, Arch, Windows o macOS.

### 📄 2. Reportes Ejecutivos (`/comandos reportes`)
* `/reporte <agent_id>` — Compila el **Expediente Forense Oficial PDF SOC v2.0** con 13 secciones y gráficas vectoriales y lo envía adjunto al chat.

### 🌐 3. Red y Telemetría (`/comandos red`)
* `/red` — Muestra el estado de sockets y puertos clave del stack (1514, 55000, 8765, 3001, 8001, 22).
* `/sitios` — Auditoría de conexiones salientes activas y clasificación de destinos web.
* `/escanear_red` — Fuerza un sondeo y muestreo inmediato de sockets en toda la red monitoreada.

### 🚨 4. Alertas y Reglas SIEM (`/comandos alertas`)
* `/alertas [n]` — Muestra las últimas `n` alertas de seguridad procesadas por el SOC (por defecto 5).
* `/buscar_alerta <termino>` — Busca alertas históricas por dirección IP, usuario o regla.
* `/silenciar <rule_id>` — Suprime temporalmente las notificaciones de una regla ruidosa.
* `/reactivar <rule_id>` — Vuelve a activar las notificaciones para una regla previamente silenciada.
* `/reglas_silenciadas` — Muestra el listado de reglas actualmente en estado de supresión.
* `/limpiar_cache` — Purga la memoria caché de deduplicación de alertas y sockets de red.
* `/reglas` — Muestra las reglas personalizadas activas en `local_rules.xml`.

### 📱 5. Pasarela WhatsApp (`/comandos waha`)
* `/waha_status` — Comprueba la salud del contenedor WAHA, el motor WEBJS y la sesión activa.
* `/waha_restart` — Reinicia el contenedor Docker de WAHA y reconecta la sesión de mensajería.
* `/waha_qr` — Envía al chat de Telegram el código QR actual para vincular WhatsApp en segundos.
* `/enviar_wa <numero> <msg>` — Envía un mensaje manual de WhatsApp de prueba a un número especificado.

### ⚙️ 6. Configuración del SOC (`/comandos config`)
* `/config` — Muestra la configuración activa del SOC, umbrales y canales habilitados.
* `/set_nivel <8-15>` — Modifica dinámicamente el nivel de severidad mínimo para alertar.
* `/set_canal <whatsapp|telegram|email> <on|off>` — Habilita o deshabilita un canal en caliente.
* `/set_phone <numero>` — Actualiza el número telefónico receptor de alertas de WhatsApp.
* `/set_email <correo>` — Actualiza la dirección de correo electrónico receptora de alertas.
* `/set_dedup <segundos>` — Modifica la ventana de deduplicación de alertas (`RELAY_DEDUP_TTL`).
* `/set_wazuh_ip <ip>` — Modifica la dirección IP de conexión al Wazuh Manager.
* `/sync_comandos` — Registra y sincroniza la lista de comandos oficiales con la API de Telegram.

### 🖥️ 7. Servidor y Sistema (`/comandos sistema`)
* `/status` — Muestra carga de CPU, consumo de RAM, espacio en disco, uptime y hostname del servidor.
* `/servicios` — Diagnostica la salud de systemd y Docker (Wazuh, Relay, WAHA, Dashboard).
* `/reiniciar <servicio>` — Reinicia un servicio (`relay`, `waha`, `dashboard`, `wazuh`).
* `/logs [n]` — Muestra las últimas `n` líneas del registro de eventos del Relay (`journalctl`).
* `/audit [n]` — Muestra las últimas `n` mutaciones y accesos registrados en `audit.jsonl`.
* `/ip` — Consulta la dirección IP pública y los adaptadores de red locales del servidor.
* `/kpis` — Muestra métricas operativas (alertas recibidas, suprimidas, despachadas y latencia).
* `/ping` — Mide la latencia de respuesta y disponibilidad entre el Relay y la API de Telegram.

---

## 🚀 Despliegue e Instalación

### 1. Requisitos del Sistema
- **Sistema Operativo**: Ubuntu 24.04 LTS o Debian 12 (probado y homologado), Arch Linux o CentOS/RHEL.
- **Hardware Recomendado**:
  - Servidor dedicado para wazuh-waha: 4 vCPU, 8 GB de RAM y 25 GB de disco SSD.
  - Servidor compartido (Wazuh Manager + wazuh-waha): 8 vCPU, 16 GB de RAM y 80 GB de disco SSD.
- **Dependencias**: Docker Engine >= 24.0, Docker Compose Plugin v2, Python >= 3.11, Git, Caddy Server o Nginx.

### 2. Instalación en Servidor Dedicado
```bash
# 1. Clonar el repositorio en la ruta estándar de producción
sudo git clone https://github.com/TadeoDDV1/wazuh-waha.git /opt/wazuh-waha
cd /opt/wazuh-waha

# 2. Ejecutar script de pre-verificación (comprueba puertos, firewall y dependencias)
sudo bash scripts/preflight.sh

# 3. Instalación de producción del entorno
sudo bash scripts/install-production.sh
```

El script `install-production.sh` se encarga de:
- Crear el usuario del sistema restringido `wazuh-waha` con su grupo respectivo.
- Establecer las rutas `/var/log/wazuh-waha`, `/var/lib/wazuh-waha` y `/var/backups/wazuh-waha`.
- Crear el entorno virtual en `relay/.venv` e instalar dependencias con `pip`.
- Configurar las unidades systemd `wazuh-waha.service` y `wazuh-waha-watchdog.timer`.
- Generar automáticamente claves criptográficas con `openssl rand -hex 24`.
- Configurar `/etc/caddy/Caddyfile` con soporte TLS y WebSockets.

```bash
# 4. Personalizar las variables de entorno
sudo nano /opt/wazuh-waha/.env

# 5. Desplegar contenedores y arrancar servicios
sudo bash scripts/deploy-production.sh

# 6. Instalar el conector en el Wazuh Manager (local o remoto)
sudo bash scripts/install-manager-side.sh
```

---

## ⚙️ Integración en el Wazuh Manager

Si el Wazuh Manager reside en una máquina virtual o servidor independiente, ejecutar:
```bash
sudo bash scripts/install-manager-side.sh --relay-url http://<IP_RELAY>:8765/alerts --api-key <TU_RELAY_API_KEY>
```

Esto automatiza la configuración de tres componentes clave:
1. **Script de Integración** (`/var/ossec/integrations/custom/whatsapp_alert.py`): Permisos `0750` propiedad de `root:wazuh`.
2. **Reglas Locales SIEM** (`/var/ossec/etc/rules/local_rules.xml`): Habilita la regla `57150` para conexiones y reconexiones de agentes.
3. **Bloque de Integración en `/var/ossec/etc/ossec.conf`**:
```xml
<integration>
  <name>custom-whatsapp</name>
  <hook_url>http://127.0.0.1:8765/alerts</hook_url>
  <api_key>TU_RELAY_API_KEY_AQUI</api_key>
  <alert_format>json</alert_format>
</integration>
```
4. Reinicio automático de `wazuh-manager.service`.

---

## 📡 Referencia de la API REST

El Relay Core expone endpoints REST estructurados bajo OpenAPI/Swagger (desactivado por defecto en producción mediante `ENABLE_DOCS=false`):

| Método | Endpoint | Autenticación | Descripción Operativa |
|---|---|---|---|
| `POST` | `/alerts` | `X-Api-Key` | Ingesta de alertas desde `whatsapp_alert.py` de Wazuh. |
| `GET` | `/health` | Pública | Comprobación de salud mínima (`status`, `service`, `version`). |
| `GET` | `/api/v1/telemetry/stream` | BFF / API Key | Stream SSE de métricas y contadores de telemetría en vivo. |
| `GET` | `/api/v1/telemetry/traffic/stream` | BFF / API Key | Stream SSE de tráfico SIEM en vivo sobre SSH ControlMaster (`tail -F`). |
| `GET` | `/api/v1/telemetry/network/stream` | BFF / API Key | Stream SSE de sockets y conexiones de red en tiempo real (`ss`). |
| `GET` | `/api/v1/reports/agent/{agent_id}` | BFF / API Key | **Descarga del Expediente Forense PDF SOC v2.0 (13 Secciones)**. |
| `GET` | `/api/v1/dashboard/reports/preview/{id}` | BFF / API Key | Datos del snapshot ejecutivo y métricas forenses para el visor web. |
| `POST` | `/api/v1/dashboard/reports/audit/{id}` | BFF / API Key | Dispara escaneo forzado FIM y consulta SCA antes de generar reporte. |
| `POST` | `/api/v1/auth/login` | Rate-Limited | Inicio de sesión en el Dashboard. Emite cookie HttpOnly firmada. |
| `GET` | `/api/v1/auth/session` | Cookie de Sesión | Valida la validez de la sesión activa y devuelve el perfil RBAC. |
| `POST` | `/api/v1/auth/logout` | Cookie de Sesión | Invalida y elimina la cookie de sesión del navegador. |
| `GET` | `/api/v1/dashboard/status` | BFF / API Key | Estado completo de servicios, daemons, memoria y módulos Wazuh. |
| `POST` | `/api/v1/dashboard/notifications/channels` | BFF / API Key | Activa o desactiva canales (WhatsApp, Telegram, Email). |
| `GET` | `/api/v1/dashboard/waha/qr` | BFF / API Key | Devuelve el código QR activo en base64 para vincular WhatsApp. |
| `POST` | `/api/v1/dashboard/wazuh/modules/toggle` | BFF / API Key | Activa/Desactiva módulos (FIM, SCA, etc.) en `agent.conf`. |
| `GET` | `/api/v1/console/targets` | Sesión `full` | Lista los destinos autorizados para la consola web interactiva. |
| `WS` | `/api/v1/console/ws` | Sesión `full` | WebSocket interactivo con PTY bidireccional (xterm.js). |

---

## 🔐 Matriz de Configuración (.env)

Las principales variables de configuración del sistema se encuentran en el archivo `.env`:

| Variable de Entorno | Valor por Defecto | Propósito y Recomendación de Seguridad |
|---|---|---|
| `DOMAIN` | `soc.example.com` | FQDN para Caddy Server y emisión automática de certificados Let's Encrypt. |
| `RELAY_BIND` | `127.0.0.1` | Dirección IP de enlace del Relay (usar `0.0.0.0` solo si el Manager es remoto). |
| `RELAY_PORT` | `8765` | Puerto TCP donde escucha la API del Relay Core. |
| `RELAY_API_KEY` | *(generada)* | Clave maestra compartida requerida por `whatsapp_alert.py` y llamadas REST. |
| `RELAY_DEDUP_TTL` | `300` | Ventana de deduplicación de alertas en segundos (5 minutos por defecto). |
| `RELAY_MIN_LEVEL_UNKNOWN` | `8` | Umbral mínimo de severidad Wazuh para disparar alertas si no hay regla explícita. |
| `WAZUH_SERVER_IP` | `127.0.0.1` | Dirección IP del host donde corre el Wazuh Manager. |
| `WAZUH_MANAGER_API_USER` | `wazuh` | Usuario con permisos de lectura en la API REST de Wazuh (puerto 55000). |
| `WAZUH_MANAGER_API_PASS` | `""` | Contraseña del usuario de la API del Wazuh Manager. |
| `ADMIN_PHONE` | `""` | Número telefónico de destino para WhatsApp (ej. `5219991234567`). |
| `WHATSAPP_ENABLED` | `true` | Conmutador global para despachar alertas a WhatsApp. |
| `WAHA_HOST` | `http://localhost:3000` | URL interna para comunicarse con el contenedor Docker de WAHA. |
| `WAHA_API_KEY` | *(generada)* | Clave de seguridad configurada en el contenedor WAHA. |
| `TELEGRAM_ENABLED` | `false` | Conmutador para habilitar el Bot y las notificaciones por Telegram. |
| `TELEGRAM_BOT_TOKEN` | `""` | Token provisto por `@BotFather` para el bot de Telegram. |
| `TELEGRAM_CHAT_ID` | `""` | ID numérico del chat, grupo o canal de Telegram autorizado. |
| `EMAIL_ALERTS_ENABLED` | `false` | Conmutador para activar notificaciones por correo electrónico. |
| `HOST_NOTIFY_EMAIL` | `true` | Envía también por email los avisos de apagado/arranque/caídas del host. |
| `SMTP_HOST` | `smtp.gmail.com` | Servidor SMTP saliente para envío de alertas por correo. |
| `SMTP_PORT` | `587` | Puerto del servidor SMTP (STARTTLS). |
| `SMTP_USER` | `""` | Usuario de autenticación en el servidor SMTP. |
| `SMTP_PASS` | `""` | Contraseña o token de aplicación para el servidor SMTP. |
| `CONSOLE_ENABLED` | `false` | Habilita o inhabilita el uso de la consola web interactiva en el Dashboard. |
| `CONSOLE_TARGETS` | `local,manager` | Destinos autorizados para conexiones SSH/Locales en la terminal web. |
| `SESSION_COOKIE_SECURE` | `true` | Exige HTTPS para la cookie de sesión del Dashboard (poner `false` en dev HTTP). |

---

## 🛠️ Operación, Mantenimiento y Respaldos

El proyecto cuenta con un menú interactivo en terminal para gestionar todas las operaciones diarias:

```bash
bash admin.sh
```

### Comandos Rápidos de Diagnóstico
```bash
# 1. Comprobar la salud de la API del Relay
curl -s http://127.0.0.1:8765/health | jq .

# 2. Diagnóstico integral automatizado del stack
sudo bash scripts/diagnose.sh

# 3. Comprobación general de salud y conectividad
sudo bash scripts/healthcheck.sh

# 4. Ver logs en tiempo real del Relay Core
journalctl -u wazuh-waha -f

# 5. Ver logs del contenedor WAHA (WhatsApp)
docker logs -f wazuh-waha

# 6. Ver logs del contenedor Dashboard Web
docker logs -f wazuh-waha-dashboard
```

### Avisos automáticos del servidor

El host envía avisos por WhatsApp (si la sesión WAHA está `WORKING`), Telegram
y email cuando ocurre un evento de infraestructura:

- **Apagado o reinicio**: `wazuh-waha-shutdown-notify.service` se ejecuta antes
  de que systemd detenga Docker y avisa del apagado.
- **Vuelta a estar en línea**: `wazuh-waha-boot-notify.service` avisa al
  arrancar con el estado de los servicios y contenedores.
- **Pérdida y recuperación de Internet**: `wazuh-waha-monitor.timer` revisa
  cada minuto y notifica la caída y la duración al reconectar.
- **Caída de relay, contenedores, servicios de Wazuh o sesión WAHA**:
  el mismo monitor avisa en el cambio y cuando se recupera.
- **Fallo del relay**: `OnFailure=` de `wazuh-waha.service` dispara un aviso.
- **Respaldo fallido**: `wazuh-waha-backup.service` dispara su propio aviso.

El historial legible de estos eventos queda en
`/var/log/wazuh-waha/eventos.log` (y `eventos.jsonl` para automatización).
Se puede desactivar el email de estos avisos con `HOST_NOTIFY_EMAIL=false`.

> **Nota sobre cortes de energía:** si el servidor se apaga de golpe (fallo
> eléctrico o hardware), ningún proceso local puede enviar el aviso en ese
> instante. El sistema avisará al volver a arrancar (`boot`) y el monitor
> reportará la recuperación. Para detectar apagones eléctricos en tiempo real
> hace falta un monitor externo (otro host o servicio de heartbeat).

### Historial de logs

```bash
# Genera /var/log/wazuh-waha/historial-wazuh-waha.log con todo el historial
bash scripts/export-logs.sh

# Incluir más líneas y abrirlo con el paginador del sistema
bash scripts/export-logs.sh --lines 5000 --open

# También está disponible desde el Dashboard:
#   Configuración → Logs del Sistema → Descargar historial
```

El archivo consolidado incluye journal del relay/monitor/respaldos, logs
rotados, contenedores WAHA/Dashboard, eventos de infraestructura, últimas
alertas de Wazuh y el listado de respaldos. Los tokens y query strings se
redactan automáticamente.

### Enriquecimiento y explicaciones

Cada alerta se enriquece de forma **determinista** (sin IA) con:

- traducción al español de la descripción y del log,
- resumen en lenguaje simple,
- severidad legible y SLA sugerido,
- activo afectado (criticidad, responsable, ubicación),
- contexto de red (servicio, dirección, país/ASN si hay GeoLite2),
- tácticas y técnicas MITRE ATT&CK,
- indicadores (IPs, dominios, URLs, hashes, usuarios, procesos),
- pasos de remediación con comando copiable.

El dashboard muestra esta información en:

- **Telemetría en vivo**: resumen y acción recomendada en el feed.
- **Alertas recientes**: severidad, resumen y primera acción.
- **Detecciones**: columnas “Qué pasó” y “Qué hacer”, con panel de detalle
  (resumen, contexto, acciones y datos técnicos).

Configuración principal:

```env
ENRICH_ENABLED=true
ENRICH_CACHE_PATH=/var/lib/wazuh-waha/enrichment_cache.sqlite3
ENRICH_ASSETS_FILE=/etc/wazuh-waha/assets.json
ENRICH_GEOIP_DB=/var/lib/wazuh-waha/GeoLite2-City.mmdb
ENRICH_REDACT_PII=true
```

Catálogos incluidos: `relay/wazuh_waha/domain/enrichment/catalog/`.
Se pueden sobreescribir con `ENRICH_CATALOG_DIR` y recargar sin reiniciar:

```bash
curl -X POST -H "X-Api-Key: $RELAY_API_KEY" \
  http://127.0.0.1:8765/api/v1/telemetry/enrichment/reload
```

Endpoints útiles:

- `GET /api/v1/telemetry/enrichment/glossary`
- `GET /api/v1/telemetry/enrichment/catalogs/status`
- `GET /api/v1/telemetry/enrichment/metrics`
- `GET /api/v1/telemetry/events/{id}/enrichment`

### Política de Respaldos

El respaldo se ejecuta automáticamente todos los días a las 03:30
(`wazuh-waha-backup.timer`, con retardo aleatorio de hasta 20 minutos y
`Persistent=true`). Guarda configuración, unidades systemd, configuración de
Wazuh, estado del relay, logs de eventos, alertas recientes y el volumen de
sesión de WAHA, con manifiesto y checksums SHA-256.

```bash
# Generar un respaldo completo manual
sudo bash scripts/backup.sh

# Ver el estado y la fecha del próximo respaldo
systemctl list-timers wazuh-waha-backup.timer
tail -n 30 /var/log/wazuh-waha/backup.log

# Restaurar desde un respaldo previo (es un directorio, no un .tar.gz)
sudo bash scripts/restore.sh /var/backups/wazuh-waha/20261106T205528Z --with-wazuh --with-waha-volume

# Revertir cambios de emergencia (Rollback)
sudo bash scripts/rollback.sh
```

---

## 🛡️ Modelo de Seguridad y Cumplimiento

1. **Principio de Menor Privilegio**: El demonio del Relay corre exclusivamente bajo el usuario del sistema `wazuh-waha` sin privilegios de root.
2. **Patrón Backend-for-Frontend (BFF)**: La `RELAY_API_KEY` maestra jamás se expone al cliente o al navegador. La autenticación en el Dashboard se basa en cookies criptográficas `HttpOnly`, `SameSite=Lax` y `Secure`.
3. **Control de Acceso Basado en Roles (RBAC)**:
   - Rol `full`: Lectura completa, mutación de configuración XML, toggle de canales y uso de terminal web.
   - Rol `read`: Supervisión visual en el Dashboard sin permisos de alteración.
4. **Protección Anti-Fuerza Bruta**: El endpoint `/api/v1/auth/login` restringe el acceso a un máximo de 5 intentos por minuto por dirección IP.
5. **Auditoría Estricta**: Cada inicio de sesión, cambio de configuración o ejecución en consola web queda registrado cronológicamente con firma en `/var/lib/wazuh-waha/audit.jsonl`.
6. **Protección de Tráfico SSH**: Todas las conexiones remotas al Wazuh Manager utilizan llaves Ed25519 con verificación estricta de host (`WAZUH_VM_SSH_STRICT_HOST_KEY=yes`) contra el archivo `known_hosts`.

---

## 📂 Estructura del Repositorio

```
wazuh-waha/
├── README.md                              # Documentación maestra y guía de arquitectura
├── admin.sh                               # Script unificado de administración y diagnóstico interactivo
├── conectar.sh                            # Asistente de sincronización entre Relay y Wazuh Manager
├── docker-compose.yml                     # Orquestación de contenedores Docker (WAHA y Dashboard)
├── docs/                                  # Documentación técnica y manual de usuario
│   ├── DOCUMENTACION_TECNICA_WAZUH_WAHA.docx # Documentación técnica y arquitectura del sistema (.docx)
│   └── MANUAL_DE_USUARIO_WAZUH_WAHA.docx     # Manual de usuario y operaciones SOC paso a paso (.docx)
├── dashboard/                             # Frontend SPA (React 19 + Vite + TypeScript)
│   ├── src/components/                    # Componentes modulares (ReportsCard, LiveTrafficTerminal, etc.)
│   ├── src/context/                       # Contextos de autenticación (BFF) y Dashboard
│   └── vite.config.ts                     # Configuración de empaquetado con manualChunks optimizado
├── relay/                                 # Backend REST API (FastAPI + Uvicorn)
│   ├── systemd/                           # Definiciones de servicio systemd y timers de watchdog
│   └── wazuh_waha/                        # Paquete Python principal
│       ├── api/                           # Enrutadores REST (alerts, telemetry, reports, console, etc.)
│       ├── common/                        # Traffic journal, streams persistentes, sesiones y auditoría
│       ├── domain/                        # Localización CIS, templates multicanal y wazuh_breakdown
│       └── infrastructure/                # Conectores externos (WAHA, Telegram, Wazuh API, SSH Pool)
├── manager-side/                          # Componentes para instalar en el Wazuh Manager
│   ├── integrations/custom/               # whatsapp_alert.py (script hook de integración)
│   └── rules/local_rules.xml              # Reglas SIEM personalizadas (regla 57150 para conexiones)
├── scripts/                               # Scripts automatizados de instalación, despliegue y backup
│   ├── install-production.sh              # Instalador automático en servidor dedicado
│   ├── deploy-production.sh               # Despliegue seguro con verificaciones de salud
│   ├── install-manager-side.sh            # Integrador automático en el Wazuh Manager
│   ├── preflight.sh                       # Comprobación de requisitos y puertos
│   └── backup.sh / restore.sh             # Respaldos completos y recuperación ante desastres
└── tests/                                 # Suite automatizada de pruebas unitarias e integración (pytest)
```

---

## 🧪 Pruebas Automatizadas

El proyecto cuenta con una cobertura integral de pruebas unitarias e integración que validan seguridad, deduplicación, formatos forenses y generación de PDFs:

```bash
# Ejecutar la suite completa de pruebas
PYTHONPATH=. relay/.venv/bin/pytest tests/ -v
```

Métricas de validación:
- **135 pruebas unitarias e integradas exitosas** (100% passed).
- Validación de encabezados válidos en PDF ReportLab v2.0.
- Verificación de políticas de seguridad BFF y saneamiento de entradas.
- Validación sintáctica de archivos XML de Wazuh (`local_rules.xml`, `ossec.conf`).

---

## 📄 Licencia

Este software ha sido diseñado y desarrollado para el monitoreo defensivo y operaciones de seguridad del **Laboratorio Regional de Cómputo de Alto Desempeño (LARCAD)**. Distribuido bajo licencia de uso institucional. Para soporte, adaptaciones o despliegues corporativos, contactar al equipo de ingeniería SOC.
