# wazuh-waha — SOC Operations & Notification Suite

Ecosistema de monitoreo, telemetría y respuesta ante incidentes para **Wazuh SIEM**, con entrega de alertas multicanal (**WhatsApp**, **Telegram**, **Email**), dashboard analítico en tiempo real, bot interactivo de administración y generador de **reportes forenses en PDF**.

```
Wazuh Manager (Alertas de seguridad)
  └── Regla activada (level >= 8)
       └── Integración whatsapp_alert.py
            └── POST http://<relay-host>:8765/alerts
                 ├── Deduplicación concurrente con fcntl.flock
                 ├── Enriquecimiento contextual con IA Local (Ollama LLM)
                 ├── Despacho a WhatsApp (WAHA) + Telegram + Email SMTP
                 ├── Journaling de tráfico y telemetría SSE
                 └── Generación de Reportes Forenses PDF por Agente
```

---

## 🌟 Capacidades del Sistema

- 📱 **Alertas Multicanal**: Despacho instantáneo a WhatsApp (WAHA), Telegram Bot y Email corporativo con plantillas por severidad.
- 🤖 **Bot Administrativo de Telegram**: Control total del SOC desde el móvil (`/reporte`, `/servicios`, `/silenciar`, `/reiniciar`, `/scan`, `/agentes`).
- 📊 **Dashboard Web en Tiempo Real**: Panel React 18 + Vite con stream de eventos SSE, métricas en vivo y editor de entorno `.env`.
- 📄 **Generador de Reportes Forenses PDF**: Informes de seguridad ejecutivos y técnicos por agente (Hardware, SO, Red, Sockets, Procesos, Software, SCA CIS, FIM y Alertas).
- 🧠 **Diagnóstico con IA Local (Ollama)**: Análisis inteligente de causa raíz sin enviar telemetría a nubes externas.
- 🛡️ **Seguridad BFF & RBAC**: Autenticación estricta con API keys, cookies seguras HTTP-only y rate limiting preventivo.

---

## 🚀 Quickstart

1. **Clonar repositorio**:
   ```bash
   git clone <repo-url> wazuh-waha && cd wazuh-waha
   ```
2. **Configurar entorno**:
   ```bash
   cp .env.example .env
   # Generar API keys seguras
   openssl rand -hex 24
   ```
3. **Instalar el Relay**:
   ```bash
   bash scripts/install-wazuh-waha.sh
   ```
4. **Instalar en la VM de Wazuh Manager**:
   Seguir instrucciones en [`docs/deployment.md`](docs/deployment.md#2-instalar-en-la-vm-del-manager).
5. **Diagnóstico general**:
   ```bash
   bash scripts/diagnose.sh
   ```

---

## 📄 Reportes Forenses de Agentes (PDF)

El sistema genera informes detallados de actividad y postura de seguridad por agente:

- **Desde el Dashboard**: Acceder a la tarjeta "Reportes de Actividad por Agente", seleccionar el endpoint y descargar el PDF.
- **Desde Telegram**: Enviar `/reporte <agent_id>` (ej. `/reporte 001`) al bot para recibir el documento directamente en el chat.
- **Vía API REST**:
  ```bash
  curl -H "X-Api-Key: $RELAY_API_KEY" http://localhost:8765/api/v1/reports/agent/001 -o reporte_001.pdf
  ```

---

## 🛠️ Comandos Frecuentes de Operación

```bash
# Estado del relay y healthcheck
systemctl status wazuh-waha
curl http://localhost:8765/health

# Contenedores Docker (WAHA y Dashboard)
docker ps --filter "name=wazuh-waha"

# Diagnóstico integral de la stack
bash scripts/diagnose.sh

# Logs en tiempo real del relay
journalctl -u wazuh-waha -f

# Recuperación de sesión WAHA si se traba
bash scripts/recover-waha.sh
```

---

## 📂 Estructura del Repositorio

```
wazuh-waha/
├── README.md                     # Documento central
├── ARCHITECTURE.md               # Arquitectura técnica detallada
├── CHANGELOG.md                  # Historial de versiones y cambios
├── .env.example                  # Plantilla de variables de configuración
├── docker-compose.yml            # Orquestación de WAHA y Dashboard
├── docs/                         # Documentación operativa y técnica
│   └── archive/                  # Planes históricos archivados
├── dashboard/                    # Interfaz web React + Vite + TypeScript
├── relay/                        # Servicio central FastAPI + Uvicorn
│   ├── pyproject.toml            # Dependencias Python
│   ├── systemd/                  # Units systemd del servicio y watchdog
│   └── wazuh_waha/               # Módulo Python (API, Notifiers, Telemetría)
├── manager-side/                 # Configuraciones para la VM Wazuh Manager
├── scripts/                      # Utilidades y scripts de mantenimiento
├── backups/                      # Copias de seguridad de alertas y entorno
└── tests/                        # Suite de pruebas automatizadas
```

---

## 📚 Documentación

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — Decisiones de diseño y flujo de datos.
- [`docs/README.md`](docs/README.md) — Índice completo de documentación técnica.
- [`docs/deployment.md`](docs/deployment.md) — Instalación paso a paso.
- [`docs/troubleshooting.md`](docs/troubleshooting.md) — Matriz de errores comunes.
- [`dashboard/README.md`](dashboard/README.md) — Documentación del Dashboard Web.
