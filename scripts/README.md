# Scripts de Operación y Mantenimiento — Wazuh-WAHA

Utilidades ejecutables para diagnóstico, instalación, sincronización, watchdogs y despliegue del sistema.

---

## 🛠️ Catálogo de Scripts

| Script | Descripción y Propósito | Permisos Requeridos | Modo Interactivo |
|---|---|---|---|
| `diagnose.sh` | Diagnóstico general e inspección read-only de toda la stack | A veces (`sudo` para sockets/units) | No |
| `auto-setup.sh` | Configuración guiada y comprobación inicial del entorno | Sí (`sudo`) | Sí |
| `install-wazuh-waha.sh` | Instalación completa de units systemd, directorios y permisos | Sí (`sudo`) | Sí |
| `deploy-server.sh` | Despliegue automatizado del servidor relay y servicios auxiliares | Sí (`sudo`) | No |
| `update_server_vm.sh` | Valida API REST Wazuh, conectividad y sincronización con la VM | No | No |
| `fix-wazuh-waha.sh` | Reinicio forzado del relay en caso de estado zombie o timeout | Sí (`sudo`) | Sí |
| `fix_venv_shebangs.sh` | Reparación de shebangs de `.venv` tras traslados o renombres de ruta | No | No |
| `recover-waha.sh` | Secuencia limpia (STOP + espera + START) para sesiones atascadas de WAHA | No | No |
| `waha-watchdog.sh` | Monitoreo recurrente de la sesión WAHA y auto-recuperación | No | No |
| `boot-notify.py` | Envío de reporte de salud por correo y WhatsApp tras el encendido | No | No |
| `boot_stack_status.sh` | Helper de evaluación de estado de servicios para boot-notify | No | No |
| `check-agent-connected.sh`| Validación de socket activo (`:1514`) hacia el Wazuh Manager | No | No |
| `notify-agent-failure.sh` | Notificación de alerta inmediata si el agente Wazuh cae (`OnFailure=`) | No | No |
| `notify-relay-failure.sh` | Notificación de alerta si el servicio relay cae (`OnFailure=`) | No | No |
| `render_manager_snippet.py` | Generador del bloque XML de integración para `ossec.conf` | No | No |
| `sync_relay_env.sh` | Sincronización bidireccional entre `.env` y `/etc/wazuh-waha/relay.env` | Sí (`sudo`) | No |
| `watch_manager_ip.sh` | Detección de cambios de IP (drift) en el manager y reconfiguración | Sí (`sudo`) | No |
| `diag-vbox.sh` | Diagnóstico específico para interfaces de red en VirtualBox | No | No |
| `waha-notify.py` | Despacho CLI directo de mensajes de texto a WhatsApp vía WAHA | No | No |
