# Documentación Técnica — Wazuh-WAHA SOC Suite

Índice central de arquitectura, guías de operación, integración y mantenimiento de la plataforma.

---

## 🚀 Despliegue e Instalación
- [Guía de Despliegue General](file:///home/tadeo/Desktop/wazuh-waha/docs/deployment.md) — Instalación y puesta en marcha del Relay y el Dashboard en hosts Linux.
- [Multi-Worker & Concurrencia](file:///home/tadeo/Desktop/wazuh-waha/docs/multi-worker.md) — Consideraciones de escalabilidad y bloqueo seguro (`fcntl.flock`) con múltiples workers de Uvicorn.
- [Notificaciones de Inicio (Boot Notify)](file:///home/tadeo/Desktop/wazuh-waha/docs/boot-notify.md) — Heartbeat automático por Email y WhatsApp tras el encendido del sistema.

## 🛡️ Detecciones y Reglas Wazuh
- [Cobertura de Reglas y Plantillas](file:///home/tadeo/Desktop/wazuh-waha/docs/rules-coverage.md) — Mapeo de `rule_id`, niveles mínimos de severidad y plantillas de notificación personalizadas.

## 🤖 Canales e Inteligencia Artificial
- [Integración con Ollama (IA Local)](file:///home/tadeo/Desktop/wazuh-waha/docs/ollama.md) — Diagnóstico y resumen en lenguaje natural de alertas de seguridad mediante LLM local offline.
- [Notificaciones de Agentes](file:///home/tadeo/Desktop/wazuh-waha/docs/agent-restart-notifications.md) — Detección de reinicios y estados de agentes monitoreados.

## 🔧 Diagnóstico y Operación
- [Resolución de Problemas (Troubleshooting)](file:///home/tadeo/Desktop/wazuh-waha/docs/troubleshooting.md) — Matriz de errores comunes y procedimientos de corrección rápida.
- [Recuperación del Servicio WAHA](file:///home/tadeo/Desktop/wazuh-waha/docs/waha-recovery.md) — Procedimiento para destrabar sesiones atascadas de WhatsApp Web API.

---

## 🗄️ Archivo Histórico
Documentos y planes de versiones y refactorizaciones previas archivados para trazabilidad histórica:
- [`docs/archive/migration-from-wazuh-integration.md`](file:///home/tadeo/Desktop/wazuh-waha/docs/archive/migration-from-wazuh-integration.md) — Histórico: Guía de migración desde el proyecto anterior monorepo.
- [`docs/archive/PLAN-2026-06-16-refactor.md`](file:///home/tadeo/Desktop/wazuh-waha/docs/archive/PLAN-2026-06-16-refactor.md) — Histórico: Refactorización modular, deduplicación y separación de capas.
- [`docs/archive/PLAN-2026-06-16-reconnect.md`](file:///home/tadeo/Desktop/wazuh-waha/docs/archive/PLAN-2026-06-16-reconnect.md) — Histórico: Reconexión de agente al manager y pruebas iniciales de WAHA.
