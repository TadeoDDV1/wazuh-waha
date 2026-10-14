# Dashboard Web SOC — Wazuh-WAHA

Panel de control web moderno para monitoreo en tiempo real, análisis forense, gestión de servicios y descarga de reportes del ecosistema Wazuh-WAHA.

---

## 🌟 Funcionalidades Principales

1. **Telemetría y Estado de Servicios en Vivo**:
   - Monitoreo en tiempo real del Relay FastAPI, Contenedor WAHA (WhatsApp), Wazuh Manager y Bot de Telegram.
   - Controles interactivos para probar conexiones, reiniciar servicios y validar credenciales.

2. **Visor de Tráfico y Eventos en Tiempo Real (SSE)**:
   - Streaming de eventos y alertas en vivo vía Server-Sent Events (`/api/v1/traffic/stream`).
   - Filtrado por severidad (Niveles L1 a L15), búsqueda textual y visor de detalle JSON.

3. **Generador y Descarga de Reportes PDF**:
   - Selección interactiva de cualquier agente Wazuh registrado.
   - Descarga directa de informes forenses completos en formato PDF (`/api/v1/reports/agent/{agent_id}`).
   - Ficha integral: Hardware, SO, Red, Sockets activos, Procesos, Software, SCA (CIS Benchmark), FIM y Detecciones.

4. **Editor Visual de Configuración (`.env`)**:
   - Edición segura de variables de entorno agrupadas por categoría (Wazuh, WhatsApp, Telegram, Correo SMTP, IA Ollama).
   - Generación automática de backups antes de aplicar cambios y recarga dinámica.

---

## 🛠️ Stack Tecnológico

- **Framework**: [React 18](https://react.dev/) + [TypeScript](https://www.typescriptlang.org/)
- **Empaquetador**: [Vite](https://vitejs.dev/)
- **Estilos**: CSS Modules + Glassmorphism Theme (Dark SOC Palette)
- **Iconografía**: [Lucide React](https://lucide.dev/)
- **Notificaciones UI**: [Sonner](https://sonner.emilkowal.ski/)
- **Linter & Calidad**: [Oxlint](https://oxc.rs/)

---

## 🚀 Desarrollo Local

```bash
# Entrar a la carpeta del dashboard
cd dashboard

# Instalar dependencias
npm install

# Iniciar servidor de desarrollo en http://localhost:5173
npm run dev
```

Las peticiones a `/api` se proxifican automáticamente hacia el Relay backend (`http://localhost:8765`) configurado en `vite.config.ts`.

---

## 📦 Compilación para Producción

```bash
# Compilar bundle estático optimizado
npm run build

# Previsualizar el build localmente
npm run preview
```

Los artefactos generados se sitúan en `dashboard/dist/` y son servidos en producción a través de Nginx dentro del contenedor Docker `wazuh-waha-dashboard`.
