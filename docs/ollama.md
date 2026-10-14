# Integración con Ollama (IA Local)

Diagnóstico y enriquecimiento contextual de alertas de seguridad mediante Modelos de Lenguaje Locales (LLM) corriendo en infraestructura propia sin envío de datos a nubes de terceros.

---

## 🌟 Estado Actual y Capacidades

- **Módulo de Inferencia:** [`relay/wazuh_waha/infrastructure/ollama_client.py`](file:///home/tadeo/Desktop/wazuh-waha/relay/wazuh_waha/infrastructure/ollama_client.py) cliente HTTP asíncrono optimizado.
- **Control Centralizado:** Habilitación y configuración directa desde el **Dashboard Web** (pestaña *AI / Ollama*) o vía variables de entorno en `.env`.
- **Monitoreo en Vivo:** Chequeo de salud del modelo y latencia a través del bot de Telegram (`/servicios`).

---

## ⚙️ Configuración (`.env`)

```ini
# Habilitar o deshabilitar inferencia local
OLLAMA_ENABLED=true

# Endpoint del servicio Ollama
OLLAMA_HOST=http://localhost:11434

# Modelo sugerido (liviano y rápido en CPU o GPU)
OLLAMA_MODEL=qwen2.5:0.5b

# Timeout estricto en segundos (evita demorar el flujo de despacho)
OLLAMA_TIMEOUT=8
```

---

## 💡 Recomendaciones Operativas

1. **Aceleración por Hardware:**
   - Si se cuenta con GPU dedicada (NVIDIA / ROCm), modelos como `llama3.2:3b` o `qwen2.5:1.5b` infieren en $\sim 1\text{-}2$ segundos.
   - En entornos solo-CPU, se recomienda mantener `qwen2.5:0.5b` y fijar un `OLLAMA_TIMEOUT` estricto (5 a 8s) para que las alertas no retrasen la entrega por WhatsApp o Telegram.

2. **Mecanismo de Respaldo (Fallback Seguro):**
   - Si Ollama supera el tiempo límite configurado o el servicio no responde, el pipeline conmuta automáticamente a la plantilla predeterminada del motor SIEM, garantizando que **ninguna alerta se pierda**.
