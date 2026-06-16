# Ollama integration

## Estado actual (junio 2026)

- `ollama_client.py` está **implementado** pero **desconectado** del formatter.
- Por default `OLLAMA_ENABLED=false` en `.env.example`.
- Si querés activarlo, hay un único cambio en `formatter.py` (ver abajo).

## Por qué off por default

Wazuh corre el script de integración con un timeout corto (~5s). Ollama
`qwen2.5:0.5b` en CPU tarda **~10s por resumen**. Eso excede el timeout, Wazuh
mata el script, y el `print(..., file=sys.stderr)` que documenta el error
tampoco se loguea (el proceso murió antes).

En resumen: con IA activada, **algunas alertas no se mandan y no sabemos por
qué**.

## Cuándo tiene sentido activarlo

- Tenés GPU disponible (`llama3.2:3b` con GPU corre en ~1s).
- Querés resumen para alertas que no tienen template (actualmente caen a
  `render_default()`, que es solo la metadata en texto plano).
- Podés tolerar que las alertas `level >= 12` tarden 2-3s más.

## Cómo activarlo

### 1. Setear env

```ini
# .env
OLLAMA_ENABLED=true
OLLAMA_MODEL=qwen2.5:0.5b   # o el que prefieras
OLLAMA_TIMEOUT=5            # segundos antes de fallback a default
```

### 2. Enchufar en `formatter.py`

Cambiar la rama "default" en `format_alert()`:

```python
# Antes:
meta["decision"] = "default"
return (templates.render_default(alert), meta)

# Después:
from . import ollama_client
from .config import settings
if settings.ollama_enabled:
    summary = await ollama_client.summarize(alert, timeout=settings.ollama_timeout)
    if summary:
        meta["decision"] = "ollama"
        return (summary, meta)
meta["decision"] = "default"
return (templates.render_default(alert), meta)
```

### 3. Subir el timeout del integration

En el bloque `<integration>` del manager:
```xml
<options>--script /var/ossec/integrations/custom/whatsapp_alert.py --timeout 30</options>
```

### 4. Reiniciar

```bash
sudo systemctl restart wazuh-waha
```

## Cuándo NO activarlo

- En hot path para TODAS las alertas (cuelga el manager).
- Sin GPU (CPU + qwen2.5:0.5b = ~10s, inaceptable).
- Si el operador no entiende por qué algunas alertas tardan más.
