import httpx

from ..config import settings


SYSTEM_PROMPT = (
    "Sos un asistente de ciberseguridad que resume alertas de Wazuh en espanol. "
    "Reglas: maximo 2 oraciones, tono profesional, inclui que paso, donde y nivel de severidad. "
    "No inventes datos que no esten en la alerta. Si no podes, decilo explicitamente."
)


async def summarize(alert, timeout=None):
    rule = alert.get("rule", {}) or {}
    agent = alert.get("agent", {}) or {}
    rid = rule.get("id", "?")
    rdesc = rule.get("description", "?")
    level = rule.get("level", "?")
    aname = agent.get("name", "?")
    aid = agent.get("id", "?")
    data = alert.get("data", {})
    log = alert.get("full_log", "")[:500]
    body = (
        f"Regla: {rid} - {rdesc}\n"
        f"Nivel: {level}\n"
        f"Agente: {aname} ({aid})\n"
        f"Data: {data}\n"
        f"Log: {log}"
    )
    payload = {
        "model": settings.ollama_model,
        "prompt": body,
        "system": SYSTEM_PROMPT,
        "stream": False,
        "options": {
            "temperature": 0.2,
            "num_predict": 120,
        },
    }
    try:
        async with httpx.AsyncClient(timeout=timeout or settings.ollama_timeout) as client:
            r = await client.post(f"{settings.ollama_host}/api/generate", json=payload)
            r.raise_for_status()
            data = r.json()
            text = (data.get("response") or "").strip()
            return text or None
    except Exception:
        return None
