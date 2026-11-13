# Plan de implementación — Enriquecimiento y traducción determinista + UX del dashboard

**Estado:** propuesta final para aprobación
**Decisión:** enriquecimiento y traducción **100 % deterministas**. **No se implementa LLM.**
**Motivo:** el hardware actual no soporta un modelo local con latencia aceptable; además, el objetivo es que los datos sean comprensibles y accionables, no generar texto libre.
**Ámbito:** relay `wazuh-waha` (alertas Wazuh, logs y eventos de red) + dashboard React existente.
**Objetivo:** que cualquier persona, aunque no sea especialista en seguridad, entienda **qué pasó, a quién afectó, qué tan grave es y qué hacer**, sin perder el detalle técnico para el analista.

---

## Estado de implementación (2026-11-13)

Implementado en esta iteración:

- [x] Paquete `relay/wazuh_waha/domain/enrichment/` con modelos, pipeline, caché y catálogos.
- [x] Enrichers deterministas: activo, red, geo, MITRE, traducción, remediación e IoCs.
- [x] Integración en `normalize_wazuh_event()` (journal + SSE).
- [x] Integración en `api/alerts.py` (reutiliza el evento enriquecido y añade acciones a la notificación).
- [x] Integración en `api/wazuh_control.py` (detecciones con `enrichment` y `description_es`).
- [x] Endpoints de glosario, estado de catálogos, métricas y recarga.
- [x] Campos de enriquecimiento en la telemetría en vivo (`summary_es`, `plain_severity`, `remediation_action`).
- [x] Dashboard: `EnrichmentPanel` reutilizable.
- [x] Dashboard: integración en `DetectionsView` (columnas “Qué pasó” / “Qué hacer” + panel).
- [x] Dashboard: integración en `RecentAlertsDrawer` (resumen, severidad y acción).
- [x] Dashboard: integración en `TelemetryGlobalCard` (resumen y acción en el feed).
- [x] Tests: `tests/test_enrichment.py` (7 tests) + los 136 existentes.
- [x] `npm run build` sin errores.

Pendiente para las siguientes fases:

- [ ] Modo simple/técnico global persistido.
- [ ] Integración en `NetworkAgentsTerminal`, `WazuhAgentsCard`, `WazuhModulesControlCard`, `ReportsCard`, `SettingsSection` y `NotificationChannelsCard`.
- [ ] Glosario contextual en todos los componentes.
- [ ] Endurecimiento, métricas por enricher y documentación final.

---

## 1. Resumen ejecutivo

El proyecto ya tiene las piezas base:

- `domain/templates.py`: traducción por diccionario/regex y extracción de IP, puerto, usuario y proceso.
- `domain/wazuh_breakdown.py`: explicaciones, riesgo y remediación por `rule_id`.
- `domain/cis_translator.py`: traducción de chequeos CIS/SCA.
- `common/network_bus.py` y `api/telemetry.py`: conexiones reales, puertos, DNS y clasificación de sitios.
- Dashboard React con tarjetas y vistas ya funcionando.

Lo que falta es un **contrato único de evento enriquecido** y una **capa de presentación comprensible** reutilizada en las funciones que ya existen.

Este plan entrega:

1. Un `CanonicalEvent` con traducción, contexto de activo, red, riesgo, MITRE, IoCs y remediación.
2. Un pipeline determinista, rápido y sin dependencias nuevas.
3. Un **modo simple/técnico** en el dashboard.
4. Componentes compartidos para explicar los datos en lenguaje claro.
5. Integración en las vistas existentes, sin crear una sección nueva aislada.

**Regla de oro:** el dashboard no debe mostrar más datos, sino **mejores datos**: primero la explicación, después el detalle técnico bajo demanda.

---

## 2. Alcance

### Incluido

- Traducción al español de descripción, `full_log` y resumen.
- Enriquecimiento con activo, red, geo, MITRE, riesgo, IoCs y remediación.
- Catálogos YAML versionados.
- Caché en memoria + SQLite compartida entre workers.
- Integración en:
  - `TelemetryGlobalCard`
  - `RecentAlertsDrawer`
  - `DetectionsView`
  - `LiveTrafficTerminal`
  - `NetworkAgentsTerminal`
  - `WazuhAgentsCard`
  - `WazuhModulesControlCard`
  - `ReportsCard`
  - `SettingsSection`
  - `NotificationChannelsCard`
- Modo simple/técnico persistido.
- Glosario contextual y ayudas emergentes.
- Acciones recomendadas con botón de copiar.
- Tests de backend y checklist de QA visual.

### Excluido explícitamente

- **LLM local o remoto.** No se implementa Ollama, OpenAI ni ningún modelo generativo.
- Captura de paquetes con Zeek/Suricata/tshark.
- Cola distribuida (Redis/NATS/Kafka).
- CMDB externa; el inventario de activos será un YAML editable.
- Threat Intelligence con APIs externas en esta entrega (queda como opción futura, apagada por defecto).
- Traducción automática de idiomas distintos de inglés → español.

---

## 3. Principios de diseño

1. **Determinista:** mismo evento → mismo resultado, siempre.
2. **Explicar antes que abrumar:** resumen primero, detalle técnico después.
3. **Lenguaje claro:** evitar jerga; si se usa un término técnico, explicarlo.
4. **Accionable:** cada hallazgo debe responder “¿qué hago ahora?”.
5. **Consistencia:** mismos colores, etiquetas y estructura en todas las vistas.
6. **Progresividad:** no romper el dashboard actual; el modo técnico conserva la vista de hoy.
7. **Rendimiento:** enriquecimiento síncrono < 20 ms p95; detalle pesado bajo demanda.
8. **Sin dependencias nuevas obligatorias:** stdlib + Pydantic + React actual.
9. **Versionado:** `schema_version` y `catalog_version` para invalidar caché.
10. **Retrocompatible:** con `ENRICH_ENABLED=false` todo funciona como hoy.

---

## 4. Arquitectura

```text
┌─────────────────────────────────────────────────────────────────────┐
│ Fuentes                                                             │
│  Wazuh alerts.json / archives.json / API / SSH / webhook / manual   │
│  network_bus (ss, syscollector)                                     │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Normalización (sync, <2 ms)                                         │
│  traffic_stream.normalize_wazuh_event()                             │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Enriquecimiento determinista (sync, <20 ms p95)                     │
│  1. AssetEnricher        agente → criticidad/SO/owner               │
│  2. NetworkEnricher      IP/puerto → servicio/dirección/DNS         │
│  3. GeoEnricher          IP pública → país/ASN/ciudad (GeoLite2)    │
│  4. MitreEnricher        rule_id → táctica/técnica                  │
│  5. TranslationEnricher  descripción + full_log → español           │
│  6. RemediationEnricher  rule_id/CIS → pasos accionables            │
│  7. IocEnricher          extrae y normaliza IoCs                    │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│ CanonicalEvent enriquecido                                          │
│  journal JSONL · SSE · dashboard · Telegram · WhatsApp · PDF · API  │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Dashboard UX                                                        │
│  Modo simple: resumen, riesgo y acciones                            │
│  Modo técnico: JSON, MITRE, IoCs y logs originales                  │
└─────────────────────────────────────────────────────────────────────┘
```

**No hay fase asíncrona de IA.** Todo el enriquecimiento es síncrono y determinista. Si en el futuro se añade Threat Intel, irá con timeout y flag propia, fuera de esta entrega.

---

## 5. Modelo canónico

Nuevo paquete:

```text
relay/wazuh_waha/domain/enrichment/
├── __init__.py
├── models.py
├── context.py
├── pipeline.py
├── cache.py
├── catalogs.py
├── enrichers/
│   ├── __init__.py
│   ├── base.py
│   ├── asset.py
│   ├── network.py
│   ├── geo.py
│   ├── mitre.py
│   ├── translation.py
│   ├── remediation.py
│   └── ioc.py
└── catalog/
    ├── rules_es.yaml
    ├── mitre.yaml
    ├── services.yaml
    ├── assets.yaml
    └── glossary.yaml
```

### 5.1 `models.py`

```python
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class AssetInfo(BaseModel):
    agent_id: str
    name: str
    os: str | None = None
    ip: str | None = None
    criticality: Literal["low", "medium", "high", "critical"] = "medium"
    owner: str | None = None
    location: str | None = None
    tags: list[str] = Field(default_factory=list)


class NetworkInfo(BaseModel):
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    service: str | None = None
    direction: str | None = None
    hostname: str | None = None
    asn: str | None = None
    country: str | None = None
    city: str | None = None
    site_category: str | None = None
    is_private: bool | None = None


class RiskInfo(BaseModel):
    technical_severity: Literal["info", "low", "medium", "high", "critical"] = "info"
    plain_severity: str = "Informativo"
    business_impact: str = ""
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    kill_chain_phase: str | None = None
    sla: str | None = None


class TranslationInfo(BaseModel):
    description_es: str
    full_log_es: str = ""
    summary_es: str | None = None
    method: Literal["catalog", "regex", "template", "raw"] = "raw"
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)


class RemediationStep(BaseModel):
    order: int = 1
    action: str
    why: str = ""
    command: str | None = None
    reference: str | None = None
    risk: Literal["low", "medium", "high"] = "low"


class Ioc(BaseModel):
    type: Literal["ip", "domain", "url", "hash", "user", "process", "file"]
    value: str
    defanged: str | None = None
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)


class Enrichment(BaseModel):
    asset: AssetInfo | None = None
    network: NetworkInfo | None = None
    risk: RiskInfo = Field(default_factory=RiskInfo)
    translations: TranslationInfo
    remediation: list[RemediationStep] = Field(default_factory=list)
    iocs: list[Ioc] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    elapsed_ms: float = 0.0
    degraded: bool = False
    errors: list[str] = Field(default_factory=list)


class NormalizedEvent(BaseModel):
    rule_id: str
    level: int
    agent_id: str
    agent_name: str
    description: str
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    user: str | None = None
    process: str | None = None
    mitre_ids: list[str] = Field(default_factory=list)
    groups: list[str] = Field(default_factory=list)


class CanonicalEvent(BaseModel):
    schema_version: str = "1.0"
    catalog_version: str = "2026.11"
    id: str
    timestamp: str
    source: Literal["wazuh", "network", "manual"] = "wazuh"
    raw: dict = Field(default_factory=dict)
    normalized: NormalizedEvent
    enrichment: Enrichment
```

### 5.2 Ejemplo de salida para el dashboard

```json
{
  "id": "2026-11-13T17:00:00.000+0000:5710:001",
  "timestamp": "2026-11-13T17:00:00.000+0000",
  "normalized": {
    "rule_id": "5710",
    "level": 10,
    "agent_id": "001",
    "agent_name": "srv-linux",
    "description": "sshd: Authentication failed.",
    "src_ip": "203.0.113.45",
    "src_port": 22,
    "user": "root"
  },
  "enrichment": {
    "asset": {
      "agent_id": "001",
      "name": "srv-linux",
      "os": "Ubuntu 22.04",
      "criticality": "high",
      "owner": "Infraestructura",
      "location": "DC-1"
    },
    "network": {
      "src_ip": "203.0.113.45",
      "src_port": 22,
      "service": "ssh",
      "direction": "inbound",
      "country": "NL",
      "asn": "AS64500",
      "is_private": false
    },
    "risk": {
      "technical_severity": "high",
      "plain_severity": "Alto — revisar hoy",
      "business_impact": "Posible fuerza bruta contra el acceso remoto del servidor.",
      "mitre_tactics": ["Acceso a credenciales"],
      "mitre_techniques": ["T1110 — Fuerza bruta"],
      "kill_chain_phase": "Explotación"
    },
    "translations": {
      "description_es": "Fallo de autenticación por SSH",
      "full_log_es": "Contraseña incorrecta para el usuario root desde 203.0.113.45 (SSH).",
      "summary_es": "Alguien intentó entrar por SSH como root desde una IP pública y falló.",
      "method": "catalog",
      "confidence": 0.95
    },
    "remediation": [
      {
        "order": 1,
        "action": "Bloquear la IP de origen en el firewall",
        "why": "Evita que el atacante siga intentando entrar.",
        "command": "ufw deny from 203.0.113.45",
        "risk": "low"
      },
      {
        "order": 2,
        "action": "Deshabilitar el login por contraseña y exigir claves SSH",
        "why": "Las claves son mucho más difíciles de adivinar que una contraseña.",
        "command": "sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && systemctl reload sshd",
        "risk": "medium"
      }
    ],
    "iocs": [
      {"type": "ip", "value": "203.0.113.45", "defanged": "203[.]0[.]113[.]45", "confidence": 0.9}
    ],
    "sources": ["catalog:rules_es", "geoip:GeoLite2"],
    "confidence": 0.93,
    "elapsed_ms": 7.4,
    "degraded": false,
    "errors": []
  }
}
```

---

## 6. Pipeline determinista

### 6.1 Interfaz

```python
# enrichers/base.py
from dataclasses import dataclass, field
from typing import Any

from ..models import CanonicalEvent


@dataclass
class EnrichmentContext:
    raw: dict[str, Any]
    event: CanonicalEvent
    errors: list[str] = field(default_factory=list)


class SyncEnricher:
    name: str = "sync"
    order: int = 100

    def enrich(self, ctx: EnrichmentContext) -> None:
        raise NotImplementedError
```

### 6.2 Pipeline

```python
# pipeline.py
class EnrichmentPipeline:
    def __init__(self, enrichers: list[SyncEnricher]):
        self.enrichers = sorted(enrichers, key=lambda e: e.order)

    def enrich(self, raw: dict, event: CanonicalEvent) -> CanonicalEvent:
        ctx = EnrichmentContext(raw=raw, event=event)
        started = time.perf_counter()
        for enricher in self.enrichers:
            try:
                enricher.enrich(ctx)
            except Exception as exc:
                ctx.errors.append(f"{enricher.name}: {exc}")
        event.enrichment.elapsed_ms = (time.perf_counter() - started) * 1000
        event.enrichment.errors.extend(ctx.errors)
        event.enrichment.degraded = bool(ctx.errors)
        return event
```

### 6.3 Enrichers

| Orden | Enricher | Entrada | Salida | Fuente |
|---:|---|---|---|---|
| 10 | `AssetEnricher` | agent_id/name | criticidad, SO, owner, ubicación | `assets.yaml` |
| 20 | `NetworkEnricher` | IPs/puertos/proceso | servicio, dirección, DNS, sitio | `services.yaml`, `dns_cache`, `telemetry._classify_network_site` |
| 30 | `GeoEnricher` | IP pública | país, ciudad, ASN | GeoLite2 local |
| 40 | `MitreEnricher` | rule_id, groups | tácticas/técnicas/fase | `mitre.yaml` |
| 50 | `TranslationEnricher` | descripción, full_log | texto español + resumen | `templates.py`, `rules_es.yaml` |
| 60 | `RemediationEnricher` | rule_id, CIS, puerto | pasos con “por qué” y comando | `rules_es.yaml`, `cis_translator` |
| 70 | `IocEnricher` | raw/normalized | IPs, dominios, URLs, hashes | regex + allowlist |

### 6.4 Reglas

- Si no hay match de catálogo, se usa regex y luego texto crudo; `method` indica la fuente.
- Si no hay remediación específica, se genera una recomendación genérica por severidad.
- Si falta GeoLite2, se omite geo y se marca `degraded=true` sin fallar.
- Si un enricher falla, los demás continúan.
- El resultado se cachea por `rule_id + campos normalizados + catalog_version`.

---

## 7. Catálogos

### 7.1 `rules_es.yaml`

```yaml
version: "2026.11"
rules:
  "5710":
    title: "Fallo de autenticación por SSH"
    category: "Acceso remoto"
    summary: "Alguien intentó entrar por SSH y no lo consiguió."
    risk: "Puede ser un error de contraseña o un ataque de fuerza bruta."
    business_impact: "Riesgo de acceso no autorizado al servidor."
    severity: high
    mitre:
      tactics: ["Credential Access"]
      techniques: ["T1110"]
    remediation:
      - action: "Bloquear la IP de origen en el firewall"
        why: "Evita que el atacante siga intentando entrar."
        command: "ufw deny from {src_ip}"
        risk: low
      - action: "Deshabilitar el login por contraseña y exigir claves SSH"
        why: "Las claves son más difíciles de adivinar que una contraseña."
        command: "sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && systemctl reload sshd"
        risk: medium
```

### 7.2 `assets.yaml`

```yaml
version: "2026.11"
defaults:
  criticality: medium
  owner: "Sin asignar"
assets:
  "001":
    name: "srv-linux"
    os: "Ubuntu 22.04"
    ip: "10.50.1.10"
    criticality: high
    owner: "Infraestructura"
    location: "DC-1"
    tags: ["produccion", "linux"]
```

### 7.3 `glossary.yaml`

```yaml
version: "2026.11"
terms:
  MITRE:
    short: "MITRE ATT&CK"
    long: "Catálogo público de tácticas y técnicas que usan los atacantes."
  FIM:
    short: "Integridad de archivos"
    long: "Vigila si un archivo importante cambió, se creó o se borró."
  SCA:
    short: "Configuración segura"
    long: "Revisa si el equipo cumple buenas prácticas de configuración."
  IoC:
    short: "Indicador de compromiso"
    long: "Dato que sugiere que algo malicioso ocurrió, como una IP o un archivo."
  CVE:
    short: "Vulnerabilidad conocida"
    long: "Fallo de seguridad público con un identificador único."
  ASN:
    short: "Red del proveedor"
    long: "Identifica a qué proveedor de Internet pertenece una IP."
```

### 7.4 Migración

- Extraer `_RULE_SOC_EXPLANATIONS` de `wazuh_breakdown.py` a `rules_es.yaml`.
- Mantener `explain_wazuh_rule()` como wrapper del catálogo.
- Reutilizar `cis_translator.localize_cis_check()` sin cambios.
- Reutilizar `templates.translate_full_log_es()` como fallback regex.
- Versionar los YAML y validarlos con Pydantic al cargar.

---

## 8. Caché

- **Memoria:** LRU por proceso (máx. 2048 entradas).
- **Disco:** SQLite en `/var/lib/wazuh-waha/enrichment_cache.sqlite3`, compartida entre workers.
- **Clave:** `sha256(rule_id | agent_id | src_ip | dst_ip | dst_port | description | catalog_version)`.
- **TTL:** 24 h para traducción/reglas; 1 h para DNS; 24 h para geo.
- **Invalidación:** cambio de `catalog_version` o `enrichment_cache_version`.
- **Limpieza:** job diario de expirados.
- **Métricas:** `cache_hit`, `cache_miss`, `cache_evictions`.

```sql
CREATE TABLE IF NOT EXISTS enrichment_cache (
    key TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    hits INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_enrichment_expires ON enrichment_cache(expires_at);
```

---

## 9. Integración en el backend

### 9.1 `common/traffic_stream.py`

`normalize_wazuh_event()` construye el `CanonicalEvent` y ejecuta `enrichment_pipeline.enrich()` antes de devolver el dict. Se conservan las claves actuales en el nivel superior para no romper la UI y se añade `enrichment`.

```python
def normalize_wazuh_event(raw: dict[str, Any]) -> dict[str, Any]:
    # ... construcción actual de `normalized` ...
    event = build_canonical_event(raw, normalized)
    if settings.enrich_enabled:
        event = enrichment_pipeline.enrich(raw, event)
    out = event.model_dump(mode="json")
    out["raw_json"] = _clip_raw(raw)  # compatibilidad con la UI actual
    return out
```

### 9.2 `api/alerts.py`

`format_alert(alert, enriched=canonical)` usa la traducción y remediación enriquecidas. Si no hay enriquecimiento, mantiene el comportamiento actual.

### 9.3 `domain/pipeline.py`

- `description_es` y `full_log_es` desde `enrichment.translations`.
- `risk.plain_severity` para la etiqueta legible.
- `remediation` para la sección de acciones.
- `iocs` para la lista de indicadores.

### 9.4 `api/telemetry.py`

Endpoints nuevos:

| Método | Ruta | Descripción |
|---|---|---|
| GET | `/api/v1/telemetry/events/{id}/enrichment` | Evento canónico enriquecido |
| GET | `/api/v1/telemetry/enrichment/glossary` | Glosario para tooltips |
| GET | `/api/v1/telemetry/enrichment/catalogs/status` | Versión y estado de catálogos |
| GET | `/api/v1/telemetry/enrichment/metrics` | Latencias, caché y degradación |
| POST | `/api/v1/telemetry/enrichment/reload` | Recarga catálogos (solo escritura) |

Además, `getWazuhDetections()` y `traffic/tail` incluyen `enrichment` en cada ítem.

### 9.5 `api/reports.py`

El PDF usa:
- resumen ejecutivo en lenguaje simple,
- riesgo de negocio,
- MITRE traducido,
- remediación con “por qué”,
- IoCs.

---

## 10. Integración en el dashboard (funciones existentes)

### 10.1 Principios UX

- **Modo simple por defecto** para usuarios sin conocimientos técnicos.
- **Modo técnico** disponible con un clic; conserva JSON, logs originales y campos crudos.
- **Divulgación progresiva:** primero resumen, luego contexto, luego detalle técnico.
- **Mismo lenguaje visual** en todas las tarjetas: severidad, color, icono y estructura.
- **Acciones copiables** con explicación de qué hace y qué riesgo tiene.
- **Glosario contextual:** cada término técnico tiene tooltip o enlace “¿Qué es?”.
- **Persistencia:** el modo elegido se guarda en `localStorage`.
- **Accesibilidad:** `aria-label`, navegación por teclado, contraste y textos alternativos.

### 10.2 Componentes compartidos nuevos

```text
dashboard/src/components/enrichment/
├── EnrichmentBadge.tsx       # “Explicado” / “Parcial”
├── SeverityPill.tsx          # Bajo / Medio / Alto / Crítico con texto claro
├── WhatHappenedCard.tsx      # “¿Qué pasó?” en 1–2 frases
├── WhyItMattersCard.tsx      # “¿Por qué importa?”
├── ActionSteps.tsx           # “¿Qué hago?” con copiar comando
├── AssetContext.tsx          # agente, criticidad, owner, ubicación
├── NetworkContext.tsx        # servicio, dirección, país, ASN
├── MitreChips.tsx            # tácticas/técnicas traducidas
├── IocList.tsx               # indicadores con defang y copiar
├── TechnicalDetails.tsx      # JSON/log original colapsable
├── GlossaryTooltip.tsx       # explicación de términos
└── SimpleModeToggle.tsx      # simple / técnico
```

```text
dashboard/src/context/EnrichmentContext.tsx   # modo + glosario + helpers
dashboard/src/types/enrichment.ts             # tipos compartidos
dashboard/src/utils/enrichment.ts             # etiquetas, colores, formateo
```

### 10.3 Mapa de integración por componente

| Componente existente | Función actual | Cambio propuesto | Beneficio para no experto |
|---|---|---|---|
| `Dashboard.tsx` | Orquesta las tarjetas | Añadir `EnrichmentProvider` y `SimpleModeToggle` en la cabecera | Control global del nivel de detalle |
| `TelemetryGlobalCard.tsx` | KPIs y alertas en vivo | Mostrar “¿Qué pasó?” y severidad legible en cada alerta; badge de enriquecimiento | Entiende el estado sin leer números |
| `RecentAlertsDrawer.tsx` | Lista de alertas recientes | Tarjeta con título traducido, riesgo, agente/criticidad y primera acción | Sabe qué atender primero |
| `DetectionsView.tsx` | Tabla por módulo + JSON crudo | Columnas “Qué pasó” y “Qué hacer”; panel de detalle con pestañas Resumen / Contexto / Acciones / Técnico | Deja de ver solo JSON |
| `LiveTrafficTerminal.tsx` | Stream xterm de alertas y conexiones | Línea enriquecida con severidad legible, servicio y resumen; clic para abrir panel de detalle | La terminal sigue siendo útil para técnicos, pero comprensible |
| `NetworkAgentsTerminal.tsx` | Sitios, sockets, interfaces, detecciones, forense | Explicar dirección (`entrante`/`saliente`), servicio, categoría y riesgo; tooltips de puertos | Entiende qué conexión es normal y cuál no |
| `WazuhAgentsCard.tsx` | Lista de agentes, tráfico, PDF | Mostrar criticidad, SO, owner y salud del agente; badge de riesgo | Sabe qué equipo es importante |
| `WazuhModulesControlCard.tsx` | Módulos, recomendaciones y reglas | Traducir nombres de módulos/reglas; explicar “qué hace” y “por qué importa”; recomendaciones con pasos | Entiende para qué sirve cada módulo |
| `ReportsCard.tsx` | Secciones, preview y PDF | Preview con resumen ejecutivo simple; secciones con “qué significa”; PDF enriquecido | Puede leer y presentar el reporte |
| `SettingsSection.tsx` | Configuración y logs | Añadir estado de catálogos, botón “Recargar explicaciones” y modo simple por defecto | Sabe si las explicaciones están actualizadas |
| `NotificationChannelsCard.tsx` | Canales de notificación | Explicar qué alertas llegan a cada canal y en qué lenguaje | Configura sin miedo |
| `WhatsappCard` / `TelegramCard` | Vinculación | Mostrar ejemplo de mensaje enriquecido | Sabe qué recibirá |

### 10.4 Detalle por vista

#### `TelemetryGlobalCard`

- Cada alerta muestra:
  - hora,
  - severidad legible (`Crítico — actuar ahora`),
  - “¿Qué pasó?” en una frase,
  - agente y criticidad,
  - badge `Explicado` o `Parcial`.
- El detalle técnico queda en un desplegable.

#### `RecentAlertsDrawer`

- Reemplazar la descripción cruda por `translations.summary_es`.
- Añadir bloque “¿Qué hago?” con el primer paso de remediación.
- Mostrar `asset.criticality` con color.
- Mantener `msg_preview` solo en modo técnico.

#### `DetectionsView`

- Columnas nuevas:
  - **Qué pasó**: `description_es`.
  - **Qué hacer**: primera acción de remediación.
- Al expandir una fila, panel con pestañas:
  1. **Resumen**: qué pasó, por qué importa.
  2. **Contexto**: activo, red, geo, MITRE.
  3. **Acciones**: pasos con copiar comando.
  4. **Técnico**: JSON original y log original.
- En modo simple, la pestaña Técnico queda oculta.

#### `LiveTrafficTerminal`

- Mantener el formato actual para técnicos.
- Añadir un comando `:simple` / `:tecnico` y un botón de panel lateral.
- En modo simple, la línea muestra:
  `17:00:01  ALTO  [srv-linux]  Fallo de acceso SSH desde 203.0.113.45  →  Revisar`
- Al hacer clic en una línea, abrir panel con el detalle enriquecido.

#### `NetworkAgentsTerminal`

- En “Sitios”: mostrar categoría comprensible (`Navegación web`, `Mensajería`, `SSH`).
- En “Sockets”: traducir `inbound/outbound/listen` a `entrante/saliente/escucha`.
- En “Detecciones”: usar el mismo panel enriquecido de `DetectionsView`.
- En “Forense”: resumen del agente con riesgos principales y acciones.

#### `WazuhAgentsCard`

- Cada agente muestra:
  - nombre y ID,
  - SO,
  - criticidad (`Alta`),
  - owner,
  - estado de salud,
  - badge de riesgo.
- El detalle de tráfico usa `NetworkContext`.

#### `WazuhModulesControlCard`

- Cada módulo muestra una línea “¿Qué hace?” tomada de `glossary.yaml`.
- Las recomendaciones incluyen:
  - qué se encontró,
  - por qué importa,
  - cómo solucionarlo.
- Los nombres de reglas se traducen con `rules_es.yaml`.

#### `ReportsCard`

- El preview muestra:
  - resumen ejecutivo en 3–5 líneas,
  - top 3 riesgos,
  - top 3 acciones.
- Las secciones del PDF se mantienen, pero con textos enriquecidos.
- Añadir botón “Ver explicación” por sección.

#### `SettingsSection`

- Nueva tarjeta “Explicaciones y catálogos”:
  - versión del catálogo,
  - número de reglas,
  - última recarga,
  - botón “Recargar”.
- Toggle “Modo simple por defecto”.

### 10.5 Flujo de usuario

```text
Usuario abre dashboard
   │
   ├─ Modo simple (por defecto)
   │    ├─ Ve severidad, resumen y acción
   │    ├─ Puede copiar el comando recomendado
   │    └─ Puede abrir “Ver detalle técnico”
   │
   └─ Modo técnico
        ├─ Ve JSON, logs originales, MITRE e IoCs
        └─ Puede volver a simple en cualquier momento
```

### 10.6 Tipos TypeScript

```ts
export interface Enrichment {
  asset?: AssetInfo;
  network?: NetworkInfo;
  risk: RiskInfo;
  translations: TranslationInfo;
  remediation: RemediationStep[];
  iocs: Ioc[];
  sources: string[];
  confidence: number;
  elapsed_ms: number;
  degraded: boolean;
  errors: string[];
}

export interface TranslationInfo {
  description_es: string;
  full_log_es: string;
  summary_es?: string;
  method: 'catalog' | 'regex' | 'template' | 'raw';
  confidence: number;
}

export interface RiskInfo {
  technical_severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  plain_severity: string;
  business_impact: string;
  mitre_tactics: string[];
  mitre_techniques: string[];
  kill_chain_phase?: string;
  sla?: string;
}

export interface RemediationStep {
  order: number;
  action: string;
  why: string;
  command?: string;
  reference?: string;
  risk: 'low' | 'medium' | 'high';
}

export interface Ioc {
  type: 'ip' | 'domain' | 'url' | 'hash' | 'user' | 'process' | 'file';
  value: string;
  defanged?: string;
  confidence: number;
}
```

Extender `TrafficEvent`, `RecentAlert` y `AgentNetworkEvent` con `enrichment?: Enrichment`.

### 10.7 Estilos y consistencia

- Reutilizar variables CSS existentes (`--cyan-accent`, `--red-error`, etc.).
- Colores de severidad:
  - Crítico: rojo.
  - Alto: naranja.
  - Medio: amarillo.
  - Bajo: verde/azul.
  - Informativo: gris.
- Iconos de `lucide-react` ya presentes.
- No introducir una librería de UI nueva.

---

## 11. Configuración

```env
# --- Enriquecimiento determinista ---
ENRICH_ENABLED=true
ENRICH_CACHE_ENABLED=true
ENRICH_CACHE_PATH=/var/lib/wazuh-waha/enrichment_cache.sqlite3
ENRICH_CACHE_TTL_SEC=86400
ENRICH_CATALOG_DIR=
ENRICH_ASSETS_FILE=/etc/wazuh-waha/assets.yaml
ENRICH_GEOIP_DB=/var/lib/wazuh-waha/GeoLite2-City.mmdb
ENRICH_REDACT_PII=true
ENRICH_UI_SIMPLE_MODE_DEFAULT=true
```

- Si `ENRICH_ENABLED=false`, no se carga nada y el dashboard funciona como hoy.
- Si falta `ENRICH_GEOIP_DB`, se desactiva geo con warning.
- Si falta `ENRICH_ASSETS_FILE`, se usa `defaults` y se marca `degraded=true`.
- No hay variables de LLM en esta entrega.

---

## 12. Observabilidad

### Métricas

- `enrichment_events_total{source}`
- `enrichment_latency_ms{enricher}`
- `enrichment_errors_total{enricher}`
- `enrichment_cache_hits_total` / `enrichment_cache_misses_total`
- `enrichment_degraded_total`

### Logs

- `enrichment_start event_id=... rule_id=...`
- `enrichment_done event_id=... elapsed_ms=... degraded=...`
- `enrichment_enricher_error enricher=... err=...`
- `enrichment_cache_hit key=... kind=...`

### Health

`/health` incluye:

```json
{
  "enrichment": {
    "enabled": true,
    "catalog_version": "2026.11",
    "geoip_loaded": true,
    "cache_ok": true,
    "degraded_last_hour": 0
  }
}
```

---

## 13. Seguridad y privacidad

- `ENRICH_REDACT_PII=true`: redactar usuarios, rutas y tokens en `full_log_es`.
- No se envían datos a APIs externas en esta entrega.
- No se cachean secretos.
- Límite de tamaño por campo enriquecido.
- Sanitizar HTML en el dashboard.
- Auditar la recarga de catálogos.
- El modo técnico no expone secretos: el backend ya recorta `raw_json`.

---

## 14. Testing

### Backend

- `tests/test_enrichment_models.py`: validación Pydantic y serialización.
- `tests/test_enrichment_pipeline.py`: orden, errores aislados, degradación.
- `tests/test_enrichment_asset.py`: activo conocido/desconocido/defaults.
- `tests/test_enrichment_network.py`: puertos, direcciones, DNS, IP privada.
- `tests/test_enrichment_geo.py`: IP pública, DB ausente, IP privada.
- `tests/test_enrichment_mitre.py`: rule_id → técnica, desconocida.
- `tests/test_enrichment_translation.py`: catálogo, regex, fallback, log vacío.
- `tests/test_enrichment_remediation.py`: regla conocida, CIS, genérica.
- `tests/test_enrichment_ioc.py`: IPs, dominios, hashes, defang, allowlist.
- `tests/test_enrichment_cache.py`: TTL, invalidación, concurrencia SQLite.
- `tests/test_enrichment_api.py`: endpoints y contrato JSON.

### Golden files

```text
tests/fixtures/enrichment/
├── ssh_bruteforce.json
├── fim_modified.json
├── sca_cis.json
├── vulnerability_cve.json
├── network_outbound.json
└── unknown_rule.json
```

Cada fixture contiene `input` y `expected` con los campos clave.

### Frontend

- `npm run build` debe pasar sin errores de TypeScript.
- Checklist manual por vista:
  - modo simple y técnico,
  - tooltips de glosario,
  - copiar comandos,
  - responsive,
  - teclado y `aria-label`,
  - estados vacíos y de error.
- Opcional (backlog): añadir `vitest` + Testing Library para componentes compartidos.

### Rendimiento

- `enrich_sync` p95 < 20 ms con 1000 eventos.
- Sin fugas de memoria en 10 000 iteraciones.
- El dashboard no debe hacer peticiones extra para el resumen básico.

### Seguridad

- `full_log` con token/password no aparece en claro.
- Catálogos inválidos → arranque seguro con warning, no crash.

---

## 15. Fases, entregables y criterios de aceptación

### Fase 0 — Preparación (0.5 día)

**Entregables**
- Rama `feat/enrichment-determinista`.
- ADR `docs/adr/ADR-001-enriquecimiento-determinista.md`.
- Feature flag `ENRICH_ENABLED=false` en el PR inicial.
- Tipos TypeScript base.

**Aceptación**
- Con la flag apagada, los 136 tests actuales pasan y el dashboard no cambia.

### Fase 1 — Núcleo determinista (2–3 días)

**Entregables**
- `domain/enrichment/` con modelos, pipeline, caché y catálogos.
- Enrichers: asset, network, mitre, translation, remediation, ioc.
- Migración de `wazuh_breakdown` y `templates` a catálogos.
- Integración en `normalize_wazuh_event()`.
- Tests unitarios y golden files.

**Aceptación**
- Cada evento del journal tiene `enrichment` con traducción, riesgo, MITRE y remediación.
- p95 de enriquecimiento < 20 ms.
- `ENRICH_ENABLED=false` no altera nada.
- Tests nuevos + existentes en verde.

### Fase 2 — Red, GeoIP y API (2 días)

**Entregables**
- `GeoEnricher` con GeoLite2 local.
- `NetworkEnricher` con DNS/PTR, servicios y clasificación de sitios.
- Endpoints `/events/{id}/enrichment`, `/glossary`, `/catalogs/status`, `/metrics`.
- `enrichment` incluido en `traffic/tail` y detecciones.

**Aceptación**
- IP pública → país/ASN/ciudad.
- IP privada → `is_private=true`, sin llamada externa.
- DB ausente → geo deshabilitado y `degraded=true`, sin error 500.
- Endpoints con tests.

### Fase 3 — UX base del dashboard (3–4 días)

**Entregables**
- `EnrichmentContext`, `SimpleModeToggle` y componentes compartidos.
- Integración en:
  - `TelemetryGlobalCard`
  - `RecentAlertsDrawer`
  - `DetectionsView`
  - `LiveTrafficTerminal`
- Glosario y tooltips.
- Modo simple/técnico persistido.

**Aceptación**
- Un usuario sin conocimientos entiende qué pasó, qué tan grave es y qué hacer en menos de 10 segundos.
- El modo técnico conserva la vista actual.
- `npm run build` pasa.
- Sin regresiones visuales evidentes.

### Fase 4 — Resto de vistas (2–3 días)

**Entregables**
- Integración en:
  - `NetworkAgentsTerminal`
  - `WazuhAgentsCard`
  - `WazuhModulesControlCard`
  - `ReportsCard`
  - `SettingsSection`
  - `NotificationChannelsCard`
- Ejemplos de mensajes en WhatsApp/Telegram.

**Aceptación**
- Todas las vistas usan el mismo lenguaje visual.
- Las recomendaciones incluyen “por qué” y “cómo”.
- El PDF usa el resumen enriquecido.

### Fase 5 — Salidas y endurecimiento (2 días)

**Entregables**
- Telegram/WhatsApp/Email con resumen y primera acción.
- PDF con secciones enriquecidas.
- Métricas, health y documentación.
- Plan de rollback.

**Aceptación**
- Mensajes incluyen resumen en español y acción recomendada.
- `/health` reporta estado de enriquecimiento.
- Rollback con `ENRICH_ENABLED=false` y reinicio.
- Documentación actualizada.

**Duración total estimada:** 10–14 días de trabajo efectivo.

---

## 16. Despliegue gradual

1. **Dev:** `ENRICH_ENABLED=true`, modo simple por defecto.
2. **Staging:** comparar 100 eventos contra la salida actual; validar traducciones.
3. **Producción canary:** activar solo para `level >= 8` durante 24 h.
4. **Producción total:** activar para todos los niveles.
5. **Dashboard:** habilitar modo simple para todos; mantener modo técnico accesible.

**Rollback:** `ENRICH_ENABLED=false` + `systemctl restart wazuh-waha`. El dashboard vuelve a la vista actual sin migración de datos.

---

## 17. Riesgos y mitigaciones

| Riesgo | Impacto | Mitigación |
|---|---|---|
| Exceso de información | Alto | Divulgación progresiva y modo simple |
| Traducción imprecisa | Medio | Catálogo + tests + “ver original” |
| Catálogos desactualizados | Medio | Versionado, tests y recarga desde Settings |
| Latencia del enriquecimiento | Medio | Sync determinista, caché, límite de tamaño |
| Crecimiento del journal | Medio | Resumen en journal, detalle en API/caché |
| Inconsistencia multi-worker | Medio | Enriquecimiento determinista + caché SQLite |
| Complejidad visual | Medio | Componentes compartidos y mismos patrones |
| Dependencia de GeoLite2 | Bajo | Desactivar geo si falta la DB |
| Regresión en notificaciones | Alto | `format_alert` retrocompatible y flag apagada |

---

## 18. Backlog futuro

- **LLM:** descartado en esta entrega por limitaciones de hardware. Solo se reconsideraría si cambia la infraestructura y con validación estricta.
- **Threat Intelligence:** APIs externas opcionales, apagadas por defecto.
- **pcap/Zeek/Suricata:** adaptador de flujos al `CanonicalEvent`.
- **CMDB real:** integración con GLPI, NetBox o Wazuh API.
- **Feedback loop:** marcar explicaciones incorrectas desde el dashboard.
- **Evaluación de calidad:** 200 eventos etiquetados para medir precisión.
- **Internacionalización:** catálogos `es`, `en`, `pt`.

---

## 19. Definition of Done

- [ ] `ENRICH_ENABLED=false` mantiene el comportamiento actual.
- [ ] `CanonicalEvent` documentado y versionado.
- [ ] Enrichers deterministas integrados en `normalize_wazuh_event()`.
- [ ] Catálogos YAML validados y versionados.
- [ ] Endpoints de consulta, glosario y métricas.
- [ ] Modo simple/técnico en el dashboard.
- [ ] Integración en las 10 vistas existentes.
- [ ] Glosario contextual y tooltips.
- [ ] Acciones recomendadas con copiar comando.
- [ ] Telegram/WhatsApp/PDF usan el enriquecimiento.
- [ ] Tests backend y checklist de QA visual.
- [ ] p95 sync < 20 ms.
- [ ] Sin secretos/PII en logs.
- [ ] Documentación y rollback actualizados.
- [ ] `/health` reporta estado de enriquecimiento.

---

## 20. Anexos

### A. Contrato de degradación

```json
{
  "degraded": true,
  "errors": ["geo: db_missing"],
  "confidence": 0.72
}
```

El dashboard muestra el evento igualmente con badge “Explicación parcial”.

### B. Textos de severidad para el usuario

| Técnica | Texto simple | Acción sugerida |
|---|---|---|
| `critical` | Crítico — actuar ahora | Aislar el equipo y revisar de inmediato |
| `high` | Alto — revisar hoy | Investigar y aplicar la acción recomendada |
| `medium` | Medio — revisar esta semana | Verificar si es esperado |
| `low` | Bajo — solo informativo | No requiere acción urgente |
| `info` | Informativo | Registrar para auditoría |

### C. Checklist de QA visual

- [ ] El modo simple oculta JSON y logs crudos.
- [ ] El modo técnico muestra todo lo actual.
- [ ] Los tooltips de glosario funcionan con teclado.
- [ ] Los comandos se copian correctamente.
- [ ] Los colores de severidad son consistentes.
- [ ] Las tarjetas se ven bien en 1280 px y 1920 px.
- [ ] No hay textos en inglés sin traducir.
- [ ] Los estados vacíos explican qué hacer.

---

**Siguiente paso sugerido:** aprobar este plan y arrancar la Fase 1 en la rama `feat/enrichment-determinista`, con la flag apagada por defecto y los tests como red de seguridad.
