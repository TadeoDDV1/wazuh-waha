"""
TelemetryStore — almacén en memoria de métricas de tráfico del relay.

Thread-safe (asyncio.Lock). Bounded (deques con maxlen), no crece sin límite.
Se integra en api/alerts.py para registrar cada alerta que pasa por el pipeline.

Nota multi-worker: cada proceso uvicorn tiene su propio store. El endpoint SSE
muestra el tráfico del worker que atiende la conexión (~50% del total con 2 workers).
Para consolidación cross-worker se necesitaría Redis o un archivo compartido.
"""

import asyncio
import time
from collections import Counter, deque
from typing import Any

# ── Mapa de módulo → prefijos de rule_id (aproximado, basado en defaults de Wazuh) ──
# Clave: module_id del dashboard; Valor: set de prefijos de rule_id (str)
_RULE_ID_TO_MODULE: dict[str, str] = {}

def _build_rule_map() -> None:
    """Construye el mapa inverso rule_id → module_id basándose en rangos conocidos."""
    ranges = {
        'fim':             list(range(550, 600)),
        'sca':             list(range(19000, 19300)),
        'rootcheck':       list(range(510, 530)),
        'threat_hunting':  [601, 602, 603, 5712, 5752],
        'vulnerabilities': list(range(23500, 23600)),
        'syscollector':    list(range(5500, 5510)),
        'pci_dss':         [106, 5710],
        'gdpr':            [1002, 1003],
        'hipaa':           [106, 5710],
        'nist_800_53':     [5710, 5712],
        'tsc':             [106, 5710],
        'mitre':           list(range(100001, 100010)),
    }
    for module_id, rule_ids in ranges.items():
        for rid in rule_ids:
            # No sobreescribir si ya hay asignación más específica
            if str(rid) not in _RULE_ID_TO_MODULE:
                _RULE_ID_TO_MODULE[str(rid)] = module_id

_build_rule_map()


def rule_id_to_module(rule_id: str) -> str:
    """Devuelve el module_id para un rule_id dado. 'unknown' si no hay match."""
    return _RULE_ID_TO_MODULE.get(str(rule_id), 'unknown')


class TelemetryStore:
    """
    Almacén bounded, seguro para asyncio, de métricas de tráfico en tiempo real.

    Estructura:
      - alerts_live: deque de las últimas 200 alertas sanitizadas
      - histogram: deque de 60 enteros (1 por segundo, rolling)
      - counters globales (desde startup, no se resetean)
      - rule_counter / agent_counter / module_counter: rolling últimas ~6h
    """

    _ALERTS_CAP = 200
    _HISTOGRAM_SECS = 60
    _TOP_N = 10
    _COUNTER_ROLLOVER_SECS = 6 * 3600  # resetear contadores de top cada 6h

    def __init__(self) -> None:
        self._lock = asyncio.Lock()

        # Ring buffer de alertas procesadas (para stream/snapshot)
        self.alerts_live: deque[dict] = deque(maxlen=self._ALERTS_CAP)

        # Histograma rolling de 60 segundos
        self._histogram: deque[int] = deque([0] * self._HISTOGRAM_SECS, maxlen=self._HISTOGRAM_SECS)
        self._bucket_ts: float = time.time()
        self._bucket_count: int = 0

        # Contadores globales (acumulados desde startup)
        self.total_received: int = 0
        self.total_sent: int = 0
        self.total_deduped: int = 0
        self.total_waha_errors: int = 0

        # Contadores de top (se resetean cada ~6h)
        self.rule_counter: Counter = Counter()
        self.agent_counter: Counter = Counter()
        self.module_counter: Counter = Counter()
        self._counters_reset_ts: float = time.time()

        # Muestras de latencia (ms) — últimas 100
        self.latency_samples: deque[float] = deque(maxlen=100)

        # Timestamp arranque
        self.started_at: float = time.time()

        # Para notificar a suscriptores SSE
        self._condition: asyncio.Condition | None = None  # se inicializa lazy

    def _get_condition(self) -> asyncio.Condition:
        if self._condition is None:
            self._condition = asyncio.Condition(self._lock)
        return self._condition

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _advance_histogram(self) -> None:
        """Avanza el histograma hasta el segundo actual, rellenando con 0 si pasó tiempo."""
        now = time.time()
        elapsed = int(now - self._bucket_ts)
        if elapsed == 0:
            # Mismo segundo
            self._bucket_count += 1
        elif elapsed == 1:
            # Siguiente segundo
            self._histogram.append(self._bucket_count)
            self._bucket_count = 1
            self._bucket_ts = now
        else:
            # Saltamos varios segundos → rellenar con 0
            self._histogram.append(self._bucket_count)
            for _ in range(min(elapsed - 1, self._HISTOGRAM_SECS)):
                self._histogram.append(0)
            self._bucket_count = 1
            self._bucket_ts = now

    def _maybe_reset_counters(self) -> None:
        now = time.time()
        if now - self._counters_reset_ts > self._COUNTER_ROLLOVER_SECS:
            self.rule_counter.clear()
            self.agent_counter.clear()
            self.module_counter.clear()
            self._counters_reset_ts = now

    # ── Public API ────────────────────────────────────────────────────────────

    async def record(
        self,
        *,
        rule_id: str,
        level: int,
        agent_id: str,
        agent_name: str,
        description: str,
        decision: str,            # 'sent' | 'deduped' | 'format_error' | 'waha_error'
        latency_ms: float | None = None,
        alert_timestamp: str = "",
        summary_es: str = "",
        plain_severity: str = "",
        remediation_action: str = "",
    ) -> None:
        """Registra una alerta que pasó por el pipeline. Llama desde api/alerts.py."""
        async with self._lock:
            self._advance_histogram()
            self._maybe_reset_counters()

            # Contadores globales
            self.total_received += 1
            if decision == 'sent':
                self.total_sent += 1
            elif decision == 'deduped':
                self.total_deduped += 1
            elif decision == 'waha_error':
                self.total_waha_errors += 1

            # Contadores de top
            self.rule_counter[rule_id] += 1
            self.agent_counter[agent_name or agent_id] += 1
            module_id = rule_id_to_module(rule_id)
            self.module_counter[module_id] += 1

            # Latencia
            if latency_ms is not None:
                self.latency_samples.append(latency_ms)

            # Alert entry para live stream
            entry: dict[str, Any] = {
                "ts": time.time(),
                "rule_id": rule_id,
                "level": level,
                "agent_id": agent_id,
                "agent_name": agent_name,
                "description": description,
                "decision": decision,
                "module_id": module_id,
                "alert_timestamp": alert_timestamp,
            }
            if latency_ms is not None:
                entry["latency_ms"] = round(latency_ms, 1)
            if summary_es:
                entry["summary_es"] = summary_es
            if plain_severity:
                entry["plain_severity"] = plain_severity
            if remediation_action:
                entry["remediation_action"] = remediation_action
            self.alerts_live.append(entry)

            # Notificar suscriptores SSE
            cond = self._get_condition()
            cond.notify_all()

    async def snapshot(self) -> dict[str, Any]:
        """Devuelve un snapshot completo de métricas. Seguro para usar desde SSE y REST."""
        async with self._lock:
            # Histograma: copia actual + bucket en curso
            hist = list(self._histogram) + [self._bucket_count]
            hist = hist[-self._HISTOGRAM_SECS:]  # siempre 60 valores

            # Latencia promedio
            lat_avg = (
                round(sum(self.latency_samples) / len(self.latency_samples), 1)
                if self.latency_samples else None
            )
            lat_p95 = (
                round(sorted(self.latency_samples)[int(len(self.latency_samples) * 0.95)], 1)
                if len(self.latency_samples) >= 10 else None
            )

            # Alertas últimos 60s
            now = time.time()
            alerts_60s = [a for a in self.alerts_live if now - a["ts"] <= 60]

            return {
                "ts": now,
                "uptime_sec": round(now - self.started_at),
                "kpis": {
                    "total_received": self.total_received,
                    "total_sent": self.total_sent,
                    "total_deduped": self.total_deduped,
                    "total_waha_errors": self.total_waha_errors,
                    "alerts_last_60s": len(alerts_60s),
                    "lat_avg_ms": lat_avg,
                    "lat_p95_ms": lat_p95,
                },
                "histogram": hist,
                "alerts_live": list(self.alerts_live),
                "top_rules": [
                    {"rule_id": rid, "count": cnt}
                    for rid, cnt in self.rule_counter.most_common(self._TOP_N)
                ],
                "top_agents": [
                    {"agent": agent, "count": cnt}
                    for agent, cnt in self.agent_counter.most_common(self._TOP_N)
                ],
                "top_modules": [
                    {"module_id": mod, "count": cnt}
                    for mod, cnt in self.module_counter.most_common(self._TOP_N)
                ],
            }

    async def wait_for_update(self, timeout: float = 1.5) -> None:
        """Espera hasta que llegue una nueva alerta (para SSE push) o se cumpla el timeout."""
        try:
            cond = self._get_condition()
            async with cond:
                await asyncio.wait_for(cond.wait(), timeout=timeout)
        except (asyncio.TimeoutError, Exception):
            pass  # timeout normal → emitir heartbeat


# Singleton de proceso — cada worker uvicorn tiene el suyo
telemetry_store = TelemetryStore()
