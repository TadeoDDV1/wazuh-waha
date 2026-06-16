# Tests

(pendiente — alcance actual no incluye tests)

Tests planeados:
- `test_dedup.py` — Deduper con fcntl.flock (file lock atómico).
- `test_formatter.py` — orquesta dedup → template → default.
- `test_templates.py` — render() de cada rule_id.
- `test_waha_client.py` — mock httpx, cubre success / 4xx / 5xx / timeout.
- `test_main.py` — FastAPI TestClient, /health /alerts /debug/recent.
