"""Caché de enriquecimiento compartida entre workers.

Usa SQLite si el archivo es escribible; si no, cae a un diccionario en
memoria. La caché nunca debe romper el pipeline: cualquier error se registra
y se continúa sin cachear.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from ...config import settings

log = logging.getLogger("wazuh-waha.enrichment.cache")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS enrichment_cache (
    key TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    hits INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_enrichment_expires ON enrichment_cache(expires_at);
"""


class EnrichmentCache:
    def __init__(
        self,
        path: str | Path | None = None,
        *,
        ttl_sec: int | None = None,
        enabled: bool | None = None,
    ) -> None:
        self.path = Path(path or settings.enrich_cache_path)
        self.ttl_sec = int(ttl_sec if ttl_sec is not None else settings.enrich_cache_ttl_sec)
        self.enabled = bool(enabled if enabled is not None else settings.enrich_cache_enabled)
        self._memory: dict[str, tuple[Any, float]] = {}
        self._lock = threading.Lock()
        self._db_ok = False
        if self.enabled:
            self._init_db()

    # ── SQLite ─────────────────────────────────────────────────────────────

    def _init_db(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(self.path, timeout=1.0) as conn:
                conn.executescript(_SCHEMA)
                conn.commit()
            self._db_ok = True
        except Exception as exc:
            self._db_ok = False
            log.warning("enrichment_cache_db_unavailable path=%s err=%s", self.path, exc)

    def _connect(self) -> sqlite3.Connection | None:
        if not self._db_ok:
            return None
        try:
            return sqlite3.connect(self.path, timeout=1.0)
        except Exception as exc:
            log.warning("enrichment_cache_connect_error err=%s", exc)
            self._db_ok = False
            return None

    # ── API ────────────────────────────────────────────────────────────────

    def get(self, key: str) -> Any | None:
        if not self.enabled:
            return None
        now = int(time.time())
        conn = self._connect()
        if conn is not None:
            try:
                with conn:
                    row = conn.execute(
                        "SELECT value, expires_at FROM enrichment_cache WHERE key = ?",
                        (key,),
                    ).fetchone()
                    if row is None:
                        return None
                    value, expires_at = row
                    if int(expires_at) <= now:
                        conn.execute("DELETE FROM enrichment_cache WHERE key = ?", (key,))
                        return None
                    conn.execute(
                        "UPDATE enrichment_cache SET hits = hits + 1 WHERE key = ?",
                        (key,),
                    )
                return json.loads(value)
            except Exception as exc:
                log.warning("enrichment_cache_get_error err=%s", exc)
                return None
            finally:
                conn.close()

        with self._lock:
            item = self._memory.get(key)
            if item is None:
                return None
            value, expires_at = item
            if expires_at <= now:
                self._memory.pop(key, None)
                return None
            return value

    def set(self, key: str, kind: str, value: Any, ttl_sec: int | None = None) -> None:
        if not self.enabled:
            return
        ttl = int(ttl_sec if ttl_sec is not None else self.ttl_sec)
        now = int(time.time())
        expires_at = now + max(1, ttl)
        try:
            payload = json.dumps(value, ensure_ascii=False, default=str)
        except Exception as exc:
            log.warning("enrichment_cache_serialize_error err=%s", exc)
            return

        conn = self._connect()
        if conn is not None:
            try:
                with conn:
                    conn.execute(
                        """
                        INSERT INTO enrichment_cache (key, kind, value, created_at, expires_at, hits)
                        VALUES (?, ?, ?, ?, ?, 0)
                        ON CONFLICT(key) DO UPDATE SET
                            kind = excluded.kind,
                            value = excluded.value,
                            created_at = excluded.created_at,
                            expires_at = excluded.expires_at
                        """,
                        (key, kind, payload, now, expires_at),
                    )
                return
            except Exception as exc:
                log.warning("enrichment_cache_set_error err=%s", exc)
            finally:
                conn.close()

        with self._lock:
            self._memory[key] = (value, expires_at)

    def purge_expired(self) -> int:
        if not self.enabled:
            return 0
        now = int(time.time())
        deleted = 0
        conn = self._connect()
        if conn is not None:
            try:
                with conn:
                    cur = conn.execute(
                        "DELETE FROM enrichment_cache WHERE expires_at <= ?", (now,)
                    )
                    deleted = cur.rowcount or 0
                return deleted
            except Exception as exc:
                log.warning("enrichment_cache_purge_error err=%s", exc)
            finally:
                conn.close()

        with self._lock:
            expired = [k for k, (_, exp) in self._memory.items() if exp <= now]
            for key in expired:
                self._memory.pop(key, None)
            return len(expired)

    def stats(self) -> dict[str, Any]:
        conn = self._connect()
        if conn is not None:
            try:
                with conn:
                    row = conn.execute(
                        "SELECT COUNT(*), COALESCE(SUM(hits), 0) FROM enrichment_cache"
                    ).fetchone()
                return {
                    "backend": "sqlite",
                    "path": str(self.path),
                    "entries": int(row[0] or 0),
                    "hits": int(row[1] or 0),
                    "enabled": self.enabled,
                }
            except Exception:
                pass
            finally:
                conn.close()
        with self._lock:
            return {
                "backend": "memory",
                "path": str(self.path),
                "entries": len(self._memory),
                "hits": 0,
                "enabled": self.enabled,
            }
