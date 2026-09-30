"""
audit.py — Registro de auditoría de mutaciones (JSONL, multi-worker).

Append con fcntl.flock igual que traffic_journal: cada worker escribe en el
mismo archivo sin pisarse. Rotación simple a .old al superar el máximo.
"""

from __future__ import annotations

import fcntl
import json
import logging
import time
from pathlib import Path
from typing import Any

_log = logging.getLogger("wazuh-waha.audit")

_MAX_AUDIT_BYTES = 5 * 1024 * 1024  # 5 MiB


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _maybe_rotate(self) -> None:
        try:
            if self.path.exists() and self.path.stat().st_size > _MAX_AUDIT_BYTES:
                old = self.path.with_suffix(self.path.suffix + ".old")
                self.path.replace(old)
                _log.info("audit_rotated path=%s -> %s", self.path, old)
        except OSError as e:
            _log.warning("audit_rotate_error err=%s", e)

    def record(
        self,
        *,
        method: str,
        path: str,
        status: int,
        ip: str = "?",
        sid: str = "-",
        scope: str = "-",
        detail: str = "",
    ) -> None:
        entry: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "method": method,
            "path": path,
            "status": status,
            "ip": ip,
            "sid": sid,
            "scope": scope,
        }
        if detail:
            entry["detail"] = detail[:200]
        line = json.dumps(entry, ensure_ascii=False) + "\n"
        try:
            self._maybe_rotate()
            with open(self.path, "a", encoding="utf-8") as fd:
                fcntl.flock(fd.fileno(), fcntl.LOCK_EX)
                try:
                    fd.write(line)
                    fd.flush()
                finally:
                    fcntl.flock(fd.fileno(), fcntl.LOCK_UN)
        except OSError as e:
            _log.warning("audit_write_error err=%s", e)


_audit: AuditLog | None = None


def get_audit_log() -> AuditLog:
    global _audit
    if _audit is None:
        from ..config import settings

        _audit = AuditLog(Path(settings.relay_lib_dir) / "audit.jsonl")
    return _audit
