import fcntl
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..config import settings

_log = logging.getLogger("wazuh-waha.backup")


def get_backup_dir() -> Path:
    """Devuelve el Path al directorio de backups configurado."""
    return Path(settings.relay_backup_dir)


def save_alert_backup(record: dict[str, Any], raw_alert: dict[str, Any] | None = None) -> Path | None:
    """
    Guarda un registro estructurado de la alerta en formato JSONL en la carpeta backups.
    Cada línea contiene la metadata del procesamiento y el payload crudo recibido.
    Multi-worker safe con fcntl.flock.
    """
    if not getattr(settings, "relay_backup_enabled", True):
        return None

    try:
        backup_dir = get_backup_dir()
        backup_dir.mkdir(parents=True, exist_ok=True)

        today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        file_path = backup_dir / f"alerts-{today_str}.jsonl"

        entry = dict(record)
        entry["backup_ts"] = datetime.now(timezone.utc).isoformat()
        if raw_alert is not None:
            entry["raw_alert"] = raw_alert

        line = json.dumps(entry, ensure_ascii=False) + "\n"

        with open(file_path, "a", encoding="utf-8") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                f.write(line)
                f.flush()
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)

        _log.debug("backup_saved path=%s rule_id=%s", file_path, record.get("rule_id"))
        return file_path
    except Exception as e:
        _log.warning("backup_save_failed err=%s", e)
        return None


def list_backups(limit_files: int = 10, tail_lines: int = 5) -> dict[str, Any]:
    """Retorna un resumen de los archivos de backup existentes."""
    backup_dir = get_backup_dir()
    enabled = getattr(settings, "relay_backup_enabled", True)

    if not backup_dir.exists():
        return {
            "enabled": enabled,
            "backup_dir": str(backup_dir),
            "total_files": 0,
            "files": [],
        }

    files_info = []
    backup_files = sorted(backup_dir.glob("alerts-*.jsonl"), reverse=True)

    for p in backup_files[:limit_files]:
        stat = p.stat()
        lines = []
        try:
            with open(p, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except Exception:
            pass

        sample = []
        for line in lines[-tail_lines:]:
            try:
                sample.append(json.loads(line))
            except Exception:
                sample.append({"raw": line.strip()})

        files_info.append({
            "filename": p.name,
            "size_bytes": stat.st_size,
            "updated_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            "total_records": len(lines),
            "recent_samples": sample,
        })

    return {
        "enabled": enabled,
        "backup_dir": str(backup_dir),
        "total_files": len(backup_files),
        "files": files_info,
    }
