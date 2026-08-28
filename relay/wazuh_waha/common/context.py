import os
import time
from collections import deque


WORKER_ID = os.getpid()

_RECENT_CAP = 50
_recent: deque[dict] = deque(maxlen=_RECENT_CAP)
_worker_started_at = time.time()


def record_recent(entry: dict) -> None:
    _recent.append(entry)


def get_recent() -> dict:
    return {
        "count": len(_recent),
        "max": _RECENT_CAP,
        "worker_id": WORKER_ID,
        "alerts": list(_recent),
    }


def get_worker_info() -> dict:
    return {
        "worker_id": WORKER_ID,
        "pid": WORKER_ID,
        "started_at": _worker_started_at,
        "uptime_sec": time.time() - _worker_started_at,
    }
