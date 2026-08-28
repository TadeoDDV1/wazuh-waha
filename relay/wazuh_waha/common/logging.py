import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from ..common.context import WORKER_ID
from ..config import settings


JSON_FMT = (
    '{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s",'
    '"worker":' + str(WORKER_ID) + ',"msg":"%(message)s"}'
)
HUMAN_FMT = (
    "%(asctime)s [%(levelname)-7s] wazuh-waha[%(process)d] :: %(message)s"
)
DATE_FMT = "%Y-%m-%d %H:%M:%S"

log = logging.getLogger("wazuh-waha")
log.setLevel(logging.INFO)

_jh = logging.StreamHandler()
_jh.setFormatter(logging.Formatter(JSON_FMT))
log.addHandler(_jh)

try:
    log_dir = Path(settings.relay_log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    _fh = RotatingFileHandler(
        log_dir / f"wazuh-waha-{WORKER_ID}.log",
        maxBytes=2_000_000,
        backupCount=3,
        encoding="utf-8",
    )
    _fh.setFormatter(logging.Formatter(HUMAN_FMT, DATE_FMT))
    log.addHandler(_fh)
    log.info("file_logger_init path=%s", log_dir / f"wazuh-waha-{WORKER_ID}.log")
except Exception as e:
    log.warning("file_logger_init_failed err=%s continuando_solo_journal", e)
