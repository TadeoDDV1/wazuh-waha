from fastapi import APIRouter

from .. import __version__
from ..common.backup import list_backups
from ..common.context import WORKER_ID, get_recent, get_worker_info
from ..common.logging import log

router = APIRouter(tags=["debug"])


@router.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "wazuh-waha",
        "version": __version__,
        "worker_id": WORKER_ID,
    }


@router.get("/debug/recent")
async def debug_recent():
    return get_recent()


@router.get("/debug/workers")
async def debug_workers():
    return get_worker_info()


@router.get("/debug/backups")
async def debug_backups():
    return list_backups()

