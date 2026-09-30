from fastapi import APIRouter, Depends

from .. import __version__
from ..common.backup import list_backups
from ..common.context import WORKER_ID, get_recent, get_worker_info
from .deps import verify_api_key

router = APIRouter(tags=["debug"])

# /health queda público para healthchecks, pero no expone datos de recon
# (worker_id/PID) ni estado interno.


@router.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "wazuh-waha",
        "version": __version__,
    }


@router.get("/debug/recent")
async def debug_recent(_: None = Depends(verify_api_key)):
    return get_recent()


@router.get("/debug/workers")
async def debug_workers(_: None = Depends(verify_api_key)):
    return get_worker_info()


@router.get("/debug/backups")
async def debug_backups(_: None = Depends(verify_api_key)):
    return list_backups()
