"""API de control y exploración de Wazuh.

Endpoints nuevos (no rompen los existentes /api/v1/dashboard/wazuh/*):
  GET  /api/v1/wazuh/overview
  GET  /api/v1/wazuh/modules
  POST /api/v1/wazuh/modules/toggle
  GET  /api/v1/wazuh/manager/config
  POST /api/v1/wazuh/manager/toggle
  GET  /api/v1/wazuh/detections
  GET  /api/v1/wazuh/detections/{module}/{agent_id}
"""

from __future__ import annotations

import re
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from .deps import verify_api_key, verify_write
from ..common.logging import log
from ..config import settings
from ..infrastructure import wazuh_control as control
from ..infrastructure.wazuh_api import wazuh_api, WazuhAPIError

router = APIRouter(prefix="/api/v1/wazuh", tags=["wazuh-control"])


@router.get("/overview")
async def overview(_: None = Depends(verify_api_key)):
    return await control.get_overview()


@router.get("/modules")
async def modules(_: None = Depends(verify_api_key)):
    groups = await control.get_groups()
    state: dict[str, Any] = {}
    for g in groups:
        name = g.get("name", "default")
        try:
            data = await control.get_agent_conf_state(name)
            state[name] = data.get("state", {})
        except Exception as exc:
            state[name] = {"error": str(exc)}
    manager_cfg = await control.get_manager_config()
    return {
        "ok": True,
        "groups": groups,
        "agents": await control.get_agents(),
        "agent_modules": control.AGENT_MODULES,
        "modules_meta": control.MODULE_META,
        "state": state,
        "manager": manager_cfg,
        "timestamp": time.time(),
    }


@router.post("/modules/toggle")
async def toggle_module(request: Request, _: None = Depends(verify_write)):
    body = await request.json()
    group = str(body.get("group") or "default")
    scope = str(body.get("scope") or "global")
    module = str(body.get("module") or "")
    enabled = bool(body.get("enabled", True))
    if not module:
        raise HTTPException(status_code=400, detail="module requerido")
    if module not in control.AGENT_MODULES:
        raise HTTPException(
            status_code=400,
            detail=(
                f"'{module}' no es un módulo de agente editable. "
                "Los módulos de manager se configuran en ossec.conf y los grupos de reglas se silencian."
            ),
        )
    try:
        result = await control.toggle_agent_module(group, scope, module, enabled)
    except control.WazuhControlError as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    log.info("wazuh_module_toggled group=%s scope=%s module=%s enabled=%s",
             group, scope, module, enabled)
    return result


@router.get("/manager/config")
async def manager_config(_: None = Depends(verify_api_key)):
    return await control.get_manager_config()


@router.post("/manager/toggle")
async def toggle_manager_module(request: Request, _: None = Depends(verify_write)):
    body = await request.json()
    module = str(body.get("module") or "")
    enabled = bool(body.get("enabled", True))

    if not settings.wazuh_manager_config_write_enabled:
        raise HTTPException(
            status_code=403,
            detail=(
                "Edición de ossec.conf deshabilitada. Activar "
                "WAZUH_MANAGER_CONFIG_WRITE_ENABLED=true y configurar sudoers sin password."
            ),
        )
    if module not in ("vulnerabilities",):
        raise HTTPException(status_code=400, detail="Módulo de manager no soportado para edición")

    from ..infrastructure.ssh_pool import ssh_pool, SSHError

    if not await ssh_pool.sudo_available():
        raise HTTPException(status_code=403, detail="sudo -n no disponible en el manager")

    path = "/var/ossec/etc/ossec.conf"
    try:
        raw = await ssh_pool.read_text(path)
    except SSHError as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    tag = "vulnerability-detection" if "<vulnerability-detection" in raw else "vulnerability-detector"
    pattern = re.compile(rf"(<{tag}\b[^>]*>)(.*?)(</{tag}>)", re.S)
    m = pattern.search(raw)
    if not m:
        raise HTTPException(status_code=404, detail=f"Bloque <{tag}> no encontrado en ossec.conf")
    body_xml = m.group(2)

    if re.search(r"<enabled>\s*(yes|no)\s*</enabled>", body_xml, re.I):
        new_body = re.sub(
            r"<enabled>\s*(yes|no)\s*</enabled>",
            f"<enabled>{'yes' if enabled else 'no'}</enabled>",
            body_xml,
            count=1,
            flags=re.I,
        )
    elif re.search(r"<disabled>\s*(yes|no)\s*</disabled>", body_xml, re.I):
        new_body = re.sub(
            r"<disabled>\s*(yes|no)\s*</disabled>",
            f"<disabled>{'no' if enabled else 'yes'}</disabled>",
            body_xml,
            count=1,
            flags=re.I,
        )
    else:
        new_body = body_xml + f"\n    <enabled>{'yes' if enabled else 'no'}</enabled>\n  "
    new_raw = raw[:m.start(2)] + new_body + raw[m.end(2):]

    from pathlib import Path

    backup_dir = Path(settings.relay_backup_dir)
    backup_dir.mkdir(parents=True, exist_ok=True)
    backup = backup_dir / f"ossec-conf-{int(time.time())}.xml"
    backup.write_text(raw, encoding="utf-8")

    try:
        await ssh_pool.write_bytes_b64_sudo(path, new_raw.encode("utf-8"))
        rc, out, err = await ssh_pool.run("sudo -n systemctl restart wazuh-manager", timeout=30)
        if rc != 0:
            raise HTTPException(status_code=500, detail=f"Error reiniciando manager: {err[:300]}")
    except SSHError as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    log.warning("wazuh_manager_module_toggled module=%s enabled=%s backup=%s",
                module, enabled, backup)
    return {
        "ok": True,
        "module": module,
        "enabled": enabled,
        "backup": str(backup),
        "message": "ossec.conf actualizado y wazuh-manager reiniciado",
    }


def _detection_from_alert(a: dict[str, Any]) -> dict[str, Any]:
    rule = a.get("rule", {}) or {}
    agent = a.get("agent", {}) or {}
    item = {
        "module": "alerts",
        "timestamp": a.get("timestamp"),
        "agent_id": str(agent.get("id", "000")),
        "agent_name": agent.get("name", "?"),
        "rule_id": str(rule.get("id", "?")),
        "level": int(rule.get("level", 0) or 0),
        "description": rule.get("description", "?"),
        "groups": rule.get("groups", []),
        "mitre": rule.get("mitre", {}),
        "src_ip": (a.get("data", {}) or {}).get("srcip", ""),
        "full_log": a.get("full_log", ""),
        "raw": a,
    }
    try:
        from ..common.traffic_stream import normalize_wazuh_event

        enriched = normalize_wazuh_event({**a, "_source": "wazuh"})
        enrichment = enriched.get("enrichment")
        if enrichment:
            item["enrichment"] = enrichment
            item["description_es"] = (enrichment.get("translations") or {}).get("description_es")
    except Exception as exc:
        log.debug("detection_enrichment_error rule=%s err=%s", item["rule_id"], exc)
    return item


@router.get("/detections")
async def detections(
    agent_id: str = Query("all"),
    module: str = Query("all"),
    level_min: int = Query(0, ge=0, le=15),
    q: str = Query(""),
    limit: int = Query(200, ge=1, le=1000),
    _: None = Depends(verify_api_key),
):
    alerts = await control.read_alerts(limit=1000)
    filtered = control.filter_alerts(
        alerts, agent_id=agent_id, level_min=level_min, q=q, limit=limit
    )
    items = [_detection_from_alert(a) for a in filtered]
    if module and module not in ("all", "alerts"):
        items = [i for i in items if module in (i.get("groups") or [])]
    return {
        "ok": True,
        "module": module,
        "agent_id": agent_id,
        "count": len(items),
        "items": items,
        "timestamp": time.time(),
    }


@router.get("/detections/{module}/{agent_id}")
async def detections_module(
    module: str,
    agent_id: str,
    limit: int = Query(100, ge=1, le=500),
    _: None = Depends(verify_api_key),
):
    aid = str(agent_id)
    try:
        if module == "fim":
            items = await wazuh_api.affected_items(f"/syscheck/{aid}?limit={limit}")
        elif module == "sca":
            items = await wazuh_api.affected_items(f"/sca/{aid}?limit={limit}")
        elif module == "rootcheck":
            items = await wazuh_api.affected_items(f"/rootcheck/{aid}?limit={limit}")
        elif module == "vulnerabilities":
            try:
                items = await wazuh_api.affected_items(f"/vulnerability/{aid}?limit={limit}")
            except WazuhAPIError:
                alerts = await control.read_alerts(limit=1000)
                items = [
                    a for a in control.filter_alerts(alerts, agent_id=aid, limit=limit)
                    if any("vulnerab" in str(g).lower() for g in (a.get("rule", {}) or {}).get("groups", []))
                    or "CVE-" in str((a.get("rule", {}) or {}).get("description", ""))
                ]
        elif module == "syscollector":
            items = await wazuh_api.affected_items(f"/syscollector/{aid}/ports?limit={limit}")
        elif module == "mitre":
            items = await wazuh_api.affected_items(f"/mitre/tactics?limit={limit}")
        elif module == "alerts":
            alerts = await control.read_alerts(limit=1000)
            items = control.filter_alerts(alerts, agent_id=aid, limit=limit)
        else:
            raise HTTPException(status_code=400, detail=f"módulo no soportado: {module}")
    except WazuhAPIError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return {
        "ok": True,
        "module": module,
        "agent_id": aid,
        "count": len(items),
        "items": items,
        "timestamp": time.time(),
    }
