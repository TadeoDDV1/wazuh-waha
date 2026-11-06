"""Control seguro de configuración de Wazuh.

- Módulos de agente: lectura/edición de `agent.conf` preservando el resto del
  XML, backup local y aplicación vía API (`PUT /groups/{group}/configuration`).
- Módulos del manager: lectura de `ossec.conf` por SSH. La escritura queda
  deshabilitada por defecto (`WAZUH_MANAGER_CONFIG_WRITE_ENABLED=false`).
"""

from __future__ import annotations

import json
import re
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from ..common.logging import log
from ..config import settings
from .ssh_pool import ssh_pool, SSHError
from .wazuh_api import wazuh_api, WazuhAPIError

AGENT_MODULES: dict[str, dict[str, str]] = {
    "fim": {"tag": "syscheck", "flag": "disabled", "on": "no", "off": "yes"},
    "sca": {"tag": "sca", "flag": "enabled", "on": "yes", "off": "no"},
    "syscollector": {"tag": "wodle:syscollector", "flag": "disabled", "on": "no", "off": "yes"},
    "rootcheck": {"tag": "rootcheck", "flag": "disabled", "on": "no", "off": "yes"},
    "threat_hunting": {"tag": "active-response", "flag": "disabled", "on": "no", "off": "yes"},
}

MODULE_META: list[dict[str, Any]] = [
    {"id": "fim", "name": "Monitoreo de Integridad de Archivos (FIM)", "level": "agent", "directive": "syscheck"},
    {"id": "sca", "name": "Evaluación de Configuración (CIS/SCA)", "level": "agent", "directive": "sca"},
    {"id": "rootcheck", "name": "Detección de Malware / Rootkits", "level": "agent", "directive": "rootcheck"},
    {"id": "syscollector", "name": "Higiene Informática (Syscollector)", "level": "agent", "directive": "wodle:syscollector"},
    {"id": "threat_hunting", "name": "Respuesta Activa / Caza de Amenazas", "level": "agent", "directive": "active-response"},
    {"id": "vulnerabilities", "name": "Detección de Vulnerabilidades (CVE)", "level": "manager", "directive": "vulnerability-detector"},
    {"id": "mitre", "name": "MITRE ATT&CK (enriquecimiento)", "level": "rule_group", "directive": "mitre"},
    {"id": "pci_dss", "name": "PCI DSS (grupo de reglas)", "level": "rule_group", "directive": "compliance:pci_dss"},
    {"id": "gdpr", "name": "GDPR (grupo de reglas)", "level": "rule_group", "directive": "compliance:gdpr"},
    {"id": "hipaa", "name": "HIPAA (grupo de reglas)", "level": "rule_group", "directive": "compliance:hipaa"},
    {"id": "nist_800_53", "name": "NIST 800-53 (grupo de reglas)", "level": "rule_group", "directive": "compliance:nist_800_53"},
    {"id": "tsc", "name": "TSC (grupo de reglas)", "level": "rule_group", "directive": "compliance:tsc"},
]


class WazuhControlError(Exception):
    pass


_GROUP_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_AGENT_SCOPE_RE = re.compile(r"^(global|default|all|[A-Za-z0-9][A-Za-z0-9._-]{0,63})$")


def _validate_group(group: str) -> str:
    """Evita path traversal / inyección en la ruta remota y en la URL de la API."""
    if not isinstance(group, str) or not _GROUP_RE.match(group):
        raise WazuhControlError(f"Grupo inválido: {group!r}")
    return group


def _validate_scope(scope: str) -> str:
    if scope == "":
        return scope
    if isinstance(scope, str) and _AGENT_SCOPE_RE.match(scope):
        return scope
    raise WazuhControlError(f"Scope de agente inválido: {scope!r}")


def _agent_conf_path(group: str) -> str:
    return f"/var/ossec/etc/shared/{_validate_group(group)}/agent.conf"


async def read_agent_conf(group: str = "default") -> str:
    if not ssh_pool.configured:
        raise WazuhControlError(
            "SSH al manager no configurado; no se puede leer agent.conf de forma segura"
        )
    return await ssh_pool.read_text(_agent_conf_path(group))


def _backup_agent_conf(group: str, raw: str) -> Path:
    group = _validate_group(group)
    backup_dir = Path(settings.relay_backup_dir)
    backup_dir.mkdir(parents=True, exist_ok=True)
    path = backup_dir / f"agent-conf-{group}-{int(time.time())}.xml"
    path.write_text(raw, encoding="utf-8")
    return path


def _root_for_scope(root: ET.Element, scope: str) -> ET.Element:
    scope = _validate_scope(scope)
    if not scope or scope in ("global", "default", "all"):
        return root
    for child in root.findall("agent_config"):
        if child.get("id") == str(scope):
            return child
    child = ET.SubElement(root, "agent_config", {"id": str(scope)})
    return child


def _find_or_create(parent: ET.Element, tag: str) -> ET.Element:
    if tag.startswith("wodle:"):
        name = tag.split(":", 1)[1]
        for el in parent.findall("wodle"):
            if el.get("name") == name:
                return el
        return ET.SubElement(parent, "wodle", {"name": name})
    el = parent.find(tag)
    if el is None:
        el = ET.SubElement(parent, tag)
    return el


def _set_flag(parent: ET.Element, tag: str, flag: str, value: str) -> None:
    el = _find_or_create(parent, tag)
    flag_el = el.find(flag)
    if flag_el is None:
        flag_el = ET.SubElement(el, flag)
    flag_el.text = value


def apply_agent_module(raw: str, scope: str, module: str, enabled: bool) -> str:
    """Devuelve el XML completo de agent.conf con solo el módulo indicado cambiado."""
    spec = AGENT_MODULES.get(module)
    if not spec:
        raise WazuhControlError(
            f"'{module}' no es un módulo de agente editable (nivel manager/rule_group)"
        )
    try:
        root = ET.fromstring(raw) if raw.strip() else ET.Element("agent_config")
    except ET.ParseError as exc:
        raise WazuhControlError(f"agent.conf inválido: {exc}") from exc

    target = _root_for_scope(root, scope)
    _set_flag(target, spec["tag"], spec["flag"], spec["on"] if enabled else spec["off"])
    xml = ET.tostring(root, encoding="unicode")
    return xml


def parse_agent_conf(raw: str) -> dict[str, dict[str, bool]]:
    """Devuelve {scope: {module: enabled}} a partir del XML."""
    out: dict[str, dict[str, bool]] = {"global": {}}
    try:
        root = ET.fromstring(raw) if raw.strip() else ET.Element("agent_config")
    except ET.ParseError:
        return out

    def read_block(el: ET.Element) -> dict[str, bool]:
        state: dict[str, bool] = {}
        syscheck = el.find("syscheck")
        if syscheck is not None:
            state["fim"] = (syscheck.findtext("disabled") or "no").lower() != "yes"
        sca = el.find("sca")
        if sca is not None:
            state["sca"] = (sca.findtext("enabled") or "yes").lower() != "no"
        rootcheck = el.find("rootcheck")
        if rootcheck is not None:
            state["rootcheck"] = (rootcheck.findtext("disabled") or "no").lower() != "yes"
        for wodle in el.findall("wodle"):
            if wodle.get("name") == "syscollector":
                state["syscollector"] = (wodle.findtext("disabled") or "no").lower() != "yes"
        ar = el.find("active-response")
        if ar is not None:
            state["threat_hunting"] = (ar.findtext("disabled") or "no").lower() != "yes"
        return state

    global_state = read_block(root)
    out["global"] = {m: global_state.get(m, True) for m in AGENT_MODULES}
    for child in root.findall("agent_config"):
        aid = child.get("id")
        if not aid:
            continue
        base = dict(out["global"])
        base.update(read_block(child))
        out[str(aid)] = {m: base.get(m, True) for m in AGENT_MODULES}
    return out


async def get_groups() -> list[dict[str, Any]]:
    try:
        return await wazuh_api.affected_items("/groups")
    except Exception:
        return [{"name": "default", "count": 1}]


async def get_agents() -> list[dict[str, Any]]:
    return await wazuh_api.affected_items("/agents?limit=500")


async def get_agent_conf_state(group: str = "default") -> dict[str, Any]:
    raw = await read_agent_conf(group)
    return {"raw": raw, "state": parse_agent_conf(raw)}


async def toggle_agent_module(
    group: str, scope: str, module: str, enabled: bool, *, restart: bool = True
) -> dict[str, Any]:
    raw = await read_agent_conf(group)
    backup = _backup_agent_conf(group, raw)
    new_xml = apply_agent_module(raw, scope, module, enabled)

    from urllib.parse import quote

    r = await wazuh_api.put(
        f"/groups/{quote(_validate_group(group), safe='')}/configuration",
        content=new_xml.encode("utf-8"),
        headers={"Content-Type": "application/xml"},
        timeout=20,
    )
    if not r.is_success:
        raise WazuhControlError(f"Error guardando agent.conf: HTTP {r.status_code} {r.text[:300]}")

    restarted: list[str] = []
    if restart:
        restarted = await restart_agents(scope)

    return {
        "ok": True,
        "group": group,
        "scope": scope,
        "module": module,
        "enabled": enabled,
        "backup": str(backup),
        "restarted_agents": restarted,
        "xml": new_xml,
        "state": parse_agent_conf(new_xml),
    }



async def restart_agents(scope: str = "global") -> list[str]:
    """Reinicia agentes activos (excluye 000, que es el manager)."""
    scope = _validate_scope(scope)
    ids: list[str] = []
    if scope in ("", "global", "default", "all"):
        try:
            agents = await get_agents()
            ids = [
                str(a.get("id")) for a in agents
                if str(a.get("id")) != "000" and str(a.get("status")) == "active"
            ]
        except Exception:
            ids = []
    else:
        ids = [str(scope)] if str(scope) != "000" else []
    if not ids:
        return []
    try:
        r = await wazuh_api.put(
            f"/agents/restart?agents_list={','.join(ids)}", timeout=15
        )
        if r.is_success:
            return r.json().get("data", {}).get("affected_items", []) or ids
    except Exception as exc:
        log.warning("wazuh_restart_agents_error scope=%s err=%s", scope, exc)
    return []


async def get_manager_config() -> dict[str, Any]:
    """Lee ossec.conf y devuelve estado de módulos del manager."""
    try:
        raw = await ssh_pool.read_text("/var/ossec/etc/ossec.conf")
    except Exception as exc:
        return {"ok": False, "error": str(exc), "modules": {}}

    def block_enabled(tag: str) -> bool | None:
        # Soporta <disabled> (agentes) y <enabled> (manager 4.14).
        m = re.search(rf"<{re.escape(tag)}\b[^>]*>(.*?)</{re.escape(tag)}>", raw, re.S)
        if not m:
            return None
        body = m.group(1)
        dm = re.search(r"<disabled>\s*(yes|no)\s*</disabled>", body, re.I)
        if dm:
            return dm.group(1).lower() != "yes"
        em = re.search(r"<enabled>\s*(yes|no)\s*</enabled>", body, re.I)
        if em:
            return em.group(1).lower() == "yes"
        return True

    def wodle_block(name: str) -> bool | None:
        m = re.search(
            rf"<wodle\s+name=[\"']{re.escape(name)}[\"'][^>]*>(.*?)</wodle>",
            raw, re.S | re.I,
        )
        if not m:
            return None
        dm = re.search(r"<disabled>\s*(yes|no)\s*</disabled>", m.group(1), re.I)
        return (dm.group(1).lower() != "yes") if dm else True

    vuln_tag = "vulnerability-detection" if "<vulnerability-detection" in raw else "vulnerability-detector"
    modules = {
        "vulnerabilities": block_enabled(vuln_tag),
        "syscheck": block_enabled("syscheck"),
        "sca": block_enabled("sca"),
        "rootcheck": block_enabled("rootcheck"),
        "syscollector": wodle_block("syscollector"),
        "logall_json": (re.search(r"<logall_json>\s*yes\s*</logall_json>", raw, re.I) is not None),
    }
    modules["_vuln_tag"] = vuln_tag
    return {
        "ok": True,
        "write_enabled": bool(settings.wazuh_manager_config_write_enabled),
        "sudo_available": await ssh_pool.sudo_available(),
        "modules": modules,
        "raw_excerpt": raw[:2000],
    }


async def get_overview() -> dict[str, Any]:
    manager_status: dict[str, Any] = {}
    manager_info: dict[str, Any] = {}
    agents: list[dict[str, Any]] = []
    errors: list[str] = []

    try:
        data = await wazuh_api.json_or_error("GET", "/manager/status")
        items = data.get("data", {}).get("affected_items", [])
        manager_status = items[0] if items else {}
    except Exception as exc:
        errors.append(f"manager/status: {exc}")
    try:
        data = await wazuh_api.json_or_error("GET", "/manager/info")
        items = data.get("data", {}).get("affected_items", [])
        manager_info = items[0] if items else {}
    except Exception as exc:
        errors.append(f"manager/info: {exc}")
    try:
        agents = await get_agents()
    except Exception as exc:
        errors.append(f"agents: {exc}")

    manager_cfg = await get_manager_config()
    groups = await get_groups()
    module_state: dict[str, Any] = {}
    for g in groups:
        name = g.get("name", "default")
        try:
            module_state[name] = await get_agent_conf_state(name)
        except Exception as exc:
            module_state[name] = {"error": str(exc), "state": {}}

    return {
        "ok": True,
        "manager": {
            "status": manager_status,
            "info": manager_info,
            "config": manager_cfg,
        },
        "agents": agents,
        "groups": groups,
        "module_state": module_state,
        "module_meta": MODULE_META,
        "errors": errors,
        "timestamp": time.time(),
    }


def _matches(alert: dict[str, Any], q: str) -> bool:
    if not q:
        return True
    q = q.lower()
    rule = alert.get("rule", {}) or {}
    agent = alert.get("agent", {}) or {}
    hay = " ".join([
        str(rule.get("id", "")),
        str(rule.get("description", "")),
        str(agent.get("name", "")),
        str(alert.get("full_log", "")),
    ]).lower()
    return q in hay


async def read_alerts(limit: int = 300) -> list[dict[str, Any]]:
    path = "/var/ossec/logs/alerts/alerts.json"
    try:
        rc, out, err = await ssh_pool.run(f"tail -n {int(limit)} {path}", timeout=10)
    except Exception:
        return []
    if rc != 0:
        return []
    alerts = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            alerts.append(json.loads(line))
        except Exception:
            continue
    return alerts


def filter_alerts(
    alerts: list[dict[str, Any]],
    *,
    agent_id: str = "",
    level_min: int = 0,
    q: str = "",
    limit: int = 200,
) -> list[dict[str, Any]]:
    out = []
    for a in alerts:
        rule = a.get("rule", {}) or {}
        agent = a.get("agent", {}) or {}
        try:
            level = int(rule.get("level", 0))
        except (TypeError, ValueError):
            level = 0
        if agent_id and agent_id != "all" and str(agent.get("id")) != str(agent_id):
            continue
        if level < level_min:
            continue
        if not _matches(a, q):
            continue
        out.append(a)
        if len(out) >= limit:
            break
    return out
