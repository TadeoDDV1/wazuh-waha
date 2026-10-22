import xml.etree.ElementTree as ET

from wazuh_waha.infrastructure.wazuh_control import (
    apply_agent_module,
    parse_agent_conf,
    filter_alerts,
)
from wazuh_waha.common.network_bus import _parse_ss, _direction


RAW = """<agent_config>
  <syscheck>
    <disabled>no</disabled>
    <directories check_all="yes">/etc</directories>
  </syscheck>
  <sca>
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
  </sca>
  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1m</interval>
  </wodle>
  <rootcheck>
    <disabled>no</disabled>
  </rootcheck>
  <active-response>
    <disabled>no</disabled>
  </active-response>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>
</agent_config>
"""


def test_disable_sca_preserves_other_directives():
    out = apply_agent_module(RAW, "global", "sca", False)
    root = ET.fromstring(out)
    assert root.findtext("sca/enabled") == "no"
    assert root.findtext("sca/scan_on_start") == "yes"
    # Directivas ajenas intactas
    assert root.findtext("syscheck/disabled") == "no"
    assert root.findtext("rootcheck/disabled") == "no"
    assert root.findtext("localfile/location") == "/var/log/syslog"
    assert root.find("wodle[@name='syscollector']").findtext("disabled") == "no"


def test_enable_syscollector_per_agent_creates_scope():
    out = apply_agent_module(RAW, "001", "syscollector", False)
    root = ET.fromstring(out)
    scope = root.find("agent_config[@id='001']")
    assert scope is not None
    assert scope.find("wodle[@name='syscollector']").findtext("disabled") == "yes"
    # El bloque global no se toca
    assert root.find("wodle[@name='syscollector']").findtext("disabled") == "no"


def test_parse_agent_conf_states():
    state = parse_agent_conf(RAW)
    assert state["global"]["fim"] is True
    assert state["global"]["sca"] is True
    out = apply_agent_module(RAW, "global", "fim", False)
    state2 = parse_agent_conf(out)
    assert state2["global"]["fim"] is False


def test_filter_alerts_by_agent_level_and_query():
    alerts = [
        {"rule": {"id": "1", "level": 3, "description": "low"}, "agent": {"id": "001", "name": "a"}, "full_log": "x"},
        {"rule": {"id": "2", "level": 10, "description": "ssh login"}, "agent": {"id": "002", "name": "b"}, "full_log": "y"},
    ]
    assert len(filter_alerts(alerts, agent_id="001")) == 1
    assert len(filter_alerts(alerts, level_min=8)) == 1
    assert filter_alerts(alerts, q="ssh")[0]["rule"]["id"] == "2"


def test_parse_ss_real_connections():
    out = (
        'tcp ESTAB 0 0 192.168.122.142:22 192.168.122.1:54321 users:(("sshd",pid=123,fd=3))\n'
        'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=120,fd=4))\n'
    )
    rows = _parse_ss(out, "000", "manager", "192.168.122.142")
    assert len(rows) == 2
    estab = next(r for r in rows if r["state"] == "ESTAB")
    assert estab["local_ip"] == "192.168.122.142"
    assert estab["remote_ip"] == "192.168.122.1"
    assert estab["remote_port"] == 54321
    assert estab["process"] == "sshd"
    assert estab["pid"] == 123
    assert estab["direction"] == "inbound"
    listen = next(r for r in rows if r["state"] == "LISTEN")
    assert listen["direction"] == "listen"


def test_direction_heuristic():
    assert _direction("ESTAB", 22, 54321) == "inbound"
    assert _direction("ESTAB", 54321, 443) == "outbound"
    assert _direction("LISTEN", 22, 0) == "listen"
