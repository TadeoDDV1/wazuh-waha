import pytest
from wazuh_waha.domain import templates


def test_extract_clean_ip_direct_data():
    alert = {
        "data": {"srcip": "198.51.100.25"},
        "full_log": "Oct 16 12:00:00 srv sshd[123]: Failed password for root from 198.51.100.25 port 55432",
    }
    assert templates.extract_clean_ip(alert) == "198.51.100.25"


def test_extract_clean_ip_root_field():
    alert = {
        "srcip": "203.0.113.88",
        "full_log": "Oct 16 12:00:00 srv sshd[123]: Invalid user test from 203.0.113.88 port 44321",
    }
    assert templates.extract_clean_ip(alert) == "203.0.113.88"


def test_extract_clean_ip_from_regex_in_full_log():
    # Alerta sin campo srcip estructurado: debe extraerse limpiamente con regex
    alert = {
        "rule": {"id": "5710", "level": 8, "description": "SSH auth failed"},
        "full_log": "Oct 16 12:00:00 srv sshd[123]: Failed password for invalid user admin from 172.217.16.206 port 60123 ssh2",
    }
    ip = templates.extract_clean_ip(alert)
    assert ip == "172.217.16.206"
    assert "Oct 16" not in ip
    assert "sshd" not in ip


def test_extract_clean_ip_never_returns_raw_log():
    # Alerta local pura sin IP: nunca debe devolver fragmentos de log
    alert = {
        "rule": {"id": "57104", "level": 8, "description": "sudo executed"},
        "full_log": "Oct 16 12:00:00 srv sudo: tadeou7 : TTY=pts/1 ; PWD=/home/tadeo ; USER=root ; COMMAND=/bin/ls",
    }
    ip = templates.extract_clean_ip(alert)
    assert ip == "🏠 Local / Consola"
    assert "COMMAND" not in ip
    assert "Oct 16" not in ip


def test_field_never_falls_back_to_raw_log():
    alert = {
        "full_log": "Oct 16 12:00:00 srv systemd: Critical error occurred in custom daemon process",
    }
    # Campo desconocido con default
    res = templates._field(alert, "unknown_field", default="?")
    assert res == "?"
    assert "Critical error" not in res
    assert "Oct 16" not in res


def test_render_soc_alert_clean_formatting():
    alert = {
        "rule": {"id": "57120", "level": 12, "description": "SSH Brute Force"},
        "agent": {"id": "002", "name": "srv-db"},
        "timestamp": "2026-10-16 11:00:00",
        "data": {"srcip": "185.220.101.5", "srcport": "41234"},
        "full_log": "Oct 16 11:00:00 srv sshd[999]: Multiple failed logins from 185.220.101.5",
    }
    rendered = templates.render("57120", alert)
    assert rendered is not None
    assert "CRÍTICO" in rendered
    assert "185.220.101.5" in rendered
    assert "srv-db" in rendered
    assert "Oct 16" not in rendered.split("Origen:")[1].split("\n")[0]


def test_render_soc_alert_html():
    alert = {
        "rule": {"id": "57102", "level": 12, "description": "SSH login exitoso como root (CRITICO)"},
        "agent": {"id": "001", "name": "manager-vm"},
        "data": {"srcip": "192.168.1.50", "dstuser": "root"},
        "timestamp": "2026-10-16 11:05:00",
    }
    html = templates.render_soc_alert_html(alert)
    assert "<html>" in html
    assert "CRÍTICO" in html
    assert "192.168.1.50" in html
    assert "root" in html
    assert "Acción SOC Recomendada" in html
