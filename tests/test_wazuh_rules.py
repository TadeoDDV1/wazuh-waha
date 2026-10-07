import xml.etree.ElementTree as ET
from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_local_rules_xml_validity():
    rules_path = REPO_ROOT / "manager-side" / "rules" / "local_rules.xml"
    assert rules_path.exists(), f"{rules_path} does not exist"

    tree = ET.parse(rules_path)
    root = tree.getroot()
    assert root.tag == "group"

    rules = {rule.attrib.get("id"): rule for rule in root.findall("rule")}

    # Critical authentication rules
    assert "57100" in rules, "Rule 57100 (SSH login) missing"
    assert int(rules["57100"].attrib.get("level", 0)) >= 8
    assert "57101" in rules, "Rule 57101 (SSH publickey) missing"
    assert "57102" in rules, "Rule 57102 (SSH root) missing"
    assert int(rules["57102"].attrib.get("level", 0)) >= 10
    assert "57103" in rules, "Rule 57103 (su) missing"
    assert "57104" in rules, "Rule 57104 (sudo) missing"

    # CVE rules elevation
    for cve_rule_id in ("57107", "57108", "57109", "57110"):
        assert cve_rule_id in rules, f"Rule {cve_rule_id} missing"
        assert int(rules[cve_rule_id].attrib.get("level", 0)) >= 8

    # Health rule
    assert "999001" in rules, "Rule 999001 (Health events) missing"
    health_rule = rules["999001"]
    assert int(health_rule.attrib.get("level", 0)) >= 8
    match_elem = health_rule.find("match")
    assert match_elem is not None
    assert "WAHA session" in match_elem.text
    assert "wazuh-agent" in match_elem.text
    assert "wazuh-waha" in match_elem.text


def test_ossec_conf_snippet_validity():
    snippet_path = REPO_ROOT / "manager-side" / "ossec.conf.snippet.xml"
    assert snippet_path.exists(), f"{snippet_path} does not exist"

    content = snippet_path.read_text(encoding="utf-8")
    wrapped = f"<root>{content}</root>"
    root = ET.fromstring(wrapped)

    integration = root.find("integration")
    assert integration is not None
    name = integration.find("name")
    assert name is not None and name.text == "custom-whatsapp"
    level = integration.find("level")
    assert level is not None and int(level.text) >= 8
    fmt = integration.find("alert_format")
    assert fmt is not None and fmt.text == "json"
    opts = integration.find("options")
    assert opts is not None and "whatsapp_alert.py" in opts.text


def test_vulnerability_detection_snippet_validity():
    snippet_path = REPO_ROOT / "manager-side" / "vulnerability-detection.snippet.xml"
    assert snippet_path.exists(), f"{snippet_path} does not exist"

    content = snippet_path.read_text(encoding="utf-8")
    wrapped = f"<root>{content}</root>"
    root = ET.fromstring(wrapped)
    assert root.find("vulnerability-detection") is not None
