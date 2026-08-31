import re

with open('relay/wazuh_waha/api/dashboard.py', 'r') as f:
    content = f.read()

# Add logic to fetch overrides for rule groups
groups_logic = """
        # Rule Groups Overrides
        "wazuh_rule_groups": {
            "authentication_success": load_overrides().get("rule_group:authentication_success", True),
            "fim": load_overrides().get("rule_group:fim", True),
            "vulnerability_detector": load_overrides().get("rule_group:vulnerability_detector", True),
            "network_threats": load_overrides().get("rule_group:network_threats", True),
            "active_response": load_overrides().get("rule_group:active_response", True),
            "suid": load_overrides().get("rule_group:suid", True),
            "sca": load_overrides().get("rule_group:sca", True),
            "rootcheck": load_overrides().get("rule_group:rootcheck", True),
            "syscollector": load_overrides().get("rule_group:syscollector", True),
        }
    })
"""
content = content.replace('    })', groups_logic)

with open('relay/wazuh_waha/api/dashboard.py', 'w') as f:
    f.write(content)
