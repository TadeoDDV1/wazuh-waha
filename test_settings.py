#!/usr/bin/env python3
import sys
import os
from pathlib import Path

# Add the relay directory to the path so we can import wazuh_waha modules
sys.path.insert(0, '/home/tadeo/Desktop/wazuh-waha/relay')

from wazuh_waha.config import settings, ENV_FILE

print(f"ENV_FILE: {ENV_FILE}")
print(f"ENV_FILE exists: {ENV_FILE.exists()}")

if ENV_FILE.exists():
    with open(ENV_FILE, 'r') as f:
        content = f.read()
        print(f"ENV_FILE content:")
        print(content)
        print("---")
        for line in content.split('\n'):
            if 'RELAY_API_KEY' in line:
                print(f"RELAY_API_KEY line: {line}")

print(f"Settings relay_api_key: '{settings.relay_api_key}'")
print(f"Expected from .env: 'f7b6d3906106ef820179e853768b8db23cb119690030d103'")
print(f"Match: {settings.relay_api_key == 'f7b6d3906106ef820179e853768b8db23cb119690030d103'}")