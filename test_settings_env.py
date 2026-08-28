#!/usr/bin/env python3
import sys
import os
from pathlib import Path

# Print environment variables that might be relevant
print("=== Environment Variables ===")
for key, value in sorted(os.environ.items()):
    if 'RELAY' in key or 'API_KEY' in key or 'WAZUH' in key or 'PYTHON' in key:
        print(f"{key}={value}")

print("\n=== Python Path ===")
print(f"sys.path[0:3]: {sys.path[:3]}")

# Add the relay directory to the path so we can import wazuh_waha modules
sys.path.insert(0, '/home/tadeo/Desktop/wazuh-waha/relay')
print(f"After adding relay path: {sys.path[0:3]}")

from wazuh_waha.config import settings, ENV_FILE

print(f"\n=== Settings Info ===")
print(f"ENV_FILE: {ENV_FILE}")
print(f"ENV_FILE exists: {ENV_FILE.exists()}")

if ENV_FILE.exists():
    with open(ENV_FILE, 'r') as f:
        content = f.read()
        for line in content.split('\n'):
            if 'RELAY_API_KEY' in line:
                print(f"RELAY_API_KEY line: {line}")

print(f"Settings relay_api_key: '{settings.relay_api_key}'")
print(f"Expected from .env: 'f7b6d3906106ef820179e853768b8db23cb119690030d103'")
print(f"Match: {settings.relay_api_key == 'f7b6d3906106ef820179e853768b8db23cb119690030d103'}")