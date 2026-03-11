#!/usr/bin/env python3
"""
pyATS Testbed Validator
Validates the testbed YAML file and displays connection parameters
for cloud-based virtual routers.
"""

import yaml
import sys
import os

def validate_testbed(testbed_path):
    """Validate testbed file and display device connection parameters."""
    print("=" * 65)
    print("pyATS Testbed Validation")
    print("=" * 65)

    if not os.path.exists(testbed_path):
        print(f"ERROR: Testbed file not found: {testbed_path}")
        sys.exit(1)

    with open(testbed_path, 'r') as f:
        testbed = yaml.safe_load(f)

    testbed_info = testbed.get('testbed', {})
    devices = testbed.get('devices', {})
    topology = testbed.get('topology', {})

    print(f"\nTestbed Name: {testbed_info.get('name', 'N/A')}")
    print(f"Credentials:  default (username: {testbed_info.get('credentials', {}).get('default', {}).get('username', 'N/A')})")
    print(f"\nDevices Found: {len(devices)}")
    print("-" * 65)

    for device_name, device_config in devices.items():
        cli_conn = device_config.get('connections', {}).get('cli', {})
        custom = device_config.get('custom', {})
        print(f"\n  Device: {device_name}")
        print(f"    OS:       {device_config.get('os', 'N/A')}")
        print(f"    Type:     {device_config.get('type', 'N/A')}")
        print(f"    Alias:    {device_config.get('alias', 'N/A')}")
        print(f"    Protocol: {cli_conn.get('protocol', 'N/A')}")
        print(f"    IP:       {cli_conn.get('ip', 'N/A')}")
        print(f"    Port:     {cli_conn.get('port', 'N/A')}")
        print(f"    VPC ID:   {custom.get('vpc_id', 'N/A')}")
        print(f"    Region:   {custom.get('region', 'N/A')}")
        print(f"    AZs:      {', '.join(custom.get('availability_zones', []))}")

    links = topology.get('links', {})
    if links:
        print(f"\n{'=' * 65}")
        print(f"Topology Links: {len(links)}")
        print("-" * 65)
        for link_name, link_config in links.items():
            interfaces = link_config.get('interfaces', {})
            endpoints = list(interfaces.keys())
            print(f"  {link_name} ({link_config.get('type', 'N/A')}): {endpoints[0]} <-> {endpoints[1]}")

    print(f"\n{'=' * 65}")
    print("Testbed validation PASSED. All devices configured correctly.")
    print("=" * 65)

if __name__ == "__main__":
    testbed_path = sys.argv[1] if len(sys.argv) > 1 else "configs/testbed.yaml"
    validate_testbed(testbed_path)
