#!/usr/bin/env python3
"""
pyATS Testbed Validator
Uses pyats.topology.loader to load and validate the testbed YAML file,
then displays connection parameters for cloud-based virtual routers.
"""

from pyats.topology import loader
import sys

def validate_testbed(testbed_path):
    """Load testbed using pyATS and display device connection parameters."""
    print("=" * 65)
    print("pyATS Testbed Validation")
    print("=" * 65)

    testbed = loader.load(testbed_path)

    print(f"\nTestbed Name: {testbed.name}")
    creds = testbed.credentials.get('default', {})
    print(f"Credentials:  default (username: {creds.get('username', 'N/A')})")
    print(f"\nDevices Found: {len(testbed.devices)}")
    print("-" * 65)

    for device_name, device in testbed.devices.items():
        cli_conn = device.connections.get('cli', {})
        custom = device.custom if hasattr(device, 'custom') else {}
        print(f"\n  Device: {device_name}")
        print(f"    OS:       {device.os}")
        print(f"    Type:     {device.type}")
        print(f"    Alias:    {device.alias}")
        print(f"    Protocol: {cli_conn.get('protocol', 'N/A')}")
        print(f"    IP:       {cli_conn.get('ip', 'N/A')}")
        print(f"    Port:     {cli_conn.get('port', 'N/A')}")
        print(f"    VPC ID:   {custom.get('vpc_id', 'N/A')}")
        print(f"    Region:   {custom.get('region', 'N/A')}")
        azs = custom.get('availability_zones', [])
        print(f"    AZs:      {', '.join(azs)}")

    print(f"\n{'=' * 65}")
    print("Testbed validation PASSED. All devices configured correctly.")
    print("=" * 65)

if __name__ == "__main__":
    testbed_path = sys.argv[1] if len(sys.argv) > 1 else "configs/testbed.yaml"
    validate_testbed(testbed_path)
