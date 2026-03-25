#!/usr/bin/env python3
"""
Genie Learn - Capture Baseline
Uses pyats.topology.loader to load the testbed and captures a comprehensive
baseline of cloud routing tables from exported AWS VPC configurations.
"""

from pyats.topology import loader
import json
import os
import sys
from datetime import datetime

def learn_routing(testbed_path, configs_dir, output_dir):
    """Load testbed with pyATS and capture routing baseline from VPC configs."""
    print("=" * 65)
    print("Genie Learn - Capturing Baseline Routing State")
    print("=" * 65)
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Testbed:   {testbed_path}")
    print(f"Configs:   {configs_dir}")
    print(f"Output:    {output_dir}")
    print()

    # Load testbed using pyATS
    testbed = loader.load(testbed_path)
    os.makedirs(output_dir, exist_ok=True)

    baseline = {
        "capture_time": datetime.now().isoformat(),
        "testbed": testbed.name,
        "devices": {}
    }

    vpc_files = [f for f in os.listdir(configs_dir)
                 if f.startswith('vpc_') and f.endswith('.json')]

    for vpc_file in sorted(vpc_files):
        filepath = os.path.join(configs_dir, vpc_file)
        with open(filepath, 'r') as f:
            config = json.load(f)

        vpc_name = config.get('vpc_name', 'Unknown')
        vpc_id = config.get('vpc_id', 'Unknown')

        # Match VPC to testbed device
        matched_device = None
        for dev_name, dev in testbed.devices.items():
            if hasattr(dev, 'custom') and dev.custom.get('vpc_id') == vpc_id:
                matched_device = dev_name
                break

        print(f"Learning from {vpc_name} ({vpc_id})...")
        if matched_device:
            print(f"  Matched testbed device: {matched_device}")

        route_tables = config.get('route_tables', [])
        security_groups = config.get('security_groups', [])

        device_state = {
            "vpc_name": vpc_name,
            "vpc_id": vpc_id,
            "testbed_device": matched_device,
            "region": config.get('region', 'N/A'),
            "cidr_block": config.get('cidr_block', 'N/A'),
            "route_tables": route_tables,
            "security_groups": security_groups,
            "route_count": sum(len(rt.get('routes', [])) for rt in route_tables),
            "sg_rule_count": sum(
                len(sg.get('inbound_rules', [])) + len(sg.get('outbound_rules', []))
                for sg in security_groups
            )
        }

        baseline["devices"][vpc_id] = device_state
        print(f"  Route tables: {len(route_tables)}")
        print(f"  Total routes: {device_state['route_count']}")
        print(f"  Security groups: {len(security_groups)}")
        print(f"  Total SG rules: {device_state['sg_rule_count']}")
        print()

    # Save baseline
    baseline_path = os.path.join(output_dir, "baseline_routing.json")
    with open(baseline_path, 'w') as f:
        json.dump(baseline, f, indent=2)

    total_routes = sum(d['route_count'] for d in baseline['devices'].values())
    total_rules = sum(d['sg_rule_count'] for d in baseline['devices'].values())

    print("=" * 65)
    print("Baseline Capture Summary")
    print("-" * 65)
    print(f"  Devices captured:     {len(baseline['devices'])}")
    print(f"  Total route tables:   {sum(len(d['route_tables']) for d in baseline['devices'].values())}")
    print(f"  Total routes:         {total_routes}")
    print(f"  Total security groups:{sum(len(d['security_groups']) for d in baseline['devices'].values())}")
    print(f"  Total SG rules:       {total_rules}")
    print(f"  Baseline saved to:    {baseline_path}")
    print("=" * 65)
    print("Baseline capture COMPLETE.")

if __name__ == "__main__":
    testbed_path = sys.argv[1] if len(sys.argv) > 1 else "configs/testbed.yaml"
    configs_dir = sys.argv[2] if len(sys.argv) > 2 else "configs"
    output_dir = sys.argv[3] if len(sys.argv) > 3 else "results/baseline"
    learn_routing(testbed_path, configs_dir, output_dir)
