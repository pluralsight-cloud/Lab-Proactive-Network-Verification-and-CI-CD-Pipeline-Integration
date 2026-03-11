#!/usr/bin/env python3
"""
Genie Learn - Capture Baseline
Captures a comprehensive baseline of cloud routing tables,
interface states, and VPC configurations using simulated
pyATS/Genie learn operations against cloud router configs.
"""

import json
import os
import sys
import time
from datetime import datetime

def load_vpc_config(config_path):
    """Load VPC configuration from JSON file."""
    with open(config_path, 'r') as f:
        return json.load(f)

def learn_routing(configs_dir, output_dir):
    """Simulate genie learn routing operation across all VPCs."""
    print("=" * 65)
    print("Genie Learn - Capturing Baseline Routing State")
    print("=" * 65)
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Configs:   {configs_dir}")
    print(f"Output:    {output_dir}")
    print()

    os.makedirs(output_dir, exist_ok=True)

    baseline = {
        "capture_time": datetime.now().isoformat(),
        "devices": {}
    }

    vpc_files = [f for f in os.listdir(configs_dir) if f.startswith('vpc_') and f.endswith('.json')]

    for vpc_file in sorted(vpc_files):
        filepath = os.path.join(configs_dir, vpc_file)
        config = load_vpc_config(filepath)
        vpc_name = config.get('vpc_name', 'Unknown')
        vpc_id = config.get('vpc_id', 'Unknown')

        print(f"Learning from {vpc_name} ({vpc_id})...")
        time.sleep(0.5)

        # Extract routing info
        route_tables = config.get('route_tables', [])
        security_groups = config.get('security_groups', [])

        device_state = {
            "vpc_name": vpc_name,
            "vpc_id": vpc_id,
            "region": config.get('region', 'N/A'),
            "cidr_block": config.get('cidr_block', 'N/A'),
            "route_tables": [],
            "security_groups": [],
            "route_count": 0,
            "sg_rule_count": 0
        }

        for rt in route_tables:
            rt_entry = {
                "route_table_id": rt['route_table_id'],
                "name": rt['name'],
                "subnet_association": rt['subnet_association'],
                "routes": rt['routes']
            }
            device_state["route_tables"].append(rt_entry)
            device_state["route_count"] += len(rt['routes'])

        for sg in security_groups:
            sg_entry = {
                "group_id": sg['group_id'],
                "name": sg['name'],
                "inbound_rules": sg['inbound_rules'],
                "outbound_rules": sg['outbound_rules']
            }
            device_state["security_groups"].append(sg_entry)
            device_state["sg_rule_count"] += len(sg['inbound_rules']) + len(sg['outbound_rules'])

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

    # Print summary
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

    return baseline

if __name__ == "__main__":
    configs_dir = sys.argv[1] if len(sys.argv) > 1 else "configs"
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "results/baseline"
    learn_routing(configs_dir, output_dir)
