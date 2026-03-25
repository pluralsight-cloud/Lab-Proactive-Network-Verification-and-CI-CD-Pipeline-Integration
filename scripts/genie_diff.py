#!/usr/bin/env python3
"""
Genie Diff - Detect VPC Routing Drift
Uses genie.utils.diff.Diff to compare baseline and current routing state,
identifying unintended configuration changes across VPCs.
"""

from genie.utils.diff import Diff
import json
import os
import sys
from datetime import datetime

def load_routing_as_dict(snapshot_dir):
    """Load routing tables and convert to dict keyed by prefix for Genie Diff."""
    routing_path = os.path.join(snapshot_dir, 'aws_configs', 'us-east-1', 'RouteTables.json')
    with open(routing_path, 'r') as f:
        data = json.load(f)

    result = {}
    for rt in data.get('RouteTables', []):
        vpc_id = rt['VpcId']
        rt_id = rt['RouteTableId']
        if vpc_id not in result:
            result[vpc_id] = {}
        for route in rt.get('Routes', []):
            prefix = route['DestinationCidrBlock']
            result[vpc_id][prefix] = {
                'route_table': rt_id,
                'state': route.get('State', 'N/A'),
                'gateway': route.get('GatewayId', ''),
                'peering': route.get('VpcPeeringConnectionId', '')
            }
    return result

def load_peering_as_dict(snapshot_dir):
    """Load VPC peering connections as dict keyed by peering ID."""
    peering_path = os.path.join(snapshot_dir, 'aws_configs', 'us-east-1', 'VpcPeeringConnections.json')
    with open(peering_path, 'r') as f:
        data = json.load(f)

    result = {}
    for p in data.get('VpcPeeringConnections', []):
        pid = p['VpcPeeringConnectionId']
        result[pid] = {
            'requester': p['RequesterVpcInfo']['VpcId'],
            'accepter': p['AccepterVpcInfo']['VpcId'],
            'status': p['Status']['Code']
        }
    return result

def main(baseline_dir, changed_dir, output_dir="results"):
    print("=" * 65)
    print("Genie Diff - VPC Routing Drift Detection")
    print("=" * 65)
    print(f"Timestamp:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Baseline:     {baseline_dir}")
    print(f"Current:      {changed_dir}")
    print()

    # Load and diff routing tables using Genie Diff
    print("Comparing routing tables using Genie Diff...")
    baseline_routes = load_routing_as_dict(baseline_dir)
    changed_routes = load_routing_as_dict(changed_dir)

    route_diff = Diff(baseline_routes, changed_routes)
    route_diff.findDiff()
    route_diff_str = str(route_diff)

    # Load and diff peering connections using Genie Diff
    print("Comparing peering connections using Genie Diff...")
    baseline_peering = load_peering_as_dict(baseline_dir)
    changed_peering = load_peering_as_dict(changed_dir)

    peering_diff = Diff(baseline_peering, changed_peering)
    peering_diff.findDiff()
    peering_diff_str = str(peering_diff)

    print()
    print("=" * 65)
    print("Diff Results")
    print("=" * 65)

    has_route_diff = bool(route_diff_str.strip())
    has_peering_diff = bool(peering_diff_str.strip())

    if not has_route_diff and not has_peering_diff:
        print("No differences detected. Configurations match baseline.")
    else:
        if has_route_diff:
            print("\nRouting Table Changes (Genie Diff output):")
            print("-" * 65)
            print(route_diff_str)

        if has_peering_diff:
            print("\nPeering Connection Changes (Genie Diff output):")
            print("-" * 65)
            print(peering_diff_str)

    # Save diff results
    os.makedirs(output_dir, exist_ok=True)
    diff_path = os.path.join(output_dir, "drift_report.json")
    report = {
        "timestamp": datetime.now().isoformat(),
        "baseline_snapshot": baseline_dir,
        "current_snapshot": changed_dir,
        "has_routing_drift": has_route_diff,
        "has_peering_drift": has_peering_diff,
        "routing_diff": route_diff_str,
        "peering_diff": peering_diff_str
    }
    with open(diff_path, 'w') as f:
        json.dump(report, f, indent=2)

    print("-" * 65)
    print(f"Drift report saved to: {diff_path}")

    if has_route_diff or has_peering_diff:
        print(f"\nWARNING: Configuration drift detected.")
        print("Review the drift report and take corrective action.")
    else:
        print("\nNo drift detected. Environment matches baseline.")

    print("=" * 65)
    return 1 if (has_route_diff or has_peering_diff) else 0

if __name__ == "__main__":
    baseline = sys.argv[1] if len(sys.argv) > 1 else "snapshots/baseline"
    changed = sys.argv[2] if len(sys.argv) > 2 else "snapshots/changed"
    output = sys.argv[3] if len(sys.argv) > 3 else "results"
    exit_code = main(baseline, changed, output)
    sys.exit(exit_code)
