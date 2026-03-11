#!/usr/bin/env python3
"""
Genie Diff - Detect VPC Routing Drift
Compares baseline and current routing state to identify
unintended configuration changes across VPCs.
"""

import json
import os
import sys
from datetime import datetime

def load_snapshot(snapshot_dir):
    """Load routing table snapshot from JSON."""
    routing_path = os.path.join(snapshot_dir, "routing_tables.json")
    topology_path = os.path.join(snapshot_dir, "topology.json")

    with open(routing_path, 'r') as f:
        routing = json.load(f)
    with open(topology_path, 'r') as f:
        topology = json.load(f)

    return routing, topology

def diff_routing_tables(baseline_routing, changed_routing):
    """Compare routing tables between baseline and changed state."""
    diffs = []

    baseline_tables = baseline_routing.get('routing_tables', {})
    changed_tables = changed_routing.get('routing_tables', {})

    all_vpcs = set(list(baseline_tables.keys()) + list(changed_tables.keys()))

    for vpc in sorted(all_vpcs):
        baseline_routes = {r['prefix']: r for r in baseline_tables.get(vpc, {}).get('routes', [])}
        changed_routes = {r['prefix']: r for r in changed_tables.get(vpc, {}).get('routes', [])}

        # Check for added routes
        for prefix in changed_routes:
            if prefix not in baseline_routes:
                diffs.append({
                    "type": "ADDED",
                    "vpc": vpc,
                    "prefix": prefix,
                    "details": changed_routes[prefix]
                })

        # Check for removed routes
        for prefix in baseline_routes:
            if prefix not in changed_routes:
                diffs.append({
                    "type": "REMOVED",
                    "vpc": vpc,
                    "prefix": prefix,
                    "details": baseline_routes[prefix]
                })

        # Check for modified routes
        for prefix in baseline_routes:
            if prefix in changed_routes:
                if baseline_routes[prefix] != changed_routes[prefix]:
                    diffs.append({
                        "type": "MODIFIED",
                        "vpc": vpc,
                        "prefix": prefix,
                        "baseline": baseline_routes[prefix],
                        "current": changed_routes[prefix]
                    })

    return diffs

def diff_topology(baseline_topo, changed_topo):
    """Compare topology between baseline and changed state."""
    diffs = []

    baseline_peers = {p['id']: p for p in baseline_topo.get('topology', {}).get('peering_connections', [])}
    changed_peers = {p['id']: p for p in changed_topo.get('topology', {}).get('peering_connections', [])}

    for peer_id in changed_peers:
        if peer_id not in baseline_peers:
            p = changed_peers[peer_id]
            diffs.append({
                "type": "ADDED_PEERING",
                "peering_id": peer_id,
                "requester": p['requester'],
                "accepter": p['accepter']
            })

    for peer_id in baseline_peers:
        if peer_id not in changed_peers:
            p = baseline_peers[peer_id]
            diffs.append({
                "type": "REMOVED_PEERING",
                "peering_id": peer_id,
                "requester": p['requester'],
                "accepter": p['accepter']
            })

    return diffs

def main(baseline_dir, changed_dir, output_dir="results"):
    print("=" * 65)
    print("Genie Diff - VPC Routing Drift Detection")
    print("=" * 65)
    print(f"Timestamp:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Baseline:     {baseline_dir}")
    print(f"Current:      {changed_dir}")
    print()

    baseline_routing, baseline_topo = load_snapshot(baseline_dir)
    changed_routing, changed_topo = load_snapshot(changed_dir)

    print("Comparing routing tables...")
    route_diffs = diff_routing_tables(baseline_routing, changed_routing)

    print("Comparing topology...")
    topo_diffs = diff_topology(baseline_topo, changed_topo)

    all_diffs = route_diffs + topo_diffs

    print()
    print("=" * 65)
    print("Diff Results")
    print("=" * 65)

    if not all_diffs:
        print("No differences detected. Configurations match baseline.")
    else:
        print(f"Total differences found: {len(all_diffs)}")
        print()

        for i, diff in enumerate(all_diffs, 1):
            diff_type = diff['type']

            if diff_type == "ADDED":
                print(f"  [{i}] ROUTE ADDED in {diff['vpc']}")
                print(f"      Prefix:   {diff['prefix']}")
                print(f"      Next Hop: {diff['details']['next_hop']}")
                print(f"      Protocol: {diff['details']['protocol']}")
                print(f"      Metric:   {diff['details']['metric']}")
                print()

            elif diff_type == "REMOVED":
                print(f"  [{i}] ROUTE REMOVED from {diff['vpc']}")
                print(f"      Prefix:   {diff['prefix']}")
                print(f"      Next Hop: {diff['details']['next_hop']}")
                print()

            elif diff_type == "MODIFIED":
                print(f"  [{i}] ROUTE MODIFIED in {diff['vpc']}")
                print(f"      Prefix:   {diff['prefix']}")
                print(f"      Baseline: next_hop={diff['baseline']['next_hop']}, metric={diff['baseline']['metric']}")
                print(f"      Current:  next_hop={diff['current']['next_hop']}, metric={diff['current']['metric']}")
                print()

            elif diff_type == "ADDED_PEERING":
                print(f"  [{i}] PEERING CONNECTION ADDED")
                print(f"      Peering ID: {diff['peering_id']}")
                print(f"      Requester:  {diff['requester']}")
                print(f"      Accepter:   {diff['accepter']}")
                print()

            elif diff_type == "REMOVED_PEERING":
                print(f"  [{i}] PEERING CONNECTION REMOVED")
                print(f"      Peering ID: {diff['peering_id']}")
                print(f"      Requester:  {diff['requester']}")
                print(f"      Accepter:   {diff['accepter']}")
                print()

    # Save diff results
    os.makedirs(output_dir, exist_ok=True)
    diff_path = os.path.join(output_dir, "drift_report.json")
    diff_report = {
        "timestamp": datetime.now().isoformat(),
        "baseline_snapshot": baseline_dir,
        "current_snapshot": changed_dir,
        "total_differences": len(all_diffs),
        "route_changes": len(route_diffs),
        "topology_changes": len(topo_diffs),
        "differences": all_diffs
    }

    with open(diff_path, 'w') as f:
        json.dump(diff_report, f, indent=2)

    print("-" * 65)
    print(f"Drift report saved to: {diff_path}")

    if all_diffs:
        print(f"\nWARNING: {len(all_diffs)} unintended change(s) detected.")
        print("Review the drift report and take corrective action.")
    else:
        print("\nNo drift detected. Environment matches baseline.")

    print("=" * 65)
    return len(all_diffs)

if __name__ == "__main__":
    baseline = sys.argv[1] if len(sys.argv) > 1 else "snapshots/baseline"
    changed = sys.argv[2] if len(sys.argv) > 2 else "snapshots/changed"
    output = sys.argv[3] if len(sys.argv) > 3 else "results"
    exit_code = main(baseline, changed, output)
    sys.exit(1 if exit_code > 0 else 0)
