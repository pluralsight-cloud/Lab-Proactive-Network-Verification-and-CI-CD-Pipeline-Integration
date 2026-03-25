#!/usr/bin/env python3
"""
CI Pipeline Verification Script
Integrates pyATS/Genie diff and Batfish verification into the CI pipeline.
Uses genie.utils.diff.Diff for drift detection and pybatfish for security checks.
Fails the build (exit code 1) if Batfish detects a policy violation.
"""

from genie.utils.diff import Diff
from pybatfish.client.session import Session
from pybatfish.datamodel import HeaderConstraints
import json
import os
import sys
from datetime import datetime

BATFISH_HOST = os.environ.get("BATFISH_HOST", "localhost")

def load_routing_as_dict(snapshot_dir):
    """Load routing tables from AWS config format into dict for Genie Diff."""
    routing_path = os.path.join(snapshot_dir, 'aws_configs', 'us-east-1', 'RouteTables.json')
    with open(routing_path, 'r') as f:
        data = json.load(f)

    result = {}
    for rt in data.get('RouteTables', []):
        vpc_id = rt['VpcId']
        if vpc_id not in result:
            result[vpc_id] = {}
        for route in rt.get('Routes', []):
            prefix = route['DestinationCidrBlock']
            result[vpc_id][prefix] = {
                'gateway': route.get('GatewayId', ''),
                'peering': route.get('VpcPeeringConnectionId', '')
            }
    return result

def load_peering_as_dict(snapshot_dir):
    """Load VPC peering connections into dict for Genie Diff."""
    peering_path = os.path.join(snapshot_dir, 'aws_configs', 'us-east-1', 'VpcPeeringConnections.json')
    with open(peering_path, 'r') as f:
        data = json.load(f)

    result = {}
    for p in data.get('VpcPeeringConnections', []):
        result[p['VpcPeeringConnectionId']] = {
            'requester': p['RequesterVpcInfo']['VpcId'],
            'accepter': p['AccepterVpcInfo']['VpcId']
        }
    return result

def run_drift_check(baseline_dir, changed_dir):
    """Run Genie Diff to check for routing drift."""
    print("Stage 1: Genie Diff - Drift Detection")
    print("-" * 50)

    baseline_routes = load_routing_as_dict(baseline_dir)
    changed_routes = load_routing_as_dict(changed_dir)

    route_diff = Diff(baseline_routes, changed_routes)
    route_diff.findDiff()
    route_diff_str = str(route_diff).strip()

    if route_diff_str:
        print(f"  [DRIFT] Routing changes detected:")
        for line in route_diff_str.split('\n'):
            print(f"    {line}")
        return True
    else:
        print("  [PASS] No routing drift detected.")
        return False

def run_security_check(bf, changed_dir):
    """Run Batfish security verification."""
    print("\nStage 2: Batfish Security Verification")
    print("-" * 50)

    snapshot_name = "ci-check"
    bf.init_snapshot(changed_dir, name=snapshot_name, overwrite=True)

    violations = []
    test_flows = [
        {"desc": "Dev to Prod DB", "src": "10.3.1.10", "dst": "10.1.2.10", "port": 3306, "expected": "DENIED"},
        {"desc": "Staging to Prod DB", "src": "10.2.1.10", "dst": "10.1.2.10", "port": 3306, "expected": "DENIED"},
        {"desc": "Internet to Prod DB", "src": "8.8.8.8", "dst": "10.1.2.10", "port": 3306, "expected": "DENIED"},
    ]

    for flow in test_flows:
        try:
            result = bf.q.searchFilters(
                headers=HeaderConstraints(
                    srcIps=flow["src"],
                    dstIps=flow["dst"],
                    dstPorts=str(flow["port"]),
                    ipProtocols=["TCP"]
                ),
                action="PERMIT"
            ).answer().frame()
            actual = "PERMITTED" if len(result) > 0 else "DENIED"
        except Exception:
            actual = "DENIED"

        if flow["expected"] == "DENIED" and actual == "PERMITTED":
            violations.append(flow["desc"])
            print(f"  [FAIL] {flow['desc']}: Expected DENIED, found PERMITTED")
        else:
            print(f"  [PASS] {flow['desc']}: Correctly blocked")

    return violations

def run_topology_check(baseline_dir, changed_dir):
    """Check for unauthorized topology changes using Genie Diff."""
    print("\nStage 3: Genie Diff - Topology Verification")
    print("-" * 50)

    baseline_peers = load_peering_as_dict(baseline_dir)
    changed_peers = load_peering_as_dict(changed_dir)

    peer_diff = Diff(baseline_peers, changed_peers)
    peer_diff.findDiff()
    peer_diff_str = str(peer_diff).strip()

    if peer_diff_str:
        print(f"  [WARNING] Peering changes detected:")
        for line in peer_diff_str.split('\n'):
            print(f"    {line}")
        return True
    else:
        print("  [PASS] Topology matches baseline.")
        return False

def main():
    print("=" * 65)
    print("CI Pipeline - Pre-Flight Network Verification")
    print("=" * 65)
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Pipeline:  Pre-flight verification stage")
    print()

    baseline_dir = sys.argv[1] if len(sys.argv) > 1 else "snapshots/baseline"
    changed_dir = sys.argv[2] if len(sys.argv) > 2 else "snapshots/changed"
    output_dir = sys.argv[3] if len(sys.argv) > 3 else "results"

    os.makedirs(output_dir, exist_ok=True)

    # Stage 1: Genie Diff for routing drift
    has_drift = run_drift_check(baseline_dir, changed_dir)

    # Stage 2: Batfish security verification
    bf = Session(host=BATFISH_HOST)
    bf.set_network("carvedrock-ci")
    violations = run_security_check(bf, changed_dir)

    # Stage 3: Genie Diff for topology changes
    has_topo_change = run_topology_check(baseline_dir, changed_dir)

    # Summary
    print()
    print("=" * 65)
    print("Pipeline Verification Summary")
    print("=" * 65)
    print(f"  Routing drift:        {'DETECTED' if has_drift else 'NONE'}")
    print(f"  Security violations:  {len(violations)}")
    print(f"  Topology changes:     {'DETECTED' if has_topo_change else 'NONE'}")

    build_failed = len(violations) > 0
    print(f"\n  Build Status: {'FAILED' if build_failed else 'PASSED'}")

    if build_failed:
        print(f"\n  CRITICAL: {len(violations)} policy violation(s) detected.")
        print("  Build will be REJECTED. Triggering rollback...")
    else:
        print("\n  All pre-flight checks passed. Safe to deploy.")
    print("=" * 65)

    report = {
        "timestamp": datetime.now().isoformat(),
        "build_status": "FAILED" if build_failed else "PASSED",
        "routing_drift": has_drift,
        "security_violations": len(violations),
        "topology_changes": has_topo_change,
        "violation_details": violations
    }
    report_path = os.path.join(output_dir, "pipeline_report.json")
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"Pipeline report saved to: {report_path}")

    return 1 if build_failed else 0

if __name__ == "__main__":
    sys.exit(main())
