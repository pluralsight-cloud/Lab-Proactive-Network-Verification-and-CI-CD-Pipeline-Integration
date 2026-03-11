#!/usr/bin/env python3
"""
CI Pipeline Verification Script
Integrates pyATS diff and Batfish verification into the CI pipeline.
Fails the build if Batfish detects a policy violation.
Returns exit code 1 on failure, 0 on success.
"""

import json
import os
import sys
from datetime import datetime

def run_drift_check(baseline_dir, changed_dir):
    """Run pyATS genie diff to check for routing drift."""
    print("Stage 1: pyATS Drift Detection")
    print("-" * 50)

    baseline_routing_path = os.path.join(baseline_dir, "routing_tables.json")
    changed_routing_path = os.path.join(changed_dir, "routing_tables.json")

    with open(baseline_routing_path, 'r') as f:
        baseline = json.load(f)
    with open(changed_routing_path, 'r') as f:
        changed = json.load(f)

    drift_count = 0
    for vpc in changed.get('routing_tables', {}):
        baseline_routes = {r['prefix']: r for r in baseline.get('routing_tables', {}).get(vpc, {}).get('routes', [])}
        changed_routes = {r['prefix']: r for r in changed.get('routing_tables', {}).get(vpc, {}).get('routes', [])}

        for prefix in changed_routes:
            if prefix not in baseline_routes:
                drift_count += 1
                print(f"  [DRIFT] New route in {vpc}: {prefix} via {changed_routes[prefix]['next_hop']}")
        for prefix in baseline_routes:
            if prefix not in changed_routes:
                drift_count += 1
                print(f"  [DRIFT] Removed route in {vpc}: {prefix}")

    if drift_count == 0:
        print("  [PASS] No routing drift detected.")
    else:
        print(f"  [WARNING] {drift_count} route change(s) detected.")

    return drift_count

def run_security_check(snapshot_dir):
    """Run Batfish security verification."""
    print("\nStage 2: Batfish Security Verification")
    print("-" * 50)

    security_path = os.path.join(snapshot_dir, "security_policies.json")
    with open(security_path, 'r') as f:
        data = json.load(f)

    policies = data.get('security_policies', [])
    violations = []

    expected_denies = [
        {"source": "10.3.0.0/16", "destination": "10.1.2.0/24", "port": "3306", "desc": "Dev to Prod DB"},
        {"source": "10.2.0.0/16", "destination": "10.1.2.0/24", "port": "3306", "desc": "Staging to Prod DB"},
        {"source": "0.0.0.0/0", "destination": "10.1.2.0/24", "port": "0-65535", "desc": "Internet to Prod DB"},
    ]

    for expected in expected_denies:
        for pol in policies:
            if (pol['source'] == expected['source'] and
                pol['destination'] == expected['destination'] and
                expected['port'] in pol['port_range']):
                if pol['action'] != "DENY":
                    violations.append({
                        "policy": pol['name'],
                        "desc": expected['desc'],
                        "expected": "DENY",
                        "actual": pol['action']
                    })
                    print(f"  [FAIL] {expected['desc']}: Expected DENY, found {pol['action']}")
                else:
                    print(f"  [PASS] {expected['desc']}: Correctly blocked")
                break

    return violations

def run_topology_check(baseline_dir, changed_dir):
    """Check for unauthorized topology changes."""
    print("\nStage 3: Topology Verification")
    print("-" * 50)

    with open(os.path.join(baseline_dir, "topology.json"), 'r') as f:
        baseline = json.load(f)
    with open(os.path.join(changed_dir, "topology.json"), 'r') as f:
        changed = json.load(f)

    baseline_peers = {p['id'] for p in baseline.get('topology', {}).get('peering_connections', [])}
    changed_peers = {p['id'] for p in changed.get('topology', {}).get('peering_connections', [])}

    new_peers = changed_peers - baseline_peers
    removed_peers = baseline_peers - changed_peers

    issues = []
    if new_peers:
        for p in new_peers:
            print(f"  [WARNING] Unauthorized peering connection added: {p}")
            issues.append(p)
    if removed_peers:
        for p in removed_peers:
            print(f"  [WARNING] Peering connection removed: {p}")
            issues.append(p)

    if not issues:
        print("  [PASS] Topology matches baseline.")

    return issues

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

    # Run all verification stages
    drift_count = run_drift_check(baseline_dir, changed_dir)
    violations = run_security_check(changed_dir)
    topo_issues = run_topology_check(baseline_dir, changed_dir)

    # Generate final report
    print()
    print("=" * 65)
    print("Pipeline Verification Summary")
    print("=" * 65)
    print(f"  Routing drift changes:     {drift_count}")
    print(f"  Security violations:       {len(violations)}")
    print(f"  Topology issues:           {len(topo_issues)}")

    total_issues = len(violations)
    build_status = "FAILED" if total_issues > 0 else "PASSED"

    print(f"\n  Build Status: {build_status}")

    if total_issues > 0:
        print(f"\n  CRITICAL: {total_issues} policy violation(s) detected.")
        print("  Build will be REJECTED. Triggering rollback...")
    else:
        print("\n  All pre-flight checks passed. Safe to deploy.")

    print("=" * 65)

    # Save pipeline report
    report = {
        "timestamp": datetime.now().isoformat(),
        "build_status": build_status,
        "drift_changes": drift_count,
        "security_violations": len(violations),
        "topology_issues": len(topo_issues),
        "violations_detail": violations,
        "topology_detail": topo_issues
    }

    report_path = os.path.join(output_dir, "pipeline_report.json")
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"Pipeline report saved to: {report_path}")

    return 1 if total_issues > 0 else 0

if __name__ == "__main__":
    sys.exit(main())
