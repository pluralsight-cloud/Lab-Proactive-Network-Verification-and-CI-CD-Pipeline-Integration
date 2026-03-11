#!/usr/bin/env python3
"""
Batfish Network Verification
Initializes Batfish snapshots and executes queries to verify
cloud security rules and routing path resilience.
"""

import json
import os
import sys
from datetime import datetime

def load_snapshot(snapshot_dir):
    """Load snapshot data from directory."""
    topology_path = os.path.join(snapshot_dir, "topology.json")
    security_path = os.path.join(snapshot_dir, "security_policies.json")
    routing_path = os.path.join(snapshot_dir, "routing_tables.json")

    data = {}
    with open(topology_path, 'r') as f:
        data['topology'] = json.load(f)
    with open(security_path, 'r') as f:
        data['security'] = json.load(f)
    with open(routing_path, 'r') as f:
        data['routing'] = json.load(f)

    return data

def init_snapshot(snapshot_dir):
    """Initialize and display Batfish snapshot details."""
    print("=" * 65)
    print("Batfish Snapshot Initialization")
    print("=" * 65)
    print(f"Timestamp:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Snapshot Dir:  {snapshot_dir}")
    print()

    data = load_snapshot(snapshot_dir)
    topo = data['topology'].get('topology', {})

    print(f"Snapshot Name: {data['topology'].get('snapshot_name', 'N/A')}")
    print(f"Captured At:   {data['topology'].get('timestamp', 'N/A')}")
    print()

    nodes = topo.get('nodes', [])
    print(f"Network Nodes: {len(nodes)}")
    print("-" * 65)
    for node in nodes:
        azs = ', '.join(node.get('availability_zones', []))
        subnets = node.get('subnets', [])
        print(f"  {node['name']}")
        print(f"    CIDR:    {node['cidr']}")
        print(f"    AZs:     {azs}")
        print(f"    Subnets: {len(subnets)}")
        for s in subnets:
            print(f"      - {s['name']} ({s['cidr']}) in {s['az']}")

    peers = topo.get('peering_connections', [])
    print(f"\nPeering Connections: {len(peers)}")
    print("-" * 65)
    for p in peers:
        print(f"  {p['id']}: {p['requester']} <-> {p['accepter']} [{p['status']}]")

    policies = data['security'].get('security_policies', [])
    print(f"\nSecurity Policies: {len(policies)}")
    print("-" * 65)
    for pol in policies:
        print(f"  {pol['name']}: {pol['action']} {pol['source']} -> {pol['destination']} ({pol['protocol']}:{pol['port_range']})")

    print()
    print("=" * 65)
    print("Snapshot initialized successfully.")
    print("=" * 65)

    return data

def verify_security_rules(data, output_dir="results"):
    """Verify security rules block unauthorized traffic flows."""
    print()
    print("=" * 65)
    print("Batfish Security Verification")
    print("=" * 65)
    print("Checking security policies for unauthorized traffic flows...")
    print()

    policies = data['security'].get('security_policies', [])
    violations = []
    passes = []

    # Define expected deny rules
    expected_denies = [
        {"source": "10.3.0.0/16", "destination": "10.1.2.0/24", "port": "3306", "desc": "Dev to Prod DB"},
        {"source": "10.2.0.0/16", "destination": "10.1.2.0/24", "port": "3306", "desc": "Staging to Prod DB"},
        {"source": "0.0.0.0/0", "destination": "10.1.2.0/24", "port": "0-65535", "desc": "Internet to Prod DB"},
    ]

    for expected in expected_denies:
        found = False
        for pol in policies:
            if (pol['source'] == expected['source'] and
                pol['destination'] == expected['destination'] and
                expected['port'] in pol['port_range']):
                if pol['action'] == "DENY":
                    passes.append({
                        "check": f"Block {expected['desc']}",
                        "policy": pol['name'],
                        "status": "PASS",
                        "detail": f"{pol['action']} {pol['source']} -> {pol['destination']}"
                    })
                else:
                    violations.append({
                        "check": f"Block {expected['desc']}",
                        "policy": pol['name'],
                        "status": "FAIL",
                        "severity": "CRITICAL",
                        "detail": f"Expected DENY but found {pol['action']} for {pol['source']} -> {pol['destination']} port {pol['port_range']}"
                    })
                found = True
                break
        if not found:
            violations.append({
                "check": f"Block {expected['desc']}",
                "policy": "MISSING",
                "status": "FAIL",
                "severity": "HIGH",
                "detail": f"No policy found for {expected['source']} -> {expected['destination']}"
            })

    # Check that allowed rules exist
    expected_permits = [
        {"source": "10.1.1.0/24", "destination": "10.1.2.0/24", "desc": "Prod App to Prod DB"},
    ]

    for expected in expected_permits:
        for pol in policies:
            if (pol['source'] == expected['source'] and
                pol['destination'] == expected['destination']):
                if pol['action'] == "PERMIT":
                    passes.append({
                        "check": f"Allow {expected['desc']}",
                        "policy": pol['name'],
                        "status": "PASS",
                        "detail": f"{pol['action']} {pol['source']} -> {pol['destination']}"
                    })
                break

    # Display results
    print("Security Check Results:")
    print("-" * 65)

    for result in passes:
        print(f"  [PASS] {result['check']}")
        print(f"         Policy: {result['policy']}")
        print(f"         {result['detail']}")
        print()

    for result in violations:
        print(f"  [FAIL] {result['check']}")
        print(f"         Policy:   {result['policy']}")
        print(f"         Severity: {result['severity']}")
        print(f"         {result['detail']}")
        print()

    print("=" * 65)
    print(f"Results: {len(passes)} passed, {len(violations)} failed")

    if violations:
        print(f"\nCRITICAL: {len(violations)} security violation(s) detected.")
        print("Unauthorized traffic flows are permitted by current policies.")
    else:
        print("\nAll security rules correctly block unauthorized traffic.")

    print("=" * 65)

    # Save results
    os.makedirs(output_dir, exist_ok=True)
    report_path = os.path.join(output_dir, "security_verification.json")
    report = {
        "timestamp": datetime.now().isoformat(),
        "total_checks": len(passes) + len(violations),
        "passed": len(passes),
        "failed": len(violations),
        "passes": passes,
        "violations": violations
    }
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"Report saved to: {report_path}")

    return len(violations)

def analyze_routing_paths(data, output_dir="results"):
    """Analyze routing paths for zone failure resilience."""
    print()
    print("=" * 65)
    print("Batfish Routing Path Analysis - Zone Failure Resilience")
    print("=" * 65)
    print("Analyzing routing paths for single zone failure impact...")
    print()

    topo = data['topology'].get('topology', {})
    routing = data['routing'].get('routing_tables', {})
    nodes = topo.get('nodes', [])

    issues = []
    checks = []

    for node in nodes:
        vpc_name = node['name']
        azs = node.get('availability_zones', [])
        subnets = node.get('subnets', [])

        print(f"Analyzing {vpc_name}:")
        print(f"  Availability Zones: {', '.join(azs)}")
        print(f"  Subnets: {len(subnets)}")

        # Check multi-AZ coverage
        if len(azs) < 2:
            issues.append({
                "vpc": vpc_name,
                "severity": "WARNING",
                "issue": "Single availability zone deployment",
                "detail": f"{vpc_name} only uses {azs[0]}. A zone failure would disrupt all connectivity.",
                "recommendation": "Deploy subnets across at least 2 availability zones."
            })
            print(f"  [WARNING] Single AZ deployment - no zone redundancy")
        else:
            # Check if subnets span multiple AZs
            subnet_azs = set(s['az'] for s in subnets)
            if len(subnet_azs) >= 2:
                checks.append({
                    "vpc": vpc_name,
                    "status": "PASS",
                    "detail": f"Subnets span {len(subnet_azs)} availability zones"
                })
                print(f"  [PASS] Multi-AZ deployment across {', '.join(subnet_azs)}")
            else:
                issues.append({
                    "vpc": vpc_name,
                    "severity": "WARNING",
                    "issue": "Subnets not distributed across AZs",
                    "detail": f"All subnets in {vpc_name} reside in {subnet_azs.pop()}.",
                    "recommendation": "Distribute subnets across available AZs."
                })
                print(f"  [WARNING] Subnets not distributed across AZs")

        # Check peering redundancy
        vpc_routes = routing.get(vpc_name, {}).get('routes', [])
        peering_routes = [r for r in vpc_routes if r['next_hop'].startswith('pcx-')]
        if peering_routes:
            print(f"  Peering routes: {len(peering_routes)}")
            for route in peering_routes:
                print(f"    {route['prefix']} via {route['next_hop']}")
        print()

    print("=" * 65)
    print("Zone Failure Resilience Summary")
    print("-" * 65)
    print(f"  VPCs analyzed:     {len(nodes)}")
    print(f"  Checks passed:     {len(checks)}")
    print(f"  Issues found:      {len(issues)}")

    if issues:
        print()
        print("Issues Requiring Attention:")
        for i, issue in enumerate(issues, 1):
            print(f"  [{i}] {issue['vpc']}: {issue['issue']}")
            print(f"      {issue['detail']}")
            print(f"      Recommendation: {issue['recommendation']}")
            print()
    else:
        print("  No single zone failure can disrupt connectivity.")

    print("=" * 65)

    # Save analysis
    os.makedirs(output_dir, exist_ok=True)
    analysis_path = os.path.join(output_dir, "routing_analysis.json")
    analysis = {
        "timestamp": datetime.now().isoformat(),
        "vpcs_analyzed": len(nodes),
        "checks_passed": len(checks),
        "issues_found": len(issues),
        "checks": checks,
        "issues": issues
    }
    with open(analysis_path, 'w') as f:
        json.dump(analysis, f, indent=2)
    print(f"Analysis saved to: {analysis_path}")

    return len(issues)

if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "init"
    snapshot_dir = sys.argv[2] if len(sys.argv) > 2 else "snapshots/baseline"
    output_dir = sys.argv[3] if len(sys.argv) > 3 else "results"

    if action == "init":
        data = init_snapshot(snapshot_dir)
    elif action == "security":
        data = load_snapshot(snapshot_dir)
        violations = verify_security_rules(data, output_dir)
        sys.exit(1 if violations > 0 else 0)
    elif action == "routing":
        data = load_snapshot(snapshot_dir)
        issues = analyze_routing_paths(data, output_dir)
    elif action == "all":
        data = init_snapshot(snapshot_dir)
        violations = verify_security_rules(data, output_dir)
        issues = analyze_routing_paths(data, output_dir)
        sys.exit(1 if violations > 0 else 0)
    else:
        print(f"Usage: {sys.argv[0]} [init|security|routing|all] [snapshot_dir] [output_dir]")
        sys.exit(1)
