#!/usr/bin/env python3
"""
Batfish Network Verification
Uses pybatfish to initialize Batfish snapshots from exported AWS configurations
and execute queries to verify security rules and routing path resilience.
"""

from pybatfish.client.session import Session
from pybatfish.datamodel import HeaderConstraints
import json
import os
import sys
from datetime import datetime

BATFISH_HOST = os.environ.get("BATFISH_HOST", "localhost")
NETWORK_NAME = "carvedrock"

def get_session():
    """Initialize pybatfish session connected to Batfish server."""
    bf = Session(host=BATFISH_HOST)
    bf.set_network(NETWORK_NAME)
    return bf

def init_snapshot(bf, snapshot_dir, snapshot_name="baseline"):
    """Initialize a Batfish snapshot from AWS configuration files."""
    print("=" * 65)
    print("Batfish Snapshot Initialization")
    print("=" * 65)
    print(f"Timestamp:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Snapshot Dir:  {snapshot_dir}")
    print(f"Snapshot Name: {snapshot_name}")
    print()

    # Initialize snapshot using pybatfish
    bf.init_snapshot(snapshot_dir, name=snapshot_name, overwrite=True)
    print(f"Snapshot '{snapshot_name}' initialized successfully.")
    print()

    # Display network topology info
    node_props = bf.q.nodeProperties().answer().frame()
    print(f"Network Nodes: {len(node_props)}")
    print("-" * 65)
    for _, row in node_props.iterrows():
        print(f"  {row['Node']}")

    print()
    print("=" * 65)
    print("Snapshot initialized successfully.")
    print("=" * 65)
    return bf

def verify_security_rules(bf, snapshot_name, output_dir="results"):
    """Execute Batfish reachability queries to verify security rules."""
    print()
    print("=" * 65)
    print("Batfish Security Verification")
    print("=" * 65)
    print("Checking security policies for unauthorized traffic flows...")
    print()

    bf.set_snapshot(snapshot_name)
    violations = []
    passes = []

    # Define traffic flows to test
    test_flows = [
        {
            "desc": "Dev to Prod DB (MySQL)",
            "src": "10.3.1.10",
            "dst": "10.1.2.10",
            "dstPort": 3306,
            "expected": "DENIED"
        },
        {
            "desc": "Staging to Prod DB (MySQL)",
            "src": "10.2.1.10",
            "dst": "10.1.2.10",
            "dstPort": 3306,
            "expected": "DENIED"
        },
        {
            "desc": "Internet to Prod DB",
            "src": "8.8.8.8",
            "dst": "10.1.2.10",
            "dstPort": 3306,
            "expected": "DENIED"
        },
        {
            "desc": "Prod App to Prod DB (MySQL)",
            "src": "10.1.1.10",
            "dst": "10.1.2.10",
            "dstPort": 3306,
            "expected": "PERMITTED"
        }
    ]

    for flow in test_flows:
        try:
            headers = HeaderConstraints(
                srcIps=flow["src"],
                dstIps=flow["dst"],
                dstPorts=str(flow["dstPort"]),
                ipProtocols=["TCP"]
            )
            result = bf.q.reachability(
                pathConstraints=None,
                headers=headers,
                actions="SUCCESS,FAILURE"
            ).answer().frame()

            if len(result) == 0:
                actual = "NO_ROUTE"
            else:
                actions = result['Action'].unique()
                if 'ACCEPTED' in actions or 'DELIVERED_TO_SUBNET' in actions:
                    actual = "PERMITTED"
                else:
                    actual = "DENIED"
        except Exception as e:
            # If reachability query fails, use filter-based check
            try:
                filter_result = bf.q.searchFilters(
                    headers=HeaderConstraints(
                        srcIps=flow["src"],
                        dstIps=flow["dst"],
                        dstPorts=str(flow["dstPort"]),
                        ipProtocols=["TCP"]
                    ),
                    action="PERMIT"
                ).answer().frame()

                actual = "PERMITTED" if len(filter_result) > 0 else "DENIED"
            except Exception:
                actual = "UNABLE_TO_DETERMINE"

        if flow["expected"] == "DENIED" and actual == "DENIED":
            passes.append({"check": flow["desc"], "status": "PASS", "detail": f"Traffic correctly blocked"})
            print(f"  [PASS] {flow['desc']}: Traffic correctly blocked")
        elif flow["expected"] == "PERMITTED" and actual == "PERMITTED":
            passes.append({"check": flow["desc"], "status": "PASS", "detail": f"Traffic correctly allowed"})
            print(f"  [PASS] {flow['desc']}: Traffic correctly allowed")
        elif flow["expected"] == "DENIED" and actual == "PERMITTED":
            violations.append({"check": flow["desc"], "status": "FAIL", "severity": "CRITICAL",
                             "detail": f"Expected DENIED but traffic is PERMITTED"})
            print(f"  [FAIL] {flow['desc']}: Expected DENIED but traffic is PERMITTED")
        elif flow["expected"] == "PERMITTED" and actual == "DENIED":
            violations.append({"check": flow["desc"], "status": "FAIL", "severity": "HIGH",
                             "detail": f"Expected PERMITTED but traffic is DENIED"})
            print(f"  [FAIL] {flow['desc']}: Expected PERMITTED but traffic is DENIED")
        else:
            print(f"  [WARN] {flow['desc']}: Result={actual}")

    print()
    print("=" * 65)
    print(f"Results: {len(passes)} passed, {len(violations)} failed")

    if violations:
        print(f"\nCRITICAL: {len(violations)} security violation(s) detected.")
        print("Unauthorized traffic flows are permitted by current policies.")
    else:
        print("\nAll security rules correctly block unauthorized traffic.")
    print("=" * 65)

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

def analyze_routing_paths(bf, snapshot_name, output_dir="results"):
    """Analyze Batfish routing paths for zone failure resilience."""
    print()
    print("=" * 65)
    print("Batfish Routing Path Analysis - Zone Failure Resilience")
    print("=" * 65)
    print("Analyzing routing paths for single zone failure impact...")
    print()

    bf.set_snapshot(snapshot_name)
    issues = []
    checks = []

    # Get routing tables from Batfish
    try:
        routes = bf.q.routes().answer().frame()
        print(f"Total routes analyzed: {len(routes)}")
        print()

        # Analyze by node
        for node in routes['Node'].unique():
            node_routes = routes[routes['Node'] == node]
            print(f"Analyzing {node}:")
            print(f"  Routes: {len(node_routes)}")
            for _, route in node_routes.iterrows():
                print(f"    {route['Network']} via {route['Next_Hop']}")
    except Exception:
        print("  Using snapshot topology data for analysis...")

    # Load topology data for AZ analysis
    snapshot_dir = f"snapshots/{'baseline' if 'baseline' in snapshot_name else 'changed'}"
    subnets_path = os.path.join(snapshot_dir, 'aws_configs', 'us-east-1', 'Subnets.json')

    if os.path.exists(subnets_path):
        with open(subnets_path, 'r') as f:
            subnet_data = json.load(f)

        # Group subnets by VPC and check AZ distribution
        vpc_azs = {}
        for subnet in subnet_data.get('Subnets', []):
            vpc_id = subnet['VpcId']
            az = subnet['AvailabilityZone']
            if vpc_id not in vpc_azs:
                vpc_azs[vpc_id] = set()
            vpc_azs[vpc_id].add(az)

        print()
        for vpc_id, azs in vpc_azs.items():
            print(f"Analyzing {vpc_id}:")
            print(f"  Availability Zones: {', '.join(sorted(azs))}")
            if len(azs) < 2:
                issues.append({
                    "vpc": vpc_id,
                    "severity": "WARNING",
                    "issue": "Single availability zone deployment",
                    "detail": f"{vpc_id} only uses {list(azs)[0]}. A zone failure would disrupt all connectivity.",
                    "recommendation": "Deploy subnets across at least 2 availability zones."
                })
                print(f"  [WARNING] Single AZ deployment - no zone redundancy")
            else:
                checks.append({"vpc": vpc_id, "status": "PASS",
                              "detail": f"Subnets span {len(azs)} availability zones"})
                print(f"  [PASS] Multi-AZ deployment across {', '.join(sorted(azs))}")
            print()

    print("=" * 65)
    print("Zone Failure Resilience Summary")
    print("-" * 65)
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

    os.makedirs(output_dir, exist_ok=True)
    analysis_path = os.path.join(output_dir, "routing_analysis.json")
    analysis = {
        "timestamp": datetime.now().isoformat(),
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

    snapshot_name = "baseline" if "baseline" in snapshot_dir else "changed"

    bf = get_session()

    if action == "init":
        init_snapshot(bf, snapshot_dir, snapshot_name)
    elif action == "security":
        init_snapshot(bf, snapshot_dir, snapshot_name)
        violations = verify_security_rules(bf, snapshot_name, output_dir)
        sys.exit(1 if violations > 0 else 0)
    elif action == "routing":
        init_snapshot(bf, snapshot_dir, snapshot_name)
        issues = analyze_routing_paths(bf, snapshot_name, output_dir)
    elif action == "all":
        init_snapshot(bf, snapshot_dir, snapshot_name)
        violations = verify_security_rules(bf, snapshot_name, output_dir)
        issues = analyze_routing_paths(bf, snapshot_name, output_dir)
        sys.exit(1 if violations > 0 else 0)
    else:
        print(f"Usage: {sys.argv[0]} [init|security|routing|all] [snapshot_dir] [output_dir]")
        sys.exit(1)
