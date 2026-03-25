#!/usr/bin/env python3
"""
Automated Rollback Script
Restores the baseline cloud state when verification fails.
Copies baseline AWS config files over changed configurations.
"""

import json
import os
import shutil
import sys
from datetime import datetime

def rollback_to_baseline(baseline_dir, changed_dir, output_dir="results"):
    """Restore baseline state by overwriting changed configs."""
    print("=" * 65)
    print("Automated Rollback - Restoring Baseline State")
    print("=" * 65)
    print(f"Timestamp:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Baseline:     {baseline_dir}")
    print(f"Target:       {changed_dir}")
    print()

    if not os.path.exists(baseline_dir):
        print(f"ERROR: Baseline directory not found: {baseline_dir}")
        sys.exit(1)

    rolled_back_files = []

    print("Rolling back configuration files:")
    print("-" * 65)

    for root, dirs, files in os.walk(baseline_dir):
        for filename in files:
            src = os.path.join(root, filename)
            rel_path = os.path.relpath(src, baseline_dir)
            dst = os.path.join(changed_dir, rel_path)

            os.makedirs(os.path.dirname(dst), exist_ok=True)
            if os.path.exists(dst):
                with open(src, 'r') as f:
                    src_content = f.read()
                with open(dst, 'r') as f:
                    dst_content = f.read()

                if src_content != dst_content:
                    shutil.copy2(src, dst)
                    rolled_back_files.append(rel_path)
                    print(f"  [RESTORED] {rel_path}")
                else:
                    print(f"  [UNCHANGED] {rel_path}")
            else:
                shutil.copy2(src, dst)
                rolled_back_files.append(rel_path)
                print(f"  [RESTORED] {rel_path}")

    print()
    print("=" * 65)
    print("Rollback Summary")
    print("-" * 65)
    print(f"  Files restored:    {len(rolled_back_files)}")

    if rolled_back_files:
        print(f"\n  Restored files:")
        for f in rolled_back_files:
            print(f"    - {f}")
    else:
        print(f"\n  No files needed rollback. State already matches baseline.")

    print()
    print("Rollback COMPLETE. Environment restored to baseline state.")
    print("=" * 65)

    os.makedirs(output_dir, exist_ok=True)
    report_path = os.path.join(output_dir, "rollback_report.json")
    report = {
        "timestamp": datetime.now().isoformat(),
        "status": "COMPLETED",
        "files_restored": rolled_back_files,
        "total_restored": len(rolled_back_files)
    }
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"Rollback report saved to: {report_path}")
    return 0

if __name__ == "__main__":
    baseline = sys.argv[1] if len(sys.argv) > 1 else "snapshots/baseline"
    changed = sys.argv[2] if len(sys.argv) > 2 else "snapshots/changed"
    output = sys.argv[3] if len(sys.argv) > 3 else "results"
    sys.exit(rollback_to_baseline(baseline, changed, output))
