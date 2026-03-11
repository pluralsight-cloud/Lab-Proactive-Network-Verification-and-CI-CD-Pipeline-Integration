#!/usr/bin/env python3
"""
Automated Rollback Script
Restores the baseline cloud state when verification fails.
Copies baseline snapshot files over changed configurations
and generates a rollback confirmation report.
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

    # Record what will be rolled back
    rolled_back_files = []

    print("Rolling back configuration files:")
    print("-" * 65)

    for filename in os.listdir(baseline_dir):
        src = os.path.join(baseline_dir, filename)
        dst = os.path.join(changed_dir, filename)

        if os.path.isfile(src):
            # Check if file differs
            if os.path.exists(dst):
                with open(src, 'r') as f:
                    src_content = f.read()
                with open(dst, 'r') as f:
                    dst_content = f.read()

                if src_content != dst_content:
                    shutil.copy2(src, dst)
                    rolled_back_files.append(filename)
                    print(f"  [RESTORED] {filename}")
                else:
                    print(f"  [UNCHANGED] {filename} (already matches baseline)")
            else:
                shutil.copy2(src, dst)
                rolled_back_files.append(filename)
                print(f"  [RESTORED] {filename}")

    print()
    print("=" * 65)
    print("Rollback Summary")
    print("-" * 65)
    print(f"  Files restored:    {len(rolled_back_files)}")
    print(f"  Baseline source:   {baseline_dir}")
    print(f"  Rollback target:   {changed_dir}")

    if rolled_back_files:
        print(f"\n  Restored files:")
        for f in rolled_back_files:
            print(f"    - {f}")
    else:
        print(f"\n  No files needed rollback. State already matches baseline.")

    print()
    print("Rollback COMPLETE. Environment restored to baseline state.")
    print("=" * 65)

    # Save rollback report
    os.makedirs(output_dir, exist_ok=True)
    report_path = os.path.join(output_dir, "rollback_report.json")
    report = {
        "timestamp": datetime.now().isoformat(),
        "status": "COMPLETED",
        "files_restored": rolled_back_files,
        "total_restored": len(rolled_back_files),
        "baseline_source": baseline_dir,
        "rollback_target": changed_dir
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
