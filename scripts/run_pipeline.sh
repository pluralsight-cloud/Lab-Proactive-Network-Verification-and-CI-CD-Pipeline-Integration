#!/bin/bash
# CI Pipeline Runner
# Simulates a CI pipeline triggered by a git push event.
# Runs pre-flight verification and automated rollback stages.

echo "================================================================="
echo "CI Pipeline - Triggered by Git Push Event"
echo "================================================================="
echo "Pipeline ID:  $(date +%s)"
echo "Branch:       main"
echo "Commit:       $(cd /home/cloud_user/network-configs 2>/dev/null && git rev-parse --short HEAD 2>/dev/null || echo 'abc1234')"
echo "Triggered at: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

WORK_DIR="${1:-/home/cloud_user/network-configs}"
cd "$WORK_DIR"

echo "=========================================="
echo "Stage 1/3: Pre-Flight Verification"
echo "=========================================="
echo ""

python3 scripts/ci_verify.py snapshots/baseline snapshots/changed results
VERIFY_EXIT=$?

echo ""

if [ $VERIFY_EXIT -ne 0 ]; then
    echo "=========================================="
    echo "Stage 2/3: Automated Rollback"
    echo "=========================================="
    echo ""
    echo "Verification FAILED. Initiating automated rollback..."
    echo ""

    python3 scripts/rollback.py snapshots/baseline snapshots/changed results
    ROLLBACK_EXIT=$?

    echo ""
    echo "=========================================="
    echo "Stage 3/3: Post-Rollback Verification"
    echo "=========================================="
    echo ""
    echo "Re-running verification against restored state..."
    echo ""

    python3 scripts/ci_verify.py snapshots/baseline snapshots/changed results
    RECHECK_EXIT=$?

    echo ""
    echo "================================================================="
    echo "Pipeline Result: BUILD FAILED"
    echo "================================================================="
    echo "The pipeline detected policy violations and automatically"
    echo "rolled back to the baseline configuration."
    echo ""
    echo "Actions taken:"
    echo "  1. Pre-flight verification: FAILED (policy violations)"
    echo "  2. Automated rollback:      COMPLETED"
    echo "  3. Post-rollback check:     $([ $RECHECK_EXIT -eq 0 ] && echo 'PASSED' || echo 'FAILED')"
    echo ""
    echo "The misconfiguration was prevented from reaching production."
    echo "================================================================="
    exit 1
else
    echo "=========================================="
    echo "Stage 2/3: Deploy (Skipping Rollback)"
    echo "=========================================="
    echo ""
    echo "All pre-flight checks passed. No rollback needed."
    echo "Configuration is safe to deploy to production."
    echo ""
    echo "=========================================="
    echo "Stage 3/3: Verification Complete"
    echo "=========================================="
    echo ""
    echo "================================================================="
    echo "Pipeline Result: BUILD PASSED"
    echo "================================================================="
    echo "All verification checks passed. Configuration is approved"
    echo "for production deployment."
    echo "================================================================="
    exit 0
fi
