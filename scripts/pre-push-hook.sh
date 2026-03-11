#!/bin/bash
# Git pre-push hook
# Triggers CI pipeline verification before allowing push
# This simulates a CI runner triggered on git push events

echo "================================================================="
echo "Git Pre-Push Hook - Triggering CI Pipeline Verification"
echo "================================================================="
echo ""

REPO_ROOT="$(git rev-parse --show-toplevel)"

# Run the CI verification pipeline
bash "$REPO_ROOT/scripts/run_pipeline.sh" "$REPO_ROOT"
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo "Push REJECTED: Pre-flight verification failed."
    echo "Fix the configuration issues and try again."
    exit 1
else
    echo ""
    echo "Push APPROVED: All verification checks passed."
    exit 0
fi
