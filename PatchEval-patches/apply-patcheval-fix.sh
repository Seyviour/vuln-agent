#!/bin/bash
# Apply PatchEval temporary file fix
#
# This script applies a necessary fix to PatchEval's Docker manager
# to prevent premature cleanup of temporary patch files.

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PATCHEVAL_DIR="$SCRIPT_DIR/../PatchEval"

echo "Applying PatchEval temporary file fix..."

if [ ! -d "$PATCHEVAL_DIR" ]; then
    echo "Error: PatchEval directory not found at $PATCHEVAL_DIR"
    exit 1
fi

cd "$PATCHEVAL_DIR"

# Check if patch is already applied
if git diff --quiet patcheval/evaluation/run_evaluation.py; then
    echo "Applying patch..."
    git apply "$SCRIPT_DIR/patcheval-tempfile-fix.patch"
    echo "✓ Patch applied successfully"
else
    echo "⚠ Changes already exist in run_evaluation.py"
    echo "  Checking if they match the expected patch..."

    # Generate current diff and compare
    CURRENT_DIFF=$(git diff patcheval/evaluation/run_evaluation.py)
    EXPECTED_DIFF=$(cat "$SCRIPT_DIR/patcheval-tempfile-fix.patch")

    if [ "$CURRENT_DIFF" = "$EXPECTED_DIFF" ]; then
        echo "✓ Patch already applied"
    else
        echo "✗ File has different modifications"
        echo "  You may need to manually review the changes"
        exit 1
    fi
fi

echo ""
echo "PatchEval is now ready for use with the multi-agent system."
