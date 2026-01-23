#!/bin/bash
# Run tests locally the same way GitHub Actions does
# This helps catch issues before pushing

set -e

echo "🧪 Running tests (GitHub Actions style)..."
echo ""

# Use the same command as GitHub Actions
python3 tests/test_cfdiag.py

echo ""
echo "✅ All tests passed!"
