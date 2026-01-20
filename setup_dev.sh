#!/bin/bash
# Setup Development Environment

echo "Setting up git hooks..."
cp scripts/run_tests.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit

echo "✅ Pre-commit hook installed."
echo "   Tests will now run automatically before every commit."
