#!/bin/bash
# Setup Development Environment

set -e

echo "🔧 Setting up development environment..."

# Setup git hooks
echo ""
echo "📝 Setting up git hooks..."

# Pre-commit hook (tests)
if [ -f "scripts/run_tests.sh" ]; then
    cp scripts/run_tests.sh .git/hooks/pre-commit
    chmod +x .git/hooks/pre-commit
    echo "   ✅ Pre-commit hook installed (runs tests before commit)"
else
    echo "   ⚠️  scripts/run_tests.sh not found"
fi

# Pre-push hook (version check)
if [ -f ".git/hooks/pre-push" ]; then
    chmod +x .git/hooks/pre-push
    echo "   ✅ Pre-push hook installed (checks version consistency)"
else
    echo "   ⚠️  .git/hooks/pre-push not found (creating...)"
    # Create pre-push hook if it doesn't exist
    cat > .git/hooks/pre-push << 'HOOK_EOF'
#!/bin/bash
# Pre-push hook to check version consistency

LATEST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "")
if [ -z "$LATEST_TAG" ]; then
    exit 0
fi

TAG_VERSION=${LATEST_TAG#v}
CODE_VERSION=$(grep -E '^VERSION = "' cfdiag/utils.py 2>/dev/null | sed 's/VERSION = "\(.*\)"/\1/' || echo "")

if [ -z "$CODE_VERSION" ]; then
    echo "Error: Could not find VERSION in cfdiag/utils.py"
    exit 1
fi

if [ "$TAG_VERSION" != "$CODE_VERSION" ]; then
    echo ""
    echo "⚠️  WARNING: Version mismatch detected!"
    echo "   Latest tag: $LATEST_TAG (version $TAG_VERSION)"
    echo "   Code version: $CODE_VERSION"
    echo ""
    echo "To fix this, run:"
    echo "   ./scripts/create_tag.sh $LATEST_TAG"
    echo ""
    read -p "Continue push anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

exit 0
HOOK_EOF
    chmod +x .git/hooks/pre-push
    echo "   ✅ Pre-push hook created"
fi

# Make scripts executable
echo ""
echo "🔨 Making scripts executable..."
if [ -f "scripts/create_tag.sh" ]; then
    chmod +x scripts/create_tag.sh
    echo "   ✅ scripts/create_tag.sh"
else
    echo "   ⚠️  scripts/create_tag.sh not found"
fi

if [ -f "scripts/check_version_tag.sh" ]; then
    chmod +x scripts/check_version_tag.sh
    echo "   ✅ scripts/check_version_tag.sh"
else
    echo "   ⚠️  scripts/check_version_tag.sh not found"
fi

if [ -f "scripts/run_tests.sh" ]; then
    chmod +x scripts/run_tests.sh
    echo "   ✅ scripts/run_tests.sh"
else
    echo "   ⚠️  scripts/run_tests.sh not found"
fi

echo ""
echo "✨ Development environment setup complete!"
echo ""
echo "📚 Quick reference:"
echo "   • Create release tag: ./scripts/create_tag.sh v3.12.6 'Message'"
echo "   • Check version: ./scripts/check_version_tag.sh"
echo "   • Tests run automatically before commit"
echo "   • Version check runs automatically before push"
echo ""
