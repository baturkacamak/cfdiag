#!/bin/bash
# Pre-push hook to check if version matches latest tag
# This ensures version is updated when creating tags

set -e

# Get latest tag
LATEST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "")

if [ -z "$LATEST_TAG" ]; then
    # No tags exist, skip check
    exit 0
fi

# Extract version from tag (remove 'v' prefix)
TAG_VERSION=${LATEST_TAG#v}

# Get version from code
CODE_VERSION=$(grep -E '^VERSION = "' cfdiag/utils.py | sed 's/VERSION = "\(.*\)"/\1/' || echo "")

if [ -z "$CODE_VERSION" ]; then
    echo "Error: Could not find VERSION in cfdiag/utils.py"
    exit 1
fi

# Check if versions match
if [ "$TAG_VERSION" != "$CODE_VERSION" ]; then
    echo ""
    echo "⚠️  WARNING: Version mismatch detected!"
    echo "   Latest tag: $LATEST_TAG (version $TAG_VERSION)"
    echo "   Code version: $CODE_VERSION"
    echo ""
    echo "To fix this, run:"
    echo "   ./scripts/create_tag.sh $LATEST_TAG"
    echo ""
    echo "Or update VERSION in cfdiag/utils.py and setup.py to match the tag."
    echo ""
    
    # Don't fail, just warn (you can change this to exit 1 to make it fail)
    # exit 1
fi

exit 0
