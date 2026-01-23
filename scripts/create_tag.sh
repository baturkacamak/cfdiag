#!/bin/bash
# Script to create a git tag and automatically update VERSION in code
# Usage: ./scripts/create_tag.sh v3.12.5 "Release message"

set -e

if [ $# -lt 1 ] || [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    echo "Usage: $0 <tag> [message]"
    echo "Example: $0 v3.12.5 'Release message'"
    echo ""
    echo "This script will:"
    echo "  1. Update VERSION in cfdiag/utils.py and setup.py"
    echo "  2. Create a commit with version update"
    echo "  3. Create the git tag"
    exit 0
fi

TAG=$1
MESSAGE=${2:-"Release $TAG"}

# Extract version number (remove 'v' prefix if present)
VERSION=${TAG#v}

# Check if tag already exists
if git rev-parse "$TAG" >/dev/null 2>&1; then
    echo "Error: Tag $TAG already exists"
    exit 1
fi

# Files that contain VERSION
VERSION_FILES=(
    "cfdiag/utils.py"
    "setup.py"
)

echo "Updating VERSION to $VERSION in code files..."

# Update VERSION in each file
for file in "${VERSION_FILES[@]}"; do
    if [ -f "$file" ]; then
        # Update VERSION = "x.x.x" pattern
        if [[ "$OSTYPE" == "darwin"* ]]; then
            # macOS
            sed -i '' "s/VERSION = \"[0-9]\+\.[0-9]\+\.[0-9]\+\"/VERSION = \"$VERSION\"/g" "$file"
        else
            # Linux
            sed -i "s/VERSION = \"[0-9]\+\.[0-9]\+\.[0-9]\+\"/VERSION = \"$VERSION\"/g" "$file"
        fi
        echo "  ✓ Updated $file"
    else
        echo "  ⚠ Warning: $file not found"
    fi
done

# Stage version files
git add "${VERSION_FILES[@]}"

# Check if there are changes
if git diff --cached --quiet; then
    echo "No version changes detected. Version might already be $VERSION"
else
    echo "Creating commit for version update..."
    git commit -m "chore: Bump version to $VERSION" --no-verify
fi

# Create the tag
echo "Creating tag $TAG..."
git tag -a "$TAG" -m "$MESSAGE"

echo ""
echo "✓ Tag $TAG created successfully!"
echo "✓ Version updated to $VERSION in code"
echo ""
echo "To push:"
echo "  git push origin main"
echo "  git push origin $TAG"
echo ""
echo "Or push everything:"
echo "  git push origin main --tags"
