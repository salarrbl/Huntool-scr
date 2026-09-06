#!/bin/bash
# Build script for Ghostcat Go version

set -e

echo "Building Ghostcat Scanner (Go version)..."
echo ""

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "❌ Go is not installed. Please install Go 1.21+ first."
    echo ""
    echo "Installation instructions:"
    echo "  Ubuntu/Debian: sudo apt install golang-go"
    echo "  macOS: brew install go"
    echo "  Windows: Download from https://go.dev/dl/"
    echo ""
    echo "Or use the Python version: python3 ghostcat.py"
    exit 1
fi

# Get Go version
GO_VERSION=$(go version | awk '{print $3}')
echo "✓ Go version: $GO_VERSION"

# Navigate to Go directory
cd "$(dirname "$0")/ghostcat-go"

# Download dependencies (if any)
echo "✓ Downloading dependencies..."
go mod tidy

# Build the binary
echo "✓ Building ghostcat binary..."
go build -o ghostcat ./cmd/ghostcat

# Check if build succeeded
if [ -f "ghostcat" ]; then
    echo ""
    echo "✅ Build successful!"
    echo ""
    echo "Usage:"
    echo "  ./ghostcat targets.txt"
    echo "  ./ghostcat targets.txt -f vulns.txt -j vulns.json"
    echo ""
    echo "Binary location: $(pwd)/ghostcat"
    echo ""
    
    # Show file info
    ls -lh ghostcat
else
    echo "❌ Build failed!"
    exit 1
fi
