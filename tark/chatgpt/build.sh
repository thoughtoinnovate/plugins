#!/bin/bash
# Build script for chatgpt-oauth WASM plugin

set -e

echo "Building chatgpt-oauth plugin..."

# Check for wasm32 target
if ! rustup target list --installed | grep -q "wasm32-unknown-unknown"; then
    echo "Installing wasm32-unknown-unknown target..."
    rustup target add wasm32-unknown-unknown
fi

# Build in release mode
cargo build --target wasm32-unknown-unknown --release

# Create dist directory
mkdir -p dist

# Copy artifacts
cp target/wasm32-unknown-unknown/release/chatgpt_oauth.wasm dist/plugin.wasm
cp plugin.toml dist/

# Optimize WASM if wasm-opt is available
if command -v wasm-opt &> /dev/null; then
    echo "Optimizing WASM with wasm-opt..."
    wasm-opt -Os dist/plugin.wasm -o dist/plugin.wasm
fi

# Show size
echo ""
echo "Build complete!"
ls -lh dist/
echo ""
echo "To install:"
echo "  mkdir -p ~/.config/tark/plugins/chatgpt-oauth"
echo "  cp dist/* ~/.config/tark/plugins/chatgpt-oauth/"
echo "  tark plugin enable chatgpt-oauth"
