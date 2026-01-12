#!/bin/bash
# Build script for gemini-auth WASM plugin

set -e

echo "Building gemini-auth WASM plugin..."

# Ensure wasm target is installed
rustup target add wasm32-wasip1 2>/dev/null || true

# Build the plugin
cargo build --target wasm32-wasip1 --release

# Copy artifacts to dist folder
mkdir -p dist
cp target/wasm32-wasip1/release/tark_plugin_gemini_auth_wasm.wasm dist/plugin.wasm
cp plugin.toml dist/

echo ""
echo "Build complete!"
echo ""
echo "Plugin files in dist/:"
ls -la dist/
echo ""
echo "To install in tark:"
echo "  tark plugin add ./dist/"
