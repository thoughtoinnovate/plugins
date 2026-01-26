#!/bin/bash
# Build script for discord channel WASM plugin

set -e

echo "Building discord channel WASM plugin..."

rustup target add wasm32-wasip1 2>/dev/null || true

cargo build --target wasm32-wasip1 --release

mkdir -p dist
cp target/wasm32-wasip1/release/tark_plugin_discord_channel.wasm dist/plugin.wasm
cp plugin.toml dist/

echo ""
echo "Build complete!"
echo ""
echo "Plugin files in dist/:"
ls -la dist/
echo ""
echo "To install in tark:"
echo "  tark plugin add ./dist/"
