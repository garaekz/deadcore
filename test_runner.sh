#!/bin/bash

set -euo pipefail

TEMP_DIR="./temp_test_outputs"
DEFAULT_MANIFEST="fixtures/minimal.manifest.json"

mkdir -p "$TEMP_DIR"

MANIFEST="${1:-$DEFAULT_MANIFEST}"

if [[ ! -f "$MANIFEST" ]]; then
    echo "Manifest file not found: $MANIFEST"
    exit 1
fi

echo "Testing with: $MANIFEST"
echo "Output dir: $TEMP_DIR"

echo "Building oxinfer..."
cargo build --locked

echo "Running analysis..."
./target/debug/oxinfer --manifest "$MANIFEST" > "$TEMP_DIR/output.json"

echo ""
echo "RESULTS"
echo "======="

CONTROLLERS=$(jq -r '.controllers | length' "$TEMP_DIR/output.json")
MODELS=$(jq -r '.models | length' "$TEMP_DIR/output.json")
POLYMORPHIC=$(jq -r '.polymorphic | length' "$TEMP_DIR/output.json")
BROADCAST=$(jq -r '.broadcast | length' "$TEMP_DIR/output.json")

echo "Controllers: $CONTROLLERS"
echo "Models: $MODELS"
echo "Polymorphic: $POLYMORPHIC"
echo "Broadcast: $BROADCAST"
echo ""
echo "Full output saved to: $TEMP_DIR/output.json"
