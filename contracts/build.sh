#!/bin/bash
set -e

cargo build --release

# Hardcoded target directory
TARGET_DIR="target/wasm32-unknown-unknown/release"

# Check if directory exists
if [ ! -d "$TARGET_DIR" ]; then
    echo "Error: Directory $TARGET_DIR does not exist"
    exit 1
fi

# Find all .wasm files
WASM_FILES=$(find "$TARGET_DIR" -type f -name "*.wasm" ! -name "*.br" -maxdepth 1)

# Check if any .wasm files were found
if [ -z "$WASM_FILES" ]; then
    echo "No .wasm files found in $TARGET_DIR"
    exit 0
fi

# Process each .wasm file
for WASM_FILE in $WASM_FILES; do
    echo "Processing $WASM_FILE"

    # Command 1: Run wasm-opt -Os, overwriting the original file
    if ! command -v wasm-opt >/dev/null 2>&1; then
        echo "Error: wasm-opt not found. Install it with 'cargo install wasm-opt' or via Binaryen."
        exit 1
    fi

    echo "Running wasm-opt -Os on $WASM_FILE"
    wasm-opt -Os "$WASM_FILE" -o "$WASM_FILE" --enable-bulk-memory-opt
    if [ $? -ne 0 ]; then
        echo "Error: wasm-opt failed for $WASM_FILE"
        exit 1
    fi

    # Command 2: Run brotli -Z to create .wasm.br
    if ! command -v brotli >/dev/null 2>&1; then
        echo "Error: brotli not found. Install it with 'brew install brotli' (macOS) or 'apt install brotli' (Ubuntu)."
        exit 1
    fi

    echo "Running brotli -Z on $WASM_FILE"
    brotli -Zf "$WASM_FILE"
    if [ $? -ne 0 ]; then
        echo "Error: brotli failed for $WASM_FILE"
        exit 1
    fi

    echo "Optimized WASM binary at $WASM_FILE, compressed to ${WASM_FILE}.br"
done

echo "All .wasm files processed successfully"
