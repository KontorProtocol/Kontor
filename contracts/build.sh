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

# Find all .wasm files, excluding *_opt.wasm
WASM_FILES=$(find "$TARGET_DIR" -type f -name "*.wasm" ! -name "*_opt.wasm" ! -name "*.br" -maxdepth 1)

# Check if any .wasm files were found
if [ -z "$WASM_FILES" ]; then
    echo "No .wasm files found in $TARGET_DIR"
    exit 0
fi

# Process each .wasm file
for WASM_FILE in $WASM_FILES; do
    echo "Processing $WASM_FILE"

    # Define output file for optimized WASM
    OPT_WASM_FILE="${WASM_FILE%.wasm}_opt.wasm"

    # Command 1: Run wasm-opt -Os, saving to new file
    if ! command -v wasm-opt >/dev/null 2>&1; then
        echo "Error: wasm-opt not found. Install it with 'cargo install wasm-opt' or via Binaryen."
        exit 1
    fi

    echo "Running wasm-opt -Oz on $WASM_FILE to $OPT_WASM_FILE"
    wasm-opt -Oz --enable-bulk-memory --enable-sign-ext "$WASM_FILE" -o "$OPT_WASM_FILE"
    if [ $? -ne 0 ]; then
        echo "Error: wasm-opt failed for $WASM_FILE"
        exit 1
    fi

    # Command 2: Run brotli -Z on optimized WASM to create .wasm.br
    if ! command -v brotli >/dev/null 2>&1; then
        echo "Error: brotli not found. Install it with 'brew install brotli' (macOS) or 'apt install brotli' (Ubuntu)."
        exit 1
    fi

    echo "Running brotli -Zf on $OPT_WASM_FILE"
    brotli -Zf "$OPT_WASM_FILE" -o "${WASM_FILE}.br"
    if [ $? -ne 0 ]; then
        echo "Error: brotli failed for $OPT_WASM_FILE"
        exit 1
    fi

    echo "Original WASM at $WASM_FILE, optimized to $OPT_WASM_FILE, compressed to ${WASM_FILE}.br"
done

echo "All .wasm files processed successfully"
