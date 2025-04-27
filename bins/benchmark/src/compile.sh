#!/bin/bash

# Create output directory if it doesn't exist
OUTPUT_DIR=".."

# Compile all .c files
for file in *.c; do
    if [ -f "$file" ]; then
        gcc "$file" -o "$OUTPUT_DIR/${file%.c}" || { echo "Failed to compile $file"; exit 1; }
    fi
done

# Compile all .cpp files
for file in *.cpp; do
    if [ -f "$file" ]; then
        g++ "$file" -o "$OUTPUT_DIR/${file%.cpp}" || { echo "Failed to compile $file"; exit 1; }
    fi
done

echo "Compilation completed. Outputs are in $OUTPUT_DIR"