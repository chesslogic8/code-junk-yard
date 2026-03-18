#!/bin/bash

OUT="all.txt"
rm -f "$OUT"

echo "AIX8 PROJECT SOURCE DUMP" >> "$OUT"
echo "========================" >> "$OUT"
echo "" >> "$OUT"

dump () {
if [ -f "$1" ]; then
echo "" >> "$OUT"
echo "==================================" >> "$OUT"
echo "FILE: $1" >> "$OUT"
echo "==================================" >> "$OUT"
cat "$1" >> "$OUT"
echo "" >> "$OUT"
fi
}

# Core project files

dump Cargo.toml

# Source

dump src/lib.rs
dump src/main.rs
dump src/bin/aix8.rs

# Tests

dump tests/integration_tests.rs

echo "Done. Output written to all.txt"
