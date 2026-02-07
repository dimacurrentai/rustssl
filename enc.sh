#!/bin/bash
# Encrypt a file with AES-256-CBC, PBKDF2, base64.
# Usage: enc.sh <input_file> <output_file> [password]
# If password is omitted, it is read from the terminal.

set -e

if [ $# -lt 2 ]; then
  echo "Usage: $0 <input_file> <output_file> [password]" >&2
  echo "  If password is omitted, you will be prompted for it." >&2
  exit 1
fi

INPUT="$1"
OUTPUT="$2"
PASS="$3"

if [ ! -f "$INPUT" ]; then
  echo "Error: input file does not exist: $INPUT" >&2
  exit 1
fi

if [ -n "$PASS" ]; then
  openssl aes-256-cbc -pbkdf2 -a -salt -in "$INPUT" -out "$OUTPUT" -pass "pass:$PASS"
else
  openssl aes-256-cbc -pbkdf2 -a -salt -in "$INPUT" -out "$OUTPUT"
fi

echo "Encrypted: $INPUT -> $OUTPUT"
