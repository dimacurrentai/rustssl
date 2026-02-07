#!/bin/bash
# Encrypt a file with AES-256-CBC, PBKDF2, base64 (Rust implementation).
# Usage: renc.sh <input_file> <output_file> [password]
# If password is omitted, it is read from the terminal.
# Compatible with enc.sh; output can be decrypted with dec.sh or rdec.sh.

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

DIR="$(cd "$(dirname "$0")" && pwd)"
BIN="$DIR/target/release/rustsslcmd"
[ -x "$BIN" ] || BIN="$DIR/target/debug/rustsslcmd"
if [ ! -x "$BIN" ]; then
  echo "Error: Rust binary not found. Run: cargo build" >&2
  exit 1
fi

if [ -n "$PASS" ]; then
  "$BIN" enc "$INPUT" "$OUTPUT" "$PASS"
else
  "$BIN" enc "$INPUT" "$OUTPUT"
fi
