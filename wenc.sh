#!/bin/bash
# Encrypt a file with AES-256-CBC, PBKDF2, base64 (WASM implementation).
# Usage: wenc.sh <input_file> <output_file> [password]
# If password is omitted, it is read from the terminal.
# Compatible with enc.sh; output can be decrypted with dec.sh, rdec.sh, or wdec.sh.

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

if [ ! -f "$DIR/wasm-out/rustsslcmd_wasm.js" ]; then
  echo "Error: WASM not built. Run ./wbuild.sh first." >&2
  exit 1
fi

if [ -n "$PASS" ]; then
  node "$DIR/wasm/cli.js" enc "$INPUT" "$OUTPUT" "$PASS"
else
  node "$DIR/wasm/cli.js" enc "$INPUT" "$OUTPUT"
fi
