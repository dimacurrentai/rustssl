#!/bin/bash
# Cross-check all encrypt/decrypt combinations (OpenSSL vs Rust).
# Tests: enc.sh, dec.sh, renc.sh, rdec.sh with multiple inputs.
# Usage: ./crosscheck.sh [password]
# Default password: crosscheck (override with first arg).

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

PASS="${1:-crosscheck}"
TMP="${TMPDIR:-/tmp}/openssl-crosscheck-$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT

# Ensure Rust binary exists
if [ ! -x "target/debug/rustsslcmd" ] && [ ! -x "target/release/rustsslcmd" ]; then
  echo "Error: Rust binary not found. Run: cargo build" >&2
  exit 1
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
pass_count=0
fail_count=0

run_test() {
  local enc_cmd="$1"
  local dec_cmd="$2"
  local enc_name="$3"
  local dec_name="$4"
  local plain="$5"
  local label="$6"

  local enc_out="$TMP/enc-$enc_name-$dec_name-$label.enc"
  local dec_out="$TMP/dec-$enc_name-$dec_name-$label.out"

  if $enc_cmd "$plain" "$enc_out" "$PASS" >/dev/null 2>&1 && \
     $dec_cmd "$enc_out" "$dec_out" "$PASS" >/dev/null 2>&1 && \
     diff -q "$plain" "$dec_out" >/dev/null 2>&1; then
    echo -e "  ${GREEN}PASS${NC} $enc_name -> $dec_name ($label)"
    ((pass_count++)) || true
    return 0
  else
    echo -e "  ${RED}FAIL${NC} $enc_name -> $dec_name ($label)"
    ((fail_count++)) || true
    return 1
  fi
}

echo "=============================================="
echo " OpenSSL / Rust encrypt-decrypt cross-check"
echo "=============================================="
echo "Password: (set via first argument; default: crosscheck)"
echo "Temp dir: $TMP"
echo ""

# --- Create test files ---
echo "Creating test files..."

# Small text
echo -n "hello world" > "$TMP/small.txt"

# Longer text (multi-line, spaces)
cat > "$TMP/medium.txt" << 'EOF'
The quick brown fox jumps over the lazy dog.
Line two with some symbols: !@#$%^&*()
EOF

# Larger file (so ciphertext is multiple blocks)
python3 -c "
s = 'x' * 4096
with open('$TMP/large.txt', 'w') as f:
    f.write(s)
" 2>/dev/null || (printf '%4096s' '' | tr ' ' 'x' > "$TMP/large.txt")

# Large payloads: 1 MiB and 10 MiB (pattern-filled for speed)
create_large() {
  local path="$1"
  local size_mb="$2"
  python3 -c "
with open('$path', 'wb') as f:
    f.write((b'x' * 4096) * (256 * $size_mb))
" 2>/dev/null && return 0
  dd if=/dev/zero bs=1048576 count="$size_mb" 2>/dev/null | tr '\0' 'x' > "$path" 2>/dev/null
}
create_large "$TMP/large1m.bin" 1
create_large "$TMP/large10m.bin" 10

# Binary (nulls and high bytes)
printf '\\0\\1\\2\\xff\\xfe\\xfd\\0\\0\\0' > "$TMP/binary.bin"

# Empty file
touch "$TMP/empty.txt"

# One block exactly (16 bytes)
printf '0123456789abcdef' > "$TMP/oneblock.txt"

FILES=("$TMP/small.txt" "$TMP/medium.txt" "$TMP/large.txt" "$TMP/binary.bin" "$TMP/empty.txt" "$TMP/oneblock.txt" "$TMP/large1m.bin" "$TMP/large10m.bin")
LABELS=("small" "medium" "large" "binary" "empty" "oneblock" "large1m" "large10m")

echo "Test files: small, medium, large, binary, empty, oneblock, large1m (1 MiB), large10m (10 MiB)"
echo ""

# --- Encryptors and decryptors ---
ENC_OPENSSL="./enc.sh"
DEC_OPENSSL="./dec.sh"
ENC_RUST="./renc.sh"
DEC_RUST="./rdec.sh"

# --- Matrix: each encryptor x each decryptor x representative files ---
echo "----------------------------------------------"
echo " Matrix: encrypt with X, decrypt with Y"
echo "----------------------------------------------"

for ei in "OPENSSL:$ENC_OPENSSL" "RUST:$ENC_RUST"; do
  enc_name="${ei%%:*}"
  enc_cmd="${ei#*:}"
  for di in "OPENSSL:$DEC_OPENSSL" "RUST:$DEC_RUST"; do
    dec_name="${di%%:*}"
    dec_cmd="${di#*:}"
    echo ""
    echo "[ $enc_name enc -> $dec_name dec ]"
    for i in "${!FILES[@]}"; do
      run_test "$enc_cmd" "$dec_cmd" "$enc_name" "$dec_name" "${FILES[$i]}" "${LABELS[$i]}"
    done
  done
done

echo ""
echo "----------------------------------------------"
echo " Summary"
echo "----------------------------------------------"
echo -e "  ${GREEN}Passed: $pass_count${NC}"
echo -e "  ${RED}Failed: $fail_count${NC}"
echo ""

if [ "$fail_count" -gt 0 ]; then
  exit 1
fi
echo -e "${GREEN}All cross-checks passed.${NC}"
exit 0
