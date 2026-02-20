#!/bin/bash
# Build the WASM module and generate Node.js bindings into wasm-out/.
# Usage: ./wbuild.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Build WASM binary
cargo build --manifest-path wasm/Cargo.toml --target wasm32-unknown-unknown --release

# Determine the exact wasm-bindgen version from Cargo.lock
WB_VERSION=$(sed -n '/^name = "wasm-bindgen"$/{n;s/^version = "\(.*\)"$/\1/p;}' wasm/Cargo.lock | head -1)

# Ensure matching wasm-bindgen CLI is available
WASM_BINDGEN="${CARGO_HOME:-$HOME/.cargo}/bin/wasm-bindgen"
NEED_INSTALL=0
if [ ! -x "$WASM_BINDGEN" ]; then
  NEED_INSTALL=1
elif [ "$("$WASM_BINDGEN" --version 2>/dev/null | awk '{print $2}')" != "$WB_VERSION" ]; then
  NEED_INSTALL=1
fi

if [ "$NEED_INSTALL" -eq 1 ]; then
  echo "Installing wasm-bindgen-cli $WB_VERSION..."
  cargo install wasm-bindgen-cli --version "$WB_VERSION" --force --quiet
fi

# Generate JS bindings
mkdir -p wasm-out
"$WASM_BINDGEN" \
  wasm/target/wasm32-unknown-unknown/release/rustsslcmd_wasm.wasm \
  --out-dir wasm-out \
  --target nodejs

echo "WASM built: wasm-out/"
