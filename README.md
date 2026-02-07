# OpenSSL-compatible AES-256-CBC encrypt/decrypt

Encrypt and decrypt files in the same format as `openssl enc -aes-256-cbc -pbkdf2 -a -salt`. You can use the OpenSSL CLI, the shell scripts that wrap it, or a **pure Rust** implementation; ciphertext is interchangeable.

**Format:** `Salted__` (8 bytes) + 8-byte salt + AES-256-CBC ciphertext, base64-encoded. Key derivation: PBKDF2-HMAC-SHA256, 10 000 iterations.

## Prerequisites

- **Shell scripts (enc.sh / dec.sh):** `openssl` on `PATH`
- **Rust scripts (renc.sh / rdec.sh) and crosscheck:** [Rust](https://rustup.rs) (e.g. `cargo build`)

## Usage

All of these use the same interface: **input file**, **output file**, and optional **password**. If you omit the password, you are prompted on the terminal.

### OpenSSL-based (enc.sh / dec.sh)

```bash
./enc.sh  <input> <output> [password]   # encrypt
./dec.sh  <input> <output> [password]   # decrypt
```

### Rust-based (renc.sh / rdec.sh)

Build once, then use the same arguments:

```bash
cargo build
./renc.sh <input> <output> [password]   # encrypt (Rust)
./rdec.sh <input> <output> [password]   # decrypt (Rust)
```

### Rust binary directly

```bash
cargo run -- enc <input> <output> [password]
cargo run -- dec <input> <output> [password]
```

You can encrypt with any tool and decrypt with any other; the format is compatible.

## Cross-check

`crosscheck.sh` runs all four combinations (OpenSSL enc/dec, Rust enc/dec) on several test files, including 1 MiB and 10 MiB payloads:

```bash
./crosscheck.sh              # password: "crosscheck"
./crosscheck.sh mypassword   # custom password
```

Requires both `openssl` and a built Rust binary (`cargo build`).

## Files

| File | Description |
|------|-------------|
| `enc.sh` | Encrypt via OpenSSL |
| `dec.sh` | Decrypt via OpenSSL |
| `renc.sh` | Encrypt via Rust binary (same args as enc.sh) |
| `rdec.sh` | Decrypt via Rust binary (same args as dec.sh) |
| `crosscheck.sh` | Cross-check all enc/dec combinations |
| `src/main.rs` | Pure Rust implementation (no OpenSSL dependency) |

## License

Same as the Rust crates used (MIT/Apache-2.0–style). Shell scripts and this repo: use as you like.
