//! OpenSSL-compatible AES-256-CBC encrypt/decrypt — zero external dependencies.
//! Format: "Salted__" (8 bytes) + salt (8 bytes) + ciphertext; whole thing base64 when -a.
//! Key derivation: PBKDF2-HMAC-SHA256, 10000 iterations, 48 bytes (key 32 + iv 16).

#[path = "../shared_code/aes256.rs"]
mod aes256;
#[path = "../shared_code/sha256.rs"]
mod sha256;
#[path = "../shared_code/base64.rs"]
mod base64;
#[path = "../shared_code/protocol.rs"]
mod protocol;
mod readpass;

use protocol::{decrypt_impl, encrypt_impl, OsRng};
use std::fs;
use std::path::Path;

// --- File I/O ---

fn encrypt_file(input: &Path, output: &Path, password: Option<&str>) -> Result<(), String> {
  let plaintext = fs::read(input).map_err(|e| e.to_string())?;
  let password_bytes = match password {
    Some(p) => p.as_bytes().to_vec(),
    None => readpass::read_password("Enter encryption password: ").map_err(|e| e.to_string())?,
  };
  let content = encrypt_impl(&password_bytes, &plaintext, &mut OsRng);
  fs::write(output, content).map_err(|e| e.to_string())?;
  Ok(())
}

fn decrypt_file(input: &Path, output: &Path, password: Option<&str>) -> Result<(), String> {
  let encoded = fs::read_to_string(input).map_err(|e| e.to_string())?;
  let password_bytes = match password {
    Some(p) => p.as_bytes().to_vec(),
    None => readpass::read_password("Enter decryption password: ").map_err(|e| e.to_string())?,
  };
  let plaintext = decrypt_impl(&password_bytes, &encoded)?;
  fs::write(output, &plaintext).map_err(|e| e.to_string())?;
  Ok(())
}

fn main() {
  let args: Vec<String> = std::env::args().collect();
  let usage = || {
    eprintln!("Usage:");
    eprintln!("  {} enc <input_file> <output_file> [password]", args[0]);
    eprintln!("  {} dec <input_file> <output_file> [password]", args[0]);
    eprintln!("  If password is omitted, it is read from the terminal.");
  };

  if args.len() < 4 {
    usage();
    std::process::exit(1);
  }

  let mode = &args[1];
  let input = Path::new(&args[2]);
  let output = Path::new(&args[3]);
  let password = args.get(4).map(String::as_str);

  if !input.exists() {
    eprintln!("Error: input file does not exist: {}", input.display());
    std::process::exit(1);
  }

  let result = match mode.as_str() {
    "enc" => encrypt_file(input, output, password),
    "dec" => decrypt_file(input, output, password),
    _ => {
      usage();
      std::process::exit(1);
    }
  };

  if let Err(e) = result {
    eprintln!("Error: {}", e);
    std::process::exit(1);
  }

  match mode.as_str() {
    "enc" => println!("Encrypted: {} -> {}", input.display(), output.display()),
    "dec" => println!("Decrypted: {} -> {}", input.display(), output.display()),
    _ => {}
  }
}
