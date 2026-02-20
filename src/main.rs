//! OpenSSL-compatible AES-256-CBC encrypt/decrypt — zero external dependencies.
//! Format: "Salted__" (8 bytes) + salt (8 bytes) + ciphertext; whole thing base64 when -a.
//! Key derivation: PBKDF2-HMAC-SHA256, 10000 iterations, 48 bytes (key 32 + iv 16).

mod aes256;
mod readpass;
mod sha256;

use aes256::Aes256;
use sha256::pbkdf2_hmac_sha256;
use std::collections::hash_map::RandomState;
use std::fs;
use std::hash::{BuildHasher, Hasher};
use std::path::Path;

const MAGIC: &[u8; 8] = b"Salted__";
const SALT_LEN: usize = 8;
const PBKDF2_ITER: u32 = 10_000;
const KEY_LEN: usize = 32;
const IV_LEN: usize = 16;
const BLOCK: usize = 16;

// --- Base64 ---

const B64_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(data: &[u8]) -> String {
  let mut out = Vec::with_capacity((data.len() + 2) / 3 * 4);
  for chunk in data.chunks(3) {
    let (b0, b1, b2) = (
      chunk[0] as u32,
      if chunk.len() > 1 { chunk[1] as u32 } else { 0 },
      if chunk.len() > 2 { chunk[2] as u32 } else { 0 },
    );
    let n = (b0 << 16) | (b1 << 8) | b2;
    out.push(B64_CHARS[((n >> 18) & 63) as usize]);
    out.push(B64_CHARS[((n >> 12) & 63) as usize]);
    if chunk.len() > 1 {
      out.push(B64_CHARS[((n >> 6) & 63) as usize]);
    } else {
      out.push(b'=');
    }
    if chunk.len() > 2 {
      out.push(B64_CHARS[(n & 63) as usize]);
    } else {
      out.push(b'=');
    }
  }
  String::from_utf8(out).unwrap()
}

fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
  let s: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
  if s.len() % 4 != 0 {
    return Err("invalid base64 length".into());
  }
  let mut out = Vec::with_capacity(s.len() / 4 * 3);
  for chunk in s.chunks(4) {
    let mut vals = [0u32; 4];
    for (i, &ch) in chunk.iter().enumerate() {
      vals[i] = match ch {
        b'A'..=b'Z' => (ch - b'A') as u32,
        b'a'..=b'z' => (ch - b'a' + 26) as u32,
        b'0'..=b'9' => (ch - b'0' + 52) as u32,
        b'+' => 62,
        b'/' => 63,
        b'=' => 0,
        _ => return Err(format!("invalid base64 char: {}", ch as char)),
      };
    }
    let n = (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6) | vals[3];
    out.push((n >> 16) as u8);
    if chunk[2] != b'=' {
      out.push((n >> 8) as u8);
    }
    if chunk[3] != b'=' {
      out.push(n as u8);
    }
  }
  Ok(out)
}

// --- PKCS7 ---

fn pkcs7_pad(data: &[u8]) -> Vec<u8> {
  let n = BLOCK - (data.len() % BLOCK);
  let mut out = data.to_vec();
  out.resize(data.len() + n, n as u8);
  out
}

fn pkcs7_unpad(data: &[u8]) -> Result<Vec<u8>, String> {
  if data.is_empty() || data.len() % BLOCK != 0 {
    return Err("invalid length".into());
  }
  let pad = *data.last().unwrap();
  if pad == 0 || pad as usize > BLOCK {
    return Err("invalid padding".into());
  }
  let len = data.len() - pad as usize;
  for &b in &data[len..] {
    if b != pad {
      return Err("invalid padding".into());
    }
  }
  Ok(data[..len].to_vec())
}

// --- CBC ---

fn cbc_encrypt(plain: &[u8], key: &[u8; KEY_LEN], iv: &[u8; IV_LEN]) -> Vec<u8> {
  let cipher = Aes256::new(key);
  let mut out = Vec::with_capacity(plain.len());
  let mut prev = *iv;
  for chunk in plain.chunks(BLOCK) {
    let mut block = [0u8; BLOCK];
    block.copy_from_slice(chunk);
    for i in 0..BLOCK {
      block[i] ^= prev[i];
    }
    cipher.encrypt_block(&mut block);
    out.extend_from_slice(&block);
    prev = block;
  }
  out
}

fn cbc_decrypt(ciphertext: &[u8], key: &[u8; KEY_LEN], iv: &[u8; IV_LEN]) -> Vec<u8> {
  let cipher = Aes256::new(key);
  let mut out = Vec::with_capacity(ciphertext.len());
  let mut prev = *iv;
  for chunk in ciphertext.chunks(BLOCK) {
    let mut block = [0u8; BLOCK];
    block.copy_from_slice(chunk);
    let saved = block;
    cipher.decrypt_block(&mut block);
    for i in 0..BLOCK {
      block[i] ^= prev[i];
    }
    out.extend_from_slice(&block);
    prev = saved;
  }
  out
}

// --- Key derivation ---

fn derive_key_iv(password: &[u8], salt: &[u8; SALT_LEN]) -> ([u8; KEY_LEN], [u8; IV_LEN]) {
  let mut buf = [0u8; KEY_LEN + IV_LEN];
  pbkdf2_hmac_sha256(password, salt, PBKDF2_ITER, &mut buf);
  let mut key = [0u8; KEY_LEN];
  let mut iv = [0u8; IV_LEN];
  key.copy_from_slice(&buf[..KEY_LEN]);
  iv.copy_from_slice(&buf[KEY_LEN..]);
  (key, iv)
}

// --- Salt generation ---

fn random_salt() -> [u8; SALT_LEN] {
  RandomState::new().build_hasher().finish().to_le_bytes()
}

// --- OpenSSL-format encrypt/decrypt ---

fn encrypt_openssl(password: &[u8], plaintext: &[u8]) -> String {
  let salt = random_salt();
  let (key, iv) = derive_key_iv(password, &salt);
  let padded = pkcs7_pad(plaintext);
  let ct = cbc_encrypt(&padded, &key, &iv);
  let mut raw = Vec::with_capacity(MAGIC.len() + SALT_LEN + ct.len());
  raw.extend_from_slice(MAGIC);
  raw.extend_from_slice(&salt);
  raw.extend_from_slice(&ct);
  let encoded = b64_encode(&raw);
  // 64-char line wrapping for OpenSSL compatibility
  let mut wrapped = String::with_capacity(encoded.len() + encoded.len() / 64 + 1);
  for (i, ch) in encoded.chars().enumerate() {
    if i > 0 && i % 64 == 0 {
      wrapped.push('\n');
    }
    wrapped.push(ch);
  }
  wrapped.push('\n');
  wrapped
}

fn decrypt_openssl(password: &[u8], data: &str) -> Result<Vec<u8>, String> {
  let raw = b64_decode(data)?;
  if raw.len() < MAGIC.len() + SALT_LEN || &raw[..MAGIC.len()] != MAGIC {
    return Err("invalid format: missing or wrong Salted__ header".into());
  }
  let mut salt = [0u8; SALT_LEN];
  salt.copy_from_slice(&raw[MAGIC.len()..MAGIC.len() + SALT_LEN]);
  let ct = &raw[MAGIC.len() + SALT_LEN..];
  let (key, iv) = derive_key_iv(password, &salt);
  let padded = cbc_decrypt(ct, &key, &iv);
  pkcs7_unpad(&padded)
}

// --- File I/O ---

fn encrypt_file(input: &Path, output: &Path, password: Option<&str>) -> Result<(), String> {
  let plaintext = fs::read(input).map_err(|e| e.to_string())?;
  let password_bytes = match password {
    Some(p) => p.as_bytes().to_vec(),
    None => readpass::read_password("Enter encryption password: ").map_err(|e| e.to_string())?,
  };
  let content = encrypt_openssl(&password_bytes, &plaintext);
  fs::write(output, content).map_err(|e| e.to_string())?;
  Ok(())
}

fn decrypt_file(input: &Path, output: &Path, password: Option<&str>) -> Result<(), String> {
  let encoded = fs::read_to_string(input).map_err(|e| e.to_string())?;
  let password_bytes = match password {
    Some(p) => p.as_bytes().to_vec(),
    None => readpass::read_password("Enter decryption password: ").map_err(|e| e.to_string())?,
  };
  let plaintext = decrypt_openssl(&password_bytes, &encoded)?;
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
