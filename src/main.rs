//! OpenSSL-compatible AES-256-CBC encrypt/decrypt.
//! Format: "Salted__" (8 bytes) + salt (8 bytes) + ciphertext; whole thing base64 when -a.
//! Key derivation: PBKDF2-HMAC-SHA256, 10000 iterations, 48 bytes (key 32 + iv 16).

use aes::Aes256;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use cipher::{Block, BlockDecryptMut, BlockEncryptMut, KeyInit};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha256;
use std::fs;
use std::io;
use std::path::Path;

const MAGIC: &[u8; 8] = b"Salted__";
const SALT_LEN: usize = 8;
const PBKDF2_ITER: u32 = 10_000;
const KEY_LEN: usize = 32;
const IV_LEN: usize = 16;
const BLOCK: usize = 16;

fn pkcs7_pad(data: &[u8]) -> Vec<u8> {
  let n = BLOCK - (data.len() % BLOCK);
  let pad_byte = n as u8;
  let mut out = data.to_vec();
  out.resize(data.len() + n, pad_byte);
  out
}

fn pkcs7_unpad(data: &[u8]) -> Result<Vec<u8>, String> {
  if data.is_empty() || data.len() % BLOCK != 0 {
    return Err("invalid length".into());
  }
  let pad_byte = *data.last().unwrap();
  if pad_byte == 0 || pad_byte as usize > BLOCK {
    return Err("invalid padding".into());
  }
  let len = data.len().saturating_sub(pad_byte as usize);
  for i in (len..data.len()).rev() {
    if data[i] != pad_byte {
      return Err("invalid padding".into());
    }
  }
  Ok(data[..len].to_vec())
}

fn cbc_encrypt(plain: &[u8], key: &[u8; KEY_LEN], iv: &[u8; IV_LEN]) -> Vec<u8> {
  let mut cipher = Aes256::new_from_slice(key).unwrap();
  let mut out = Vec::with_capacity(plain.len());
  let mut prev = *iv;
  for chunk in plain.chunks(BLOCK) {
    let mut block = Block::<Aes256>::default();
    block.copy_from_slice(chunk);
    for (a, &b) in block.iter_mut().zip(prev.iter()) {
      *a ^= b;
    }
    cipher.encrypt_block_mut(&mut block);
    out.extend_from_slice(&block);
    prev = block.into();
  }
  out
}

fn cbc_decrypt(ciphertext: &[u8], key: &[u8; KEY_LEN], iv: &[u8; IV_LEN]) -> Vec<u8> {
  let mut cipher = Aes256::new_from_slice(key).unwrap();
  let mut out = Vec::with_capacity(ciphertext.len());
  let mut prev = *iv;
  for chunk in ciphertext.chunks(BLOCK) {
    let mut block = Block::<Aes256>::default();
    block.copy_from_slice(chunk);
    let block_copy: [u8; BLOCK] = block.into();
    cipher.decrypt_block_mut(&mut block);
    for (a, &b) in block.iter_mut().zip(prev.iter()) {
      *a ^= b;
    }
    out.extend_from_slice(&block);
    prev = block_copy;
  }
  out
}

fn derive_key_iv(password: &[u8], salt: &[u8; SALT_LEN]) -> ([u8; KEY_LEN], [u8; IV_LEN]) {
  let mut buf = [0u8; KEY_LEN + IV_LEN];
  pbkdf2_hmac::<Sha256>(password, salt, PBKDF2_ITER, &mut buf);
  let mut key = [0u8; KEY_LEN];
  let mut iv = [0u8; IV_LEN];
  key.copy_from_slice(&buf[..KEY_LEN]);
  iv.copy_from_slice(&buf[KEY_LEN..]);
  (key, iv)
}

/// Encrypt to OpenSSL-compatible format (binary: Salted__ + salt + ciphertext).
fn encrypt_openssl(password: &[u8], plaintext: &[u8]) -> Vec<u8> {
  let mut salt = [0u8; SALT_LEN];
  rand::thread_rng().fill_bytes(&mut salt);
  let (key, iv) = derive_key_iv(password, &salt);
  let padded = pkcs7_pad(plaintext);
  let ciphertext = cbc_encrypt(&padded, &key, &iv);
  let mut out = Vec::with_capacity(MAGIC.len() + SALT_LEN + ciphertext.len());
  out.extend_from_slice(MAGIC);
  out.extend_from_slice(&salt);
  out.extend_from_slice(&ciphertext);
  out
}

/// Decrypt from OpenSSL-compatible format (binary).
fn decrypt_openssl(password: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
  if data.len() < MAGIC.len() + SALT_LEN || &data[..MAGIC.len()] != MAGIC {
    return Err("invalid format: missing or wrong Salted__ header".into());
  }
  let mut salt = [0u8; SALT_LEN];
  salt.copy_from_slice(&data[MAGIC.len()..MAGIC.len() + SALT_LEN]);
  let ciphertext = &data[MAGIC.len() + SALT_LEN..];
  let (key, iv) = derive_key_iv(password, &salt);
  let padded = cbc_decrypt(ciphertext, &key, &iv);
  pkcs7_unpad(&padded)
}

fn read_password_tty(prompt: &str) -> io::Result<Vec<u8>> {
  let pass = rpassword::prompt_password(prompt)?;
  Ok(pass.into_bytes())
}

fn encrypt_file(input_path: &Path, output_path: &Path, password: Option<&str>) -> Result<(), String> {
  let plaintext = fs::read(input_path).map_err(|e| e.to_string())?;
  let password_bytes = match password {
    Some(p) => p.as_bytes().to_vec(),
    None => read_password_tty("Enter encryption password: ").map_err(|e| e.to_string())?,
  };
  let raw = encrypt_openssl(&password_bytes, &plaintext);
  let encoded = BASE64.encode(&raw);
  // 64-char lines so OpenSSL's -a decoder accepts arbitrarily large output
  let wrapped: String =
    encoded.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join("\n");
  let mut content = wrapped;
  content.push('\n');
  fs::write(output_path, content).map_err(|e| e.to_string())?;
  Ok(())
}

fn decrypt_file(input_path: &Path, output_path: &Path, password: Option<&str>) -> Result<(), String> {
  let encoded = fs::read_to_string(input_path).map_err(|e| e.to_string())?;
  // Accept both one-line and OpenSSL's 64-char wrapped base64
  let encoded: String = encoded.trim_end().chars().filter(|c| !c.is_whitespace()).collect();
  let raw = BASE64.decode(&encoded).map_err(|e| e.to_string())?;
  let password_bytes = match password {
    Some(p) => p.as_bytes().to_vec(),
    None => read_password_tty("Enter decryption password: ").map_err(|e| e.to_string())?,
  };
  let plaintext = decrypt_openssl(&password_bytes, &raw)?;
  fs::write(output_path, &plaintext).map_err(|e| e.to_string())?;
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
