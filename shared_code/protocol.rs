//! OpenSSL-compatible AES-256-CBC encrypt/decrypt protocol.
//! Format: "Salted__" (8 bytes) + salt (8 bytes) + ciphertext; base64-encoded.
//! Key derivation: PBKDF2-HMAC-SHA256, 10000 iterations, 48 bytes (key 32 + iv 16).

use crate::aes256::Aes256;
use crate::base64::{b64_decode, b64_encode};
use crate::sha256::pbkdf2_hmac_sha256;

pub const MAGIC: &[u8; 8] = b"Salted__";
pub const SALT_LEN: usize = 8;
pub const PBKDF2_ITER: u32 = 10_000;
pub const KEY_LEN: usize = 32;
pub const IV_LEN: usize = 16;
pub const BLOCK: usize = 16;

// --- PKCS7 ---

pub fn pkcs7_pad(data: &[u8]) -> Vec<u8> {
  let n = BLOCK - (data.len() % BLOCK);
  let mut out = data.to_vec();
  out.resize(data.len() + n, n as u8);
  out
}

pub fn pkcs7_unpad(data: &[u8]) -> Result<Vec<u8>, String> {
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

pub fn cbc_encrypt(plain: &[u8], key: &[u8; KEY_LEN], iv: &[u8; IV_LEN]) -> Vec<u8> {
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

pub fn cbc_decrypt(ciphertext: &[u8], key: &[u8; KEY_LEN], iv: &[u8; IV_LEN]) -> Vec<u8> {
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

pub fn derive_key_iv(password: &[u8], salt: &[u8; SALT_LEN]) -> ([u8; KEY_LEN], [u8; IV_LEN]) {
  let mut buf = [0u8; KEY_LEN + IV_LEN];
  pbkdf2_hmac_sha256(password, salt, PBKDF2_ITER, &mut buf);
  let mut key = [0u8; KEY_LEN];
  let mut iv = [0u8; IV_LEN];
  key.copy_from_slice(&buf[..KEY_LEN]);
  iv.copy_from_slice(&buf[KEY_LEN..]);
  (key, iv)
}

// --- Salt source ---

pub trait SaltSource {
  fn salt(&mut self) -> [u8; SALT_LEN];
}

/// Seeded PRNG (splitmix64) — used from WASM, caller provides the seed.
pub struct SeededRng(pub u64);

impl SaltSource for SeededRng {
  fn salt(&mut self) -> [u8; SALT_LEN] {
    self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
    let mut z = self.0;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    (z ^ (z >> 31)).to_le_bytes()
  }
}

/// OS random — used natively, delegates to std RandomState.
#[cfg(not(target_arch = "wasm32"))]
pub struct OsRng;

#[cfg(not(target_arch = "wasm32"))]
impl SaltSource for OsRng {
  fn salt(&mut self) -> [u8; SALT_LEN] {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    RandomState::new().build_hasher().finish().to_le_bytes()
  }
}

// --- OpenSSL-format encrypt/decrypt ---

pub fn encrypt_impl(password: &[u8], plaintext: &[u8], rng: &mut impl SaltSource) -> String {
  let salt = rng.salt();
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

pub fn decrypt_impl(password: &[u8], data: &str) -> Result<Vec<u8>, String> {
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
