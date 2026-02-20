//! Zero-dependency WASM build of OpenSSL-compatible AES-256-CBC encrypt/decrypt.
//! All crypto (AES, SHA-256, HMAC, PBKDF2, Base64) implemented from scratch.
//! Format: "Salted__" + salt(8) + ciphertext, base64-encoded with 64-char lines.

#[path = "../../src/aes256.rs"]
mod aes256;
#[path = "../../src/sha256.rs"]
mod sha256;

use aes256::Aes256;
use sha256::pbkdf2_hmac_sha256;
use wasm_bindgen::prelude::*;

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

// --- Salt source ---

trait SaltSource {
  fn salt(&mut self) -> [u8; SALT_LEN];
}

/// Seeded PRNG (splitmix64) — used from WASM, caller provides the seed.
struct SeededRng(u64);

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

fn encrypt_impl(password: &[u8], plaintext: &[u8], rng: &mut impl SaltSource) -> String {
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

fn decrypt_impl(password: &[u8], data: &str) -> Result<Vec<u8>, String> {
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

// --- WASM exports ---

#[wasm_bindgen]
pub fn encrypt(password: &str, plaintext: &[u8], seed_hi: u32, seed_lo: u32) -> String {
  let seed = ((seed_hi as u64) << 32) | (seed_lo as u64);
  encrypt_impl(password.as_bytes(), plaintext, &mut SeededRng(seed))
}

#[wasm_bindgen]
pub fn decrypt(password: &str, data: &str) -> Result<Vec<u8>, JsValue> {
  decrypt_impl(password.as_bytes(), data).map_err(|e| JsValue::from_str(&e))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn base64_roundtrip() {
    for input in [b"" as &[u8], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
      assert_eq!(b64_decode(&b64_encode(input)).unwrap(), input);
    }
    // RFC 4648 test vectors
    assert_eq!(b64_encode(b""), "");
    assert_eq!(b64_encode(b"f"), "Zg==");
    assert_eq!(b64_encode(b"fo"), "Zm8=");
    assert_eq!(b64_encode(b"foo"), "Zm9v");
    assert_eq!(b64_encode(b"foob"), "Zm9vYg==");
    assert_eq!(b64_encode(b"fooba"), "Zm9vYmE=");
    assert_eq!(b64_encode(b"foobar"), "Zm9vYmFy");
  }

  #[test]
  fn pkcs7_roundtrip() {
    for len in 0..=33 {
      let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
      let padded = pkcs7_pad(&data);
      assert!(padded.len() % BLOCK == 0);
      assert!(padded.len() >= data.len() + 1);
      assert_eq!(pkcs7_unpad(&padded).unwrap(), data);
    }
  }

  #[test]
  fn sha256_known_vectors() {
    use sha256::Sha256;
    // Empty string
    let h = Sha256::hash(b"");
    assert_eq!(
      hex(&h),
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    // "abc"
    let h = Sha256::hash(b"abc");
    assert_eq!(
      hex(&h),
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" (two blocks)
    let h = Sha256::hash(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    assert_eq!(
      hex(&h),
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
  }

  #[test]
  fn hmac_sha256_known() {
    use sha256::HmacSha256;
    // RFC 4231 Test Case 2
    let h = HmacSha256::mac(b"Jefe", b"what do ya want for nothing?");
    assert_eq!(
      hex(&h),
      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
  }

  #[test]
  fn aes256_known_vector() {
    // NIST FIPS 197 Appendix C.3 — AES-256
    let key: [u8; 32] = [
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    let plaintext: [u8; 16] = [
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ];
    let expected: [u8; 16] = [
      0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
    ];
    let cipher = Aes256::new(&key);
    let mut block = plaintext;
    cipher.encrypt_block(&mut block);
    assert_eq!(block, expected);
    cipher.decrypt_block(&mut block);
    assert_eq!(block, plaintext);
  }

  #[test]
  fn encrypt_decrypt_roundtrip() {
    let password = b"testpassword";
    for (i, plaintext) in [
      b"" as &[u8],
      b"hello world",
      b"0123456789abcdef", // exactly one block
      &[0xffu8; 1024],     // larger binary
    ]
    .iter()
    .enumerate()
    {
      let encoded = encrypt_impl(password, plaintext, &mut SeededRng(i as u64));
      let decrypted = decrypt_impl(password, &encoded).unwrap();
      assert_eq!(decrypted, *plaintext);
    }
  }

  #[test]
  fn different_seeds_produce_different_output() {
    let a = encrypt_impl(b"pw", b"hello", &mut SeededRng(1));
    let b = encrypt_impl(b"pw", b"hello", &mut SeededRng(2));
    assert_ne!(a, b);
  }

  #[test]
  fn os_rng_roundtrip() {
    let encoded = encrypt_impl(b"pw", b"hello world", &mut OsRng);
    let decrypted = decrypt_impl(b"pw", &encoded).unwrap();
    assert_eq!(decrypted, b"hello world");
  }

  #[test]
  fn cross_decrypt_from_main_binary() {
    // Encrypted by the main rustsslcmd binary (crate-based crypto):
    // plaintext: "hello world", password: "testpw"
    let ciphertext = "U2FsdGVkX1+o3xHAIt6xZVIYs9xEAUAcJgxhb6qHYjk=\n";
    let result = decrypt_impl(b"testpw", ciphertext).unwrap();
    assert_eq!(result, b"hello world");
  }

  fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
  }
}
