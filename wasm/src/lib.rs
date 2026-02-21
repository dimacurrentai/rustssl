//! Zero-dependency WASM build of OpenSSL-compatible AES-256-CBC encrypt/decrypt.
//! All crypto (AES, SHA-256, HMAC, PBKDF2, Base64) implemented from scratch.
//! Format: "Salted__" + salt(8) + ciphertext, base64-encoded with 64-char lines.

#[path = "../../shared_code/aes256.rs"]
mod aes256;
#[path = "../../shared_code/sha256.rs"]
mod sha256;
#[path = "../../shared_code/base64.rs"]
mod base64;
#[path = "../../shared_code/protocol.rs"]
mod protocol;

use protocol::{decrypt_impl, encrypt_impl, SeededRng};
use wasm_bindgen::prelude::*;

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
  use aes256::Aes256;
  use base64::{b64_decode, b64_encode};
  use protocol::{pkcs7_pad, pkcs7_unpad, BLOCK};

  #[cfg(not(target_arch = "wasm32"))]
  use protocol::OsRng;

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
  #[cfg(not(target_arch = "wasm32"))]
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
