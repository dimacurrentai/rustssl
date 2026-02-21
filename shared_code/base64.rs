//! Base64 encoding and decoding (RFC 4648).

const B64_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn b64_encode(data: &[u8]) -> String {
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

pub fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
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
